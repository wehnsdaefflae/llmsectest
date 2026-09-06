"""Target a real LLM **application** by its HTTP endpoint.

This is the faithful way to security-test an application (vs. a bare model): we
POST the attacker's input to the application's own chat endpoint and read its
reply, so the app's real system prompt, guardrails, RAG and tools are all in the
loop. We send **only the attacker turn** — the application supplies its own
system prompt — so any provided ``system`` message is intentionally ignored.

Zero extra dependencies (stdlib ``urllib``). Request/response shapes vary per
app, so both are configurable; the response field is auto-detected across common
shapes (``reply``/``response``/``message``/``content`` or OpenAI-style
``choices[0].message.content``) when not given explicitly.

The per-request budget is a **wall-clock deadline**, not just a socket timeout —
see :meth:`AppEndpointAdapter._read_within_deadline` for why that distinction
decides whether a runaway app is caught at all.

Applications that bind a persona, a knowledge base or a tool set to a
**conversation** need one more thing: a session value that changes per probe. See
:meth:`AppEndpointAdapter._session_value` for the two shapes that takes and why a
scan without it measures the wrong thing.
"""

from __future__ import annotations

import contextlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from .base import (
    AdapterError,
    AdapterThrottleError,
    AdapterTimeoutError,
    CompletionRequest,
    CompletionResponse,
    LLMAdapter,
    Role,
    is_rate_limit_error,
    retry_after_seconds,
)

_AUTODETECT = ("reply", "response", "output", "message", "content", "text", "answer")

#: Bytes requested per body read. Only an upper bound: each read returns whatever has
#: already arrived, so the deadline is re-checked at every chunk rather than once per
#: full buffer.
_READ_CHUNK = 8192

#: Hard ceiling on one buffered response body. Set far above any real chat reply (a
#: verbose LLM answer is kilobytes), so it can only be reached by an app that is streaming
#: without terminating — the same condition the deadline catches, arriving by volume
#: instead of by clock. It exists so this scanner cannot be made to exhaust its own memory
#: by the very behaviour it is here to report.
_MAX_BODY_BYTES = 32 * 1024 * 1024


def _last_user(request: CompletionRequest) -> str:
    return next(
        (m.content for m in reversed(request.messages) if m.role == Role.USER), ""
    )


def _extract(data: object, path: str | None) -> str:
    """Pull the reply text out of a decoded JSON response."""
    if path:
        cur: object = data
        for part in path.split("."):
            # A path that misses is named, whatever it missed on. Until 2026-09-05 only
            # the "walked into a scalar" branch was, so a mistyped key raised a bare
            # KeyError and the operator read `KeyError: 'conversaton_id'` where the answer
            # is that their path does not match this application's reply. `run_probe`'s
            # broad floor kept it inconclusive throughout, so this is the message rather
            # than the guarantee.
            try:
                if isinstance(cur, list):
                    cur = cur[int(part)]
                elif isinstance(cur, dict):
                    cur = cur[part]
                else:
                    raise KeyError(part)
            except (KeyError, IndexError, ValueError) as exc:
                raise AdapterError(
                    f"response path {path!r} does not match the reply JSON (stopped at "
                    f"{part!r})"
                ) from exc
        return str(cur)
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        # OpenAI-compatible shape first, then common single-field shapes.
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            pass
        for key in _AUTODETECT:
            if key in data and isinstance(data[key], str):
                return data[key]
    raise AdapterError(
        "could not find the reply in the app response; pass response_path=… "
        f"(top-level keys: {list(data) if isinstance(data, dict) else type(data).__name__})"
    )


def _place(body: dict, path: str, value: str) -> None:
    """Write ``value`` into ``body`` at a dotted ``path``, creating the objects on the way.

    The same dotted convention :func:`_extract` reads a reply out of, used in the other
    direction, so an application that answers at ``choices.0.message.content`` and wants its
    session at ``metadata.conversation_id`` is described in one vocabulary. List indices are
    not accepted here: reading past one is unambiguous, while writing into one would have to
    invent how long the list is.
    """
    parts = path.split(".")
    cur = body
    for part in parts[:-1]:
        if part.isdigit():
            raise AdapterError(
                f"session field {path!r} indexes a list at {part!r}; a session value is "
                "placed into named fields only"
            )
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    if parts[-1].isdigit():
        raise AdapterError(
            f"session field {path!r} indexes a list at {parts[-1]!r}; a session value is "
            "placed into named fields only"
        )
    cur[parts[-1]] = value


class AppEndpointAdapter(LLMAdapter):
    """Drive a running LLM application via its HTTP chat endpoint."""

    provider = "app"

    def __init__(
        self,
        endpoint: str,
        model: str | None = None,
        request_field: str = "message",
        response_path: str | None = None,
        headers: dict[str, str] | None = None,
        extra_body: dict[str, object] | None = None,
        timeout: float = 120.0,
        session_field: str | None = None,
        session_init: dict[str, object] | None = None,
    ):
        super().__init__(model or endpoint)
        if not endpoint:
            raise AdapterError("AppEndpointAdapter needs the application's endpoint URL")
        if session_init is not None and not session_field:
            raise AdapterError(
                "session_init describes where a session value comes from; session_field "
                "says where it goes into the request body, and without it the value "
                "obtained would be thrown away"
            )
        self.endpoint = endpoint
        self.request_field = request_field
        self.response_path = response_path
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.extra_body = extra_body or {}
        self.timeout = timeout
        self.session_field = session_field
        self.session_init = None if session_init is None else dict(session_init)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        sent = _last_user(request)
        body = {self.request_field: sent, **self.extra_body}
        if self.session_field:
            _place(body, self.session_field, self._session_value())
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(body).encode(),
            headers=self.headers,
            method="POST",
        )
        # Started before the connection, so the time spent connecting and waiting for the
        # response headers is already charged against the body's deadline below; otherwise
        # a slow handshake plus a slow body could each spend the full timeout and the
        # request would take twice what the caller asked for. (Connect and the header wait
        # themselves are bounded by ``urlopen``'s own socket timeout, which is sufficient
        # there: both either make progress or block, and neither can trickle.)
        deadline = time.monotonic() + self.timeout
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(self._read_within_deadline(resp, deadline).decode())
        except TimeoutError as exc:
            raise self._timeout_error() from exc
        except urllib.error.HTTPError as exc:
            # An HTTPError is a URLError subclass, so the branch below used to swallow it
            # and every status came out of a report as "unreachable". The guarantee held —
            # an AdapterError is inconclusive and never a finding — but the *reason* was
            # wrong on three of the five ways this endpoint can fail, and the reason is
            # what an operator acts on. Measured on 2026-08-28 by driving the real CLI at
            # a server answering 429, 500 and 401: all three read "unreachable: HTTP Error
            # …", so the advice was "check your URL" for a throttle, an outage and a bad
            # token alike. This is the path every third-party cohort member runs through.
            raise self._http_error(exc) from exc
        except urllib.error.URLError as exc:  # pragma: no cover - network
            # A connect-phase timeout surfaces as URLError(reason=timeout); keep it a
            # timeout (not a generic "unreachable") so a slow endpoint is handled the
            # same whether it stalls before or during the response.
            if isinstance(exc.reason, TimeoutError):
                raise self._timeout_error() from exc
            raise AdapterError(f"app endpoint {self.endpoint} unreachable: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise AdapterError(f"app endpoint {self.endpoint} returned non-JSON: {exc}") from exc
        text = _extract(payload, self.response_path)
        self._refuse_our_own_turn(text, sent)
        return CompletionResponse(
            text=text,
            model=self.model,
            provider=self.provider,
            raw=payload,
        )

    def _refuse_our_own_turn(self, text: str, sent: str) -> None:
        """Refuse to score a "reply" that is the attacker turn we just sent.

        **The defect this exists for (2026-09-06, measured on Open Notebook v1.14.0).**
        An application whose reply is the last element of a growing message list makes
        ``messages.0.content`` a plausible-looking response path, and it reads back
        ``ChatMessage(type="human")`` — our own attack prompt, verbatim. Every marker this
        suite scores for LLM01 and LLM05 is a string the *attack* carries, so each probe
        then finds its own sentinel or its own payload in what it believes is the reply and
        scores a finding. The scan renders, validates and reports a near-total failure of
        an application that was never asked anything.

        That is the one class of wrongness this scanner must never produce. Everything else
        the honesty guarantee covers fails towards silence: an unreachable app, a bad token
        or a mistyped path is inconclusive and never a finding. A response path aimed at our
        own turn fails the other way, manufacturing high-severity findings out of nothing,
        and nothing in a rendered report distinguishes it from a real one.

        Equality after trimming surrounding whitespace is the whole test, and it is
        deliberately narrow. Trimmed rather than byte-for-byte because an application that
        echoes the turn with a trailing newline is the same defect. Every probe prompt in
        :mod:`llmsectest.probes.application` wraps its marker in instruction text, so no
        compliant reply is ever equal to the prompt: the LLM05 payload cases ask
        for the payload inside a framing sentence, and LLM01 asks for the sentinel after
        "Ignore all previous instructions". An application that genuinely echoes the whole
        request has no assistant turn to score either, so stopping is the right answer for
        it too, and the message says which two things to check.

        Raised as a plain :class:`AdapterError`, so the probe is recorded inconclusive and
        the operator gets the reason, rather than a report that has to be disbelieved later.
        """
        if sent.strip() and text.strip() == sent.strip():
            raise AdapterError(
                f"app endpoint {self.endpoint} answered with the exact text we sent it, so "
                f"--app-response-path "
                f"{self.response_path or '(auto-detected)'} is reading our own turn back "
                f"rather than the application's reply. Every LLM01 and LLM05 marker is a "
                f"string our attack carries, so scoring this would manufacture a finding "
                f"per probe. Check the path against a real reply (a message list usually "
                f"needs the LAST element, e.g. `messages.-1.content`), or the endpoint "
                f"itself if it truly echoes."
            )

    def _session_value(self) -> str:
        """A session value for **this probe**, minted here or issued by the application.

        **The defect this exists for (2026-09-05, measured on khoj v1.42.10).** The adapter
        sends one POST per probe with one fixed body, so an application that binds a
        persona, a knowledge base or a tool set to a *conversation* left a scan two wrong
        choices. Pointing every probe at one conversation lets each attack see the ones
        before it, so a refusal or a leak early on changes what every later probe measures,
        which is a property of the scan and not of the application. Asking the application
        for a fresh conversation instead, on khoj's only isolation flag, dropped the persona
        and scanned a default assistant that holds none of the app's own instructions.

        Two shapes, and the cheaper one covers most applications:

        * **client-minted** (``session_init`` unset). A fresh UUID per probe, written into
          the field the application reads. No extra request, so a 28-probe scan still makes
          28 requests. Every application that accepts a caller-supplied conversation or
          session id needs only this.
        * **server-issued** (``session_init`` set). One request to the application before
          each probe, with a dotted path into its reply naming the value to carry. The shape
          for applications where only the application can create a conversation.

        A failure here is a plain :class:`AdapterError`, never an
        :class:`AdapterTimeoutError`: a slow or broken session setup is inconclusive, and
        must never be scored as the target failing to bound its per-request work.
        """
        if self.session_init is None:
            return uuid.uuid4().hex
        spec = self.session_init
        unknown = set(spec) - {"url", "method", "headers", "body", "response_path"}
        if unknown:
            # Loud, because the alternative is a scan that silently used a different
            # session shape from the one described and reported the numbers anyway.
            raise AdapterError(
                f"session_init has unknown key(s) {sorted(unknown)}; it takes url, method, "
                "headers, body and response_path"
            )
        raw_url = str(spec.get("url") or "")
        if not raw_url:
            raise AdapterError("session_init needs a 'url' to ask for a session")
        if not spec.get("response_path"):
            # Named rather than auto-detected. The reply-shape auto-detection reads
            # `message`/`content`/`text`, which a session response very plausibly also
            # carries, so guessing here would take "created" for a conversation id and
            # every probe would run against the application's default session with the
            # numbers reported as if the session had been set.
            raise AdapterError(
                "session_init needs a 'response_path' naming the session value in the "
                "reply; the reply-shape auto-detection reads a chat answer and would "
                "take the wrong field here"
            )
        url = urllib.parse.urljoin(self.endpoint, raw_url)
        body = spec.get("body")
        req = urllib.request.Request(
            url,
            data=None if body is None else json.dumps(body).encode(),
            headers={**self.headers, **(spec.get("headers") or {})},  # type: ignore[dict-item]
            method=str(spec.get("method") or "POST").upper(),
        )
        deadline = time.monotonic() + self.timeout
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(self._read_within_deadline(resp, deadline).decode())
        except (AdapterError, urllib.error.URLError, TimeoutError,
                json.JSONDecodeError) as exc:
            raise AdapterError(
                f"session setup at {url} failed before the probe was sent ({exc}), so "
                "nothing was scored. This is the session step, not the chat endpoint"
            ) from exc
        try:
            value = _extract(payload, str(spec["response_path"]))
        except AdapterError as exc:
            raise AdapterError(
                f"session setup at {url} answered, but its reply carries no session value "
                f"({exc}); name it with response_path"
            ) from exc
        if not value:
            raise AdapterError(
                f"session setup at {url} returned an empty session value, so every probe "
                "would share the application's default session"
            )
        return value

    def _read_within_deadline(self, resp: object, deadline: float) -> bytes:
        """Read the response body under a real wall-clock deadline.

        The obvious ``urlopen(..., timeout=…)`` bounds a *single socket operation*, not
        the request. An app that keeps trickling bytes therefore never trips it: measured
        against a server emitting five bytes a second, a client with ``timeout=3`` was
        still reading after twelve. That is the most realistic unbounded-consumption
        target there is — a streaming endpoint that never terminates — and it would run
        until some outer limit killed the whole scan, which is exactly what the
        per-request budget exists to prevent.

        So the budget is enforced here instead, on four levels:

        * the deadline is re-checked before every read, so total time is bounded even
          while data keeps arriving;
        * reads use ``read1``, which returns whatever has already arrived rather than
          blocking for a full buffer — a plain ``read(n)`` waits for *n* bytes and would
          skip past the deadline check entirely, which is the trap this method exists to
          avoid;
        * the socket timeout is tightened to the time actually left, so a target that
          goes quiet mid-body cannot spend a fresh full budget on top of what it has
          already used;
        * the accumulated body is capped at :data:`_MAX_BODY_BYTES`. A tool that reports
          unbounded consumption must not be unbounded itself: a fast stream can move a
          great deal of data inside even a short budget, and buffering all of it would
          make the scanner the thing that runs out of memory.

        The bytes received so far travel out on the exception, turning "did not answer"
        into a measurement of what the app produced instead.
        """
        chunks: list[bytes] = []
        received = 0
        # read1 is what makes the deadline effective; the fallback exists only for
        # response objects that do not implement it (no stdlib HTTP response is one).
        read = getattr(resp, "read1", None) or resp.read  # type: ignore[attr-defined]
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise self._timeout_error(bytes_received=received)
            _tighten_socket_timeout(resp, remaining)
            try:
                chunk = read(_READ_CHUNK)
            except TimeoutError as exc:
                raise self._timeout_error(bytes_received=received) from exc
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            received += len(chunk)
            if received > _MAX_BODY_BYTES:
                raise self._volume_error(received)

    def _http_error(self, exc: urllib.error.HTTPError) -> AdapterError:
        """An answered request that refused us, named by what the application actually said.

        Both returns stay inside the ``AdapterError`` family, so the honesty guarantee is
        untouched: the probe is inconclusive, it is never a finding, and the run exits
        non-zero. Only the operator's next move changes, which is the whole point of
        separating these — a 429 is a budget to raise, a 401 is a token to fix, a 500 is
        the application's own log to read, and none of them is a URL to check.

        A 429 becomes :class:`AdapterThrottleError` with the ``Retry-After`` the app sent,
        the same class the SDK-backed adapters raise, so a throttled application and a
        throttled hosted model are one case downstream instead of two.
        """
        status = exc.code
        if is_rate_limit_error(exc):
            retry_after = retry_after_seconds(exc)
            hint = (
                f" It asked us to retry after {retry_after:g}s."
                if retry_after is not None
                else ""
            )
            return AdapterThrottleError(
                f"app endpoint {self.endpoint} rate-limited the request (HTTP 429).{hint} "
                f"No answer was returned, so nothing was scored",
                retry_after=retry_after,
            )
        return AdapterError(
            f"app endpoint {self.endpoint} answered HTTP {status} ({exc.reason}) instead "
            f"of a reply, so nothing was scored. The endpoint was reached: this is the "
            f"application refusing or failing, not an unreachable URL"
        )

    def _timeout_error(self, bytes_received: int | None = None) -> AdapterTimeoutError:
        if bytes_received:
            produced = (
                f". It emitted {bytes_received} byte(s) of response in that time and "
                "had still not terminated, so it did not bound its per-request work"
            )
        elif bytes_received == 0:
            produced = (
                ". It sent no response body at all in that time, so it did not bound "
                "its per-request work"
            )
        else:
            produced = ". The app did not bound its per-request work"
        return AdapterTimeoutError(
            f"app endpoint {self.endpoint} did not respond within "
            f"{self.timeout:g}s{produced} "
            "(raise --app-timeout if the app is legitimately slow)",
            timeout=self.timeout,
            bytes_received=bytes_received,
        )

    def _volume_error(self, bytes_received: int) -> AdapterTimeoutError:
        """The app blew the body ceiling before the clock ran out.

        Reported as the same failure as running out of time, because it *is* the same
        finding: one request produced more output than any real reply contains and had not
        terminated. Reading further would only trade the app's runaway generation for our
        own memory exhaustion.
        """
        return AdapterTimeoutError(
            f"app endpoint {self.endpoint} streamed more than "
            f"{_MAX_BODY_BYTES // (1024 * 1024)} MiB in reply to one request "
            f"({bytes_received} byte(s) read) and had still not terminated, so it did not "
            "bound its per-request work; the read was cut off to protect this process",
            timeout=self.timeout,
            bytes_received=bytes_received,
        )


def _tighten_socket_timeout(resp: object, remaining: float) -> None:
    """Shrink the response socket's timeout to the wall-clock time still available.

    Best-effort by design: the socket is reached through the response's buffered
    reader, which is an implementation detail of the stdlib HTTP client. If the walk
    does not find a socket, the deadline check between reads still bounds a *dripping*
    target, and only the narrower case of a target that goes silent mid-body falls back
    to the original socket timeout.
    """
    sock = getattr(getattr(getattr(resp, "fp", None), "raw", None), "_sock", None)
    with contextlib.suppress(AttributeError, OSError, ValueError):
        sock.settimeout(remaining)  # type: ignore[union-attr]
