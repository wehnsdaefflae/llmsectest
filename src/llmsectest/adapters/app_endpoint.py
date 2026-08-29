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
"""

from __future__ import annotations

import contextlib
import json
import time
import urllib.error
import urllib.request

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
            if isinstance(cur, list):
                cur = cur[int(part)]
            elif isinstance(cur, dict):
                cur = cur[part]
            else:
                raise AdapterError(f"response path {path!r} does not match the reply JSON")
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
    ):
        super().__init__(model or endpoint)
        if not endpoint:
            raise AdapterError("AppEndpointAdapter needs the application's endpoint URL")
        self.endpoint = endpoint
        self.request_field = request_field
        self.response_path = response_path
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.extra_body = extra_body or {}
        self.timeout = timeout

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        body = {self.request_field: _last_user(request), **self.extra_body}
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
        return CompletionResponse(
            text=_extract(payload, self.response_path),
            model=self.model,
            provider=self.provider,
            raw=payload,
        )

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
