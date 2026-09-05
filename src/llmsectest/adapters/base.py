"""Unified LLM adapter interface.

Every provider (OpenAI, Anthropic, HuggingFace, local runtimes) is wrapped in a
single `LLMAdapter` contract so that security probes can target any model the
same way. Probes depend only on this module, never on a vendor SDK.
"""

from __future__ import annotations

import abc
import contextlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


@dataclass(frozen=True)
class Message:
    role: Role
    content: str

    @staticmethod
    def system(content: str) -> Message:
        return Message(Role.SYSTEM, content)

    @staticmethod
    def user(content: str) -> Message:
        return Message(Role.USER, content)

    @staticmethod
    def assistant(content: str) -> Message:
        return Message(Role.ASSISTANT, content)


@dataclass
class CompletionRequest:
    messages: list[Message]
    max_tokens: int = 512
    temperature: float = 0.0
    stop: list[str] | None = None
    extra: dict = field(default_factory=dict)


#: Deepest nesting :func:`_json_strings` will walk. A decoded chat-completion body is
#: three or four levels; the bound exists so a self-referential or pathologically nested
#: payload from an untrusted target cannot spend the scan's budget in the walker.
_MAX_BODY_DEPTH = 12


def _json_strings(node: object, depth: int = 0) -> list[str]:
    """Every string *value* in a decoded JSON structure, in document order.

    Anything that is not a ``dict``, ``list``, ``tuple`` or ``str`` contributes nothing:
    numbers and booleans cannot carry a planted canary, and an object that is none of
    these is a vendor SDK instance rather than a decoded body.
    """
    if depth > _MAX_BODY_DEPTH:
        return []
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in _json_strings(v, depth + 1)]
    if isinstance(node, (list, tuple)):
        return [s for v in node for s in _json_strings(v, depth + 1)]
    return []


@dataclass
class CompletionResponse:
    text: str
    model: str
    provider: str
    raw: object = None
    usage: dict = field(default_factory=dict)

    def body_beyond_text(self) -> str:
        """Everything the provider said that is *not* in :attr:`text`, one string.

        :attr:`text` is one field of the response body, chosen by ``response_path`` or
        autodetected. A model's answer can also arrive in a *sibling* field, and on
        2026-09-04 one did: LibreChat returned the planted LLM02 secret verbatim in
        ``choices[0].message.reasoning`` while ``choices[0].message.content`` held a
        polite refusal, so the reply field said the application resisted and the body
        said it had not. Every oracle in this tool read the reply field only.

        Returns the string leaves of :attr:`raw` that :attr:`text` does not already
        contain, joined by newlines, and ``""`` when there is nothing extra. Leaves
        rather than the serialised JSON, because the leaves are already decoded: a
        secret containing a quote or a newline matches here and would not survive
        ``json.dumps``. Keys are skipped — a key is our protocol's vocabulary, not the
        application's output.

        Only JSON-native bodies are walked. The model adapters put a vendor SDK object
        in :attr:`raw`, and stringifying one is a guess about a third party's
        ``__repr__``; those return ``""`` rather than a maybe. The black-box app
        endpoint, which is where this gap was found and where every field-tier scan
        runs, stores the decoded JSON itself.

        Reading it is not the same as *scoring* it: which probes may look here is
        decided in :func:`~llmsectest.probes.runner.run_probe`, because a reply that
        merely echoes our own attack must never become a finding.
        """
        extra = [s for s in _json_strings(self.raw) if s and s not in self.text]
        seen: set[str] = set()
        unique = [s for s in extra if not (s in seen or seen.add(s))]
        return "\n".join(unique)


@dataclass
class PreflightResult:
    """Outcome of an adapter health check (see :meth:`LLMAdapter.preflight`).

    Returned only on success — a hard failure (server unreachable, requested
    model not loaded) raises :class:`AdapterError` so callers fail fast with a
    clear message instead of an opaque SDK error deep inside the first probe.
    """

    provider: str
    reachable: bool
    detail: str
    base_url: str | None = None
    available_models: list[str] = field(default_factory=list)
    #: ``True``/``False`` when the server advertises a model list, else ``None``
    #: (model presence could not be verified, e.g. an empty ``/v1/models``).
    model_loaded: bool | None = None


class AdapterError(RuntimeError):
    """Raised when an adapter cannot complete a request."""


class AdapterTimeoutError(AdapterError):
    """Raised when a target did not respond within the per-request time budget.

    A subclass of :class:`AdapterError` so existing ``except AdapterError`` paths
    still catch it, but distinguishable by callers that treat a *slow/hung* target
    differently from an *unreachable or malformed* one. In particular, a probe run
    can record a timeout as an inconclusive outcome (rather than aborting the whole
    scan) — one endpoint that will not stop generating on a single request must not
    take down every other probe's result. ``timeout`` is the budget (seconds) that
    was exceeded.

    ``bytes_received`` is how much of the response body had arrived when the budget
    ran out, when the adapter can tell. It distinguishes the two shapes of an
    over-budget target, which matters for OWASP LLM10: ``0`` is a target that went
    quiet (a *stall*), while a large count is a target that kept producing output
    without terminating (a *drip*) — the second is measured resource consumption,
    not merely an absent answer. ``None`` means the adapter cannot report it.
    """

    def __init__(
        self,
        message: str,
        timeout: float | None = None,
        bytes_received: int | None = None,
    ):
        super().__init__(message)
        self.timeout = timeout
        self.bytes_received = bytes_received


class AdapterThrottleError(AdapterError):
    """Raised when a target refused the request because we asked too often (HTTP 429).

    A subclass of :class:`AdapterError` so it lands in the same *inconclusive, never a
    finding* channel as an unreachable endpoint, but distinguishable, and the distinction
    is the point. Until 2026-08-13 a throttle was neither: the vendor SDK's rate-limit
    exception matched nothing in :data:`_TRANSPORT_ERROR_NAMES`, so it propagated out of
    :func:`~llmsectest.probes.runner.run_probe`, failed the pytest test, and this suite
    renders a failing security test as a CVSS-scored OWASP finding. A hosted target that
    merely throttled us was published as a vulnerable one — the 2026-08-04 defect, alive
    in a second shape on every hosted provider. Measured on the real ``openai``
    ``RateLimitError`` before the fix, not inferred from reading the code.

    It is deliberately **not** folded into "is the endpoint reachable?". The endpoint was
    reached and answered, correctly, with a 429; an operator told to check their URL would
    look in the wrong place. ``retry_after`` carries the provider's ``Retry-After`` header
    in seconds when it sent one, because that is the number the operator actually needs.

    There is still no retry or backoff here, on purpose: the honest count comes before the
    backoff, the same order the 2026-08-05 undelivered fix took. Deciding *not* to score an
    answer we never got is a correctness property; retrying to get one is a feature, and
    a feature built on top of a wrong count would only produce a confident wrong number.
    """

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


#: Class names of a rate-limit refusal, matched across the exception's whole MRO. Name
#: matching catches ``openai``/``anthropic``'s ``RateLimitError`` and the ``TooManyRequests``
#: spelling used by ``requests``-style stacks. It is only half the test, because a provider
#: may raise a *generic* HTTP error carrying a 429 (``huggingface_hub`` raises
#: ``HfHubHTTPError``, whose name says nothing at all) — see :func:`http_status`.
_RATE_LIMIT_ERROR_NAMES = frozenset({"RateLimitError", "TooManyRequests"})

#: Class names of a transport-level failure, matched across the exception's whole MRO.
#: Matching by *name* rather than by type is what lets one helper serve every provider
#: without importing a single vendor SDK eagerly: it catches ``openai`` and
#: ``anthropic``'s ``APIConnectionError``/``APITimeoutError``, ``httpx``'s
#: ``ConnectError``, ``requests``' ``ConnectionError``/``Timeout``, and the stdlib pair,
#: including for a provider whose package is not installed here at all.
_TRANSPORT_ERROR_NAMES = frozenset({
    "APIConnectionError", "APITimeoutError",
    "ConnectionError", "ConnectError", "Timeout", "TimeoutError",
})


def is_transport_error(exc: BaseException) -> bool:
    """True for a failure to *reach* the target, as opposed to a failure of the target."""
    return bool({t.__name__ for t in type(exc).__mro__} & _TRANSPORT_ERROR_NAMES)


def http_status(exc: BaseException) -> int | None:
    """The HTTP status an SDK exception carries, wherever that SDK chose to put it.

    There is no shared convention: ``openai`` and ``anthropic`` expose ``status_code`` on
    the exception, ``httpx``/``requests``-based stacks hang a ``response`` object off it,
    and some wrappers only set ``.response.status_code``. Read every spelling and take the
    first integer that turns up, so a status-based rule works for a provider whose package
    is not installed here at all.
    """
    for value in (
        getattr(exc, "status_code", None),
        getattr(getattr(exc, "response", None), "status_code", None),
        getattr(exc, "code", None),
    ):
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def is_rate_limit_error(exc: BaseException) -> bool:
    """True when the target refused *because we asked too often*, not because it broke.

    Two independent tests, because either alone misses real providers: the exception's
    class name (``RateLimitError``), and an HTTP **429** carried anywhere
    :func:`http_status` looks. ``huggingface_hub`` is the case that needs the second one,
    since it raises a generic ``HfHubHTTPError`` for every status.
    """
    if {t.__name__ for t in type(exc).__mro__} & _RATE_LIMIT_ERROR_NAMES:
        return True
    return http_status(exc) == 429


def retry_after_seconds(exc: BaseException) -> float | None:
    """The provider's ``Retry-After`` header in seconds, when it sent one.

    Only the delta-seconds form is read. The HTTP-date form is legal too, but turning it
    into a wait needs the response clock, and a wrong number here is worse than none: it
    would go into a report as advice.

    Two places are read, because SDKs disagree about where the response goes.
    ``openai``/``anthropic`` hang a ``response`` object off the exception; the stdlib's
    ``urllib.error.HTTPError`` *is* the response and carries ``headers`` directly, which is
    the shape the ``app:<url>`` adapter raises. Reading only the first spelling silently
    dropped every ``Retry-After`` a real application sends us.
    """
    headers = getattr(getattr(exc, "response", None), "headers", None)
    if headers is None:
        headers = getattr(exc, "headers", None)
    if headers is None:
        return None
    try:
        raw = headers.get("retry-after") or headers.get("Retry-After")
    except (AttributeError, TypeError):
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


@contextlib.contextmanager
def transport_errors(provider: str, endpoint: str) -> Iterator[None]:
    """Translate a vendor SDK's transport failure into :class:`AdapterError`.

    Wrap the network call itself, and nothing else, in every adapter::

        with transport_errors(self.provider, "the Anthropic API"):
            resp = self._client.messages.create(...)

    **This is not cosmetic, it is what makes the report honest, and it was missing on
    two of our own adapters until 2026-08-12.** A probe that raises out of
    :func:`~llmsectest.probes.runner.run_probe` is a failing pytest test, and this suite
    renders a failing security test as a CVSS-scored OWASP finding, so an unreachable
    endpoint published a full set of critical vulnerabilities with a Python traceback as
    the evidence text (found in the cohort on 2026-08-04). The fix on 2026-08-05 gave
    ``run_probe`` an ``except AdapterError`` that records the probe *undelivered*
    instead, and exits the run non-zero. But that guarantee only reaches a target whose
    adapter actually raises ``AdapterError``: ``OpenAIAdapter`` translated, the
    ``anthropic`` and ``huggingface`` adapters did not, so both still published the
    2026-08-04 defect. Measured rather than assumed, with a fake SDK client raising the
    transport error each real SDK raises: ``run_probe`` propagated the raw exception on
    both, and returned ``undelivered`` on the openai control.

    Living here rather than in one adapter is the durable half: a **new** adapter gets
    the guarantee by using the helper, and ``test_adapter_transport.py`` fails when a
    provider is added to the registry without a case proving it, so the gap cannot be
    reintroduced silently.

    A **rate-limit refusal** is translated too, into :class:`AdapterThrottleError`, and
    for the same reason: an answer we never got must not be scored. It gets its own class
    and its own message because the operator's next move differs — reached-but-throttled
    is a budget to raise, unreachable is a URL to check. Added 2026-08-13, after measuring
    that a real ``openai.RateLimitError`` propagated out of ``run_probe`` and was published
    as a critical finding; the comment in ``openai_adapter.complete`` had recorded that
    behaviour as intentional ("rate limit … propagates unchanged"), which is how it
    survived the 2026-08-05 fix and the 2026-08-12 audit.

    Nothing else is translated (see :func:`is_transport_error`, :func:`is_rate_limit_error`).
    Every other error, including a malformed reply, an auth failure or a 500, propagates
    unchanged: those are facts about the target, and burying them here would trade one
    dishonest report for another.
    """
    try:
        yield
    except Exception as exc:  # broad on purpose: re-raised below unless we translate it
        if is_rate_limit_error(exc):
            retry_after = retry_after_seconds(exc)
            hint = (
                f" It asked us to retry after {retry_after:g}s."
                if retry_after is not None
                else ""
            )
            raise AdapterThrottleError(
                f"{provider} rate-limited the request to {endpoint} (HTTP 429).{hint} "
                f"No answer was returned, so nothing was scored "
                f"({type(exc).__name__}: {exc})",
                retry_after=retry_after,
            ) from exc
        if is_transport_error(exc):
            raise AdapterError(
                f"{provider} request to {endpoint} failed, is the endpoint reachable? "
                f"({type(exc).__name__}: {exc})"
            ) from exc
        raise


class LLMAdapter(abc.ABC):
    """Provider-agnostic chat-completion interface.

    Concrete adapters lazily import their vendor SDK inside ``__init__`` so that
    importing this package never requires every provider's dependency to be
    installed.
    """

    provider: str = "base"

    def __init__(self, model: str):
        self.model = model

    @abc.abstractmethod
    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """Run one chat completion and return the assistant text."""

    def preflight(self) -> PreflightResult | None:
        """Best-effort health check before a scan.

        Returns ``None`` when the provider exposes no cheap health endpoint (the
        scan then proceeds and surfaces any real error on its first request).
        Local OpenAI-compatible runtimes override this to verify the server is
        reachable and the requested model is loaded, raising
        :class:`AdapterError` with an actionable message on failure — so a
        down server / unloaded model fails fast instead of mid-suite.
        """
        return None

    def prompt(self, text: str, *, system: str | None = None, **kwargs) -> str:
        """Convenience: send a single user turn, return the response text."""
        messages: list[Message] = []
        if system is not None:
            messages.append(Message.system(system))
        messages.append(Message.user(text))
        return self.complete(CompletionRequest(messages=messages, **kwargs)).text
