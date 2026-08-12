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


@dataclass
class CompletionResponse:
    text: str
    model: str
    provider: str
    raw: object = None
    usage: dict = field(default_factory=dict)


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

    Only transport failures are translated (see :func:`is_transport_error`). Every other
    error, including a malformed reply or a bad request, propagates unchanged: those are
    facts about the target, and burying them here would trade one dishonest report for
    another.
    """
    try:
        yield
    except Exception as exc:  # broad on purpose: re-raised below unless transport-level
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
