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
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .base import (
    AdapterError,
    AdapterTimeoutError,
    CompletionRequest,
    CompletionResponse,
    LLMAdapter,
    Role,
)

_AUTODETECT = ("reply", "response", "output", "message", "content", "text", "answer")


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
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
        except TimeoutError as exc:
            raise self._timeout_error() from exc
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

    def _timeout_error(self) -> AdapterTimeoutError:
        return AdapterTimeoutError(
            f"app endpoint {self.endpoint} did not respond within "
            f"{self.timeout:g}s — the app did not bound its per-request work "
            "(raise --app-timeout if the app is legitimately slow)",
            timeout=self.timeout,
        )
