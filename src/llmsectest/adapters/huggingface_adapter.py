"""HuggingFace adapter via the Inference API (``huggingface_hub``).

Targets hosted chat models. Local transformers pipelines and the
LMStudio/Ollama OpenAI-compatible endpoints are separate adapters (milestone 2).
"""

from __future__ import annotations

import os

from .base import AdapterError, CompletionRequest, CompletionResponse, LLMAdapter


class HuggingFaceAdapter(LLMAdapter):
    provider = "huggingface"

    def __init__(
        self,
        model: str = "meta-llama/Llama-3.1-8B-Instruct",
        api_key: str | None = None,
    ):
        super().__init__(model)
        try:
            from huggingface_hub import InferenceClient
        except ImportError as exc:  # pragma: no cover - exercised only without SDK
            raise AdapterError(
                "huggingface_hub not installed; `pip install llmsectest[huggingface]`"
            ) from exc
        key = api_key or os.environ.get("HF_TOKEN")
        self._client = InferenceClient(model=model, token=key)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        resp = self._client.chat_completion(
            messages=[
                {"role": m.role.value, "content": m.content} for m in request.messages
            ],
            max_tokens=request.max_tokens,
            temperature=max(request.temperature, 0.01),
            stop=request.stop,
        )
        return CompletionResponse(
            text=resp.choices[0].message.content or "",
            model=self.model,
            provider=self.provider,
            raw=resp,
        )
