"""OpenAI LLM adapter implementation."""

from typing import Any, List, Optional

from llmsectest.core.base import LLMAdapter, LLMMessage, LLMResponse


class OpenAIAdapter(LLMAdapter):
    """Adapter for OpenAI models (GPT-4, GPT-3.5, etc.)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4",
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> None:
        """
        Initialize OpenAI adapter.

        Args:
            api_key: OpenAI API key (or use OPENAI_API_KEY env var)
            model: Model to use (default: gpt-4)
            temperature: Sampling temperature
            **kwargs: Additional OpenAI API parameters
        """
        super().__init__(model=model, **kwargs)
        self.api_key = api_key
        self.temperature = temperature
        self._client: Optional[Any] = None

    def _get_client(self) -> Any:
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
            except ImportError:
                raise ImportError(
                    "OpenAI package not installed. Install with: pip install llmsectest[openai]"
                )

            self._client = AsyncOpenAI(api_key=self.api_key)
        return self._client

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[LLMMessage]] = None,
    ) -> LLMResponse:
        """
        Send a message to OpenAI API.

        Args:
            message: User message
            system_prompt: Optional system prompt
            conversation_history: Optional conversation history

        Returns:
            LLMResponse with model output
        """
        client = self._get_client()

        messages = []

        # Add system prompt if provided
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        # Add conversation history if provided
        if conversation_history:
            for msg in conversation_history:
                messages.append({"role": msg.role, "content": msg.content})

        # Add current message
        messages.append({"role": "user", "content": message})

        # Call OpenAI API
        response = await client.chat.completions.create(
            model=self.model or "gpt-4",
            messages=messages,
            temperature=self.temperature,
            **self.config,
        )

        # Extract response
        content = response.choices[0].message.content or ""

        return LLMResponse(
            content=content,
            model=self.model or "gpt-4",
            provider="openai",
            metadata={
                "finish_reason": response.choices[0].finish_reason,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                }
                if response.usage
                else {},
            },
        )

    def get_provider_name(self) -> str:
        """Get provider name."""
        return "openai"

    def get_model_name(self) -> str:
        """Get model name."""
        return self.model or "gpt-4"
