"""Adapters for downstream LLM providers used by the /chat endpoint."""

from __future__ import annotations

import os
from typing import Optional


class LLMClient:
    """Base interface."""

    name = "base"

    def generate(self, prompt: str, model: Optional[str] = None) -> str:  # pragma: no cover
        raise NotImplementedError


class EchoClient(LLMClient):
    """Default no-key client — useful for offline demos and unit tests."""

    name = "echo"

    def generate(self, prompt: str, model: Optional[str] = None) -> str:
        return f"[echo:{model or 'demo'}] {prompt}"


class GroqClient(LLMClient):
    """Groq API (https://console.groq.com)."""

    name = "groq"

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self._client = None

    def _ensure(self):
        if self._client is None:
            from groq import Groq  # type: ignore

            self._client = Groq(api_key=self.api_key)

    def generate(self, prompt: str, model: Optional[str] = None) -> str:
        self._ensure()
        resp = self._client.chat.completions.create(
            model=model or "llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=512,
        )
        return resp.choices[0].message.content


class OpenAIClient(LLMClient):
    name = "openai"

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self._client = None

    def _ensure(self):
        if self._client is None:
            from openai import OpenAI  # type: ignore

            self._client = OpenAI(api_key=self.api_key)

    def generate(self, prompt: str, model: Optional[str] = None) -> str:
        self._ensure()
        resp = self._client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=512,
        )
        return resp.choices[0].message.content


class OllamaClient(LLMClient):
    name = "ollama"

    def __init__(self, base_url: Optional[str] = None) -> None:
        self.base_url = base_url or os.environ.get(
            "OLLAMA_BASE_URL", "http://localhost:11434"
        )

    def generate(self, prompt: str, model: Optional[str] = None) -> str:
        import httpx

        resp = httpx.post(
            f"{self.base_url.rstrip('/')}/api/generate",
            json={"model": model or "llama3.2", "prompt": prompt, "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")


class HuggingFaceClient(LLMClient):
    """HuggingFace Inference Providers client (router.huggingface.co).

    Uses the new OpenAI-compatible Inference Providers API. Every HF user
    gets free monthly credits ($0.10/mo on free tier — hundreds of demo
    messages). Auth is the same HuggingFace token (hf_...).

    Get a token at https://huggingface.co/settings/tokens (Read scope).
    Set HUGGINGFACE_API_KEY (or HF_TOKEN) in your .env.

    Useful older / weaker-aligned models for prompt-injection demos:
        - meta-llama/Meta-Llama-3-8B-Instruct   (Llama 3, weaker than 3.1)
        - mistralai/Mistral-7B-Instruct-v0.2    (early Mistral, fewer guardrails)
        - mistralai/Mistral-Nemo-Instruct-2407  (newer but lightly aligned)
        - Qwen/Qwen2.5-7B-Instruct              (good instruction-following)
    """

    name = "huggingface"

    DEFAULT_MODEL = "meta-llama/Meta-Llama-3-8B-Instruct"
    BASE_URL = "https://router.huggingface.co/v1"

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = (
            api_key
            or os.environ.get("HUGGINGFACE_API_KEY")
            or os.environ.get("HF_TOKEN")
        )
        self._client = None

    def _ensure(self):
        if self._client is None:
            from openai import OpenAI  # type: ignore

            self._client = OpenAI(
                base_url=self.BASE_URL,
                api_key=self.api_key,
            )

    def generate(self, prompt: str, model: Optional[str] = None) -> str:
        if not self.api_key:
            return (
                "[huggingface error] No HUGGINGFACE_API_KEY set in .env. "
                "Get a free token at https://huggingface.co/settings/tokens"
            )

        model_id = model or self.DEFAULT_MODEL

        try:
            self._ensure()
            resp = self._client.chat.completions.create(
                model=model_id,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=512,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            msg = str(exc)
            # Friendly fallback messages
            if "401" in msg or "Unauthorized" in msg:
                return "[huggingface auth error] Invalid HUGGINGFACE_API_KEY."
            if "404" in msg or "not found" in msg.lower():
                return (
                    f"[huggingface error] Model '{model_id}' is not available "
                    "via the Inference Providers router. Try "
                    "meta-llama/Meta-Llama-3-8B-Instruct or "
                    "mistralai/Mistral-7B-Instruct-v0.2."
                )
            if "402" in msg or "payment" in msg.lower() or "credit" in msg.lower():
                return (
                    "[huggingface error] Free monthly credits exhausted. "
                    "Switch back to Groq for the rest of the demo, or "
                    "upgrade your HuggingFace plan."
                )
            return f"[huggingface error] {msg[:300]}"


def make_client(provider: Optional[str] = None) -> LLMClient:
    provider = (provider or os.environ.get("LLM_PROVIDER", "echo")).lower()
    if provider == "groq":
        return GroqClient()
    if provider == "openai":
        return OpenAIClient()
    if provider == "ollama":
        return OllamaClient()
    if provider in ("huggingface", "hf"):
        return HuggingFaceClient()
    return EchoClient()


__all__ = [
    "LLMClient",
    "EchoClient",
    "GroqClient",
    "OpenAIClient",
    "OllamaClient",
    "HuggingFaceClient",
    "make_client",
]