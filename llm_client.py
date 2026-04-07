"""
llm_client.py — LLM provider abstraction
-----------------------------------------
Supports three backends, selected by LLM_PROVIDER in your .env:

  LLM_PROVIDER=anthropic        → uses the official Anthropic SDK
  LLM_PROVIDER=digitalocean     → DigitalOcean GenAI (OpenAI-compatible REST)
  LLM_PROVIDER=generic          → any OpenAI-compatible endpoint (custom URL + key)

All three expose the same interface:

    client = build_llm_client()
    response: LLMResponse = await client.chat(messages, model, max_tokens, system)

Response is a plain dataclass so the caller never needs to know which SDK
was used underneath.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

_log = logging.getLogger("guardrail.llm")


# ---------------------------------------------------------------------------
# Shared response shape — provider-agnostic
# ---------------------------------------------------------------------------

@dataclass
class LLMResponse:
    content:      str                    # the model's reply text
    model:        str                    # model string echoed back
    provider:     str                    # "anthropic" | "digitalocean" | "generic"
    raw:          dict = field(default_factory=dict)  # full raw response for debugging
    input_tokens:  int = 0
    output_tokens: int = 0


# ---------------------------------------------------------------------------
# Message type used by all callers
# ---------------------------------------------------------------------------

@dataclass
class ChatMessage:
    role:    str   # "user" | "assistant" | "system"
    content: str


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class _BaseLLMClient:
    provider: str = "base"

    async def chat(
        self,
        messages:   list[ChatMessage],
        model:      str,
        max_tokens: int           = 1024,
        system:     Optional[str] = None,
    ) -> LLMResponse:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Anthropic backend  (uses official SDK, not raw HTTP)
# ---------------------------------------------------------------------------

class AnthropicClient(_BaseLLMClient):
    """
    Wraps the official `anthropic` Python SDK.
    Required env vars:
        ANTHROPIC_API_KEY   your Anthropic key (sk-ant-...)
    """
    provider = "anthropic"

    def __init__(self, api_key: str):
        import anthropic as _sdk
        self._client = _sdk.AsyncAnthropic(api_key=api_key)

    async def chat(
        self,
        messages:   list[ChatMessage],
        model:      str           = "claude-sonnet-4-20250514",
        max_tokens: int           = 1024,
        system:     Optional[str] = None,
    ) -> LLMResponse:
        kwargs: dict[str, Any] = dict(
            model      = model,
            max_tokens = max_tokens,
            messages   = [{"role": m.role, "content": m.content} for m in messages],
        )
        if system:
            kwargs["system"] = system

        resp = await self._client.messages.create(**kwargs)
        raw  = resp.model_dump()

        return LLMResponse(
            content       = resp.content[0].text if resp.content else "",
            model         = resp.model,
            provider      = self.provider,
            raw           = raw,
            input_tokens  = getattr(resp.usage, "input_tokens",  0),
            output_tokens = getattr(resp.usage, "output_tokens", 0),
        )


# ---------------------------------------------------------------------------
# DigitalOcean GenAI backend
# ---------------------------------------------------------------------------

class DigitalOceanClient(_BaseLLMClient):
    """
    DigitalOcean GenAI Platform.

    Endpoint format: POST {DO_ENDPOINT_URL}/api/v1/chat/completions
    Auth:            Authorization: Bearer {DO_API_KEY}
    Note:            'model' is not sent — the agent is pre-configured with a model.

    Required env vars:
        DO_API_KEY          your DigitalOcean personal access token (dop_v1_...)
        DO_ENDPOINT_URL     base agent URL from the DO GenAI console, e.g.
                            https://<agent-id>.agents.do-ai.run

    The endpoint URL is shown in the DigitalOcean GenAI Platform UI under
    AI & ML → GenAI Platform → your agent → "API" tab.
    """
    provider = "digitalocean"

    def __init__(self, api_key: str, endpoint_url: str):
        self._key = api_key
        self._url = endpoint_url.rstrip("/") + "/api/v1/chat/completions"
        _log.info("DigitalOcean LLM client → %s", urlparse(self._url).netloc)

    async def chat(
        self,
        messages:   list[ChatMessage],
        model:      str           = "",     # unused — DO agent is pre-configured
        max_tokens: int           = 1024,
        system:     Optional[str] = None,
    ) -> LLMResponse:
        payload_messages = []
        if system:
            payload_messages.append({"role": "system", "content": system})
        payload_messages += [{"role": m.role, "content": m.content} for m in messages]

        payload = {
            "messages":              payload_messages,
            "max_tokens":            max_tokens,
            "stream":                False,
            "include_functions_info":  False,
            "include_retrieval_info":  False,
            "include_guardrails_info": False,
        }

        async with httpx.AsyncClient(timeout=60.0) as http:
            resp = await http.post(
                self._url,
                headers={
                    "Authorization": f"Bearer {self._key}",
                    "Content-Type":  "application/json",
                },
                content=json.dumps(payload),
            )

        if not resp.is_success:
            _log.error(
                "DigitalOcean error: status=%d body=%s",
                resp.status_code, resp.text[:500],
            )
            resp.raise_for_status()

        raw = resp.json()
        try:
            text = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            _log.error("DigitalOcean unexpected response shape: %s — body: %s", exc, str(raw)[:500])
            raise ValueError(f"Unexpected response format from DigitalOcean: {exc}") from exc

        usage = raw.get("usage", {})
        return LLMResponse(
            content       = text,
            model         = raw.get("model", ""),
            provider      = self.provider,
            raw           = raw,
            input_tokens  = usage.get("prompt_tokens",     0),
            output_tokens = usage.get("completion_tokens", 0),
        )


# ---------------------------------------------------------------------------
# Generic OpenAI-compatible backend  (any URL + Bearer key)
# ---------------------------------------------------------------------------

class GenericOpenAIClient(_BaseLLMClient):
    """
    Talks to any endpoint that speaks the OpenAI chat completions protocol.
    Works with: Ollama, vLLM, LM Studio, Together AI, Groq, Azure OpenAI, etc.

    Required env vars:
        GENERIC_API_KEY         API key / token for the endpoint
        GENERIC_ENDPOINT_URL    Base URL, e.g. http://localhost:11434/v1
                                The client appends /chat/completions automatically.

    Optional:
        GENERIC_AUTH_HEADER     Header name to send the key in.
                                Defaults to "Authorization" (Bearer token).
                                Set to "api-key" for Azure OpenAI.
        GENERIC_AUTH_PREFIX     Prefix before the key value.
                                Defaults to "Bearer ".
                                Set to "" for endpoints that want the raw key.
    """
    provider = "generic"

    def __init__(
        self,
        api_key:      str,
        endpoint_url: str,
        auth_header:  str = "Authorization",
        auth_prefix:  str = "Bearer ",
    ):
        self._key         = api_key
        self._base        = endpoint_url.rstrip("/")
        self._url         = f"{self._base}/chat/completions"
        self._auth_header = auth_header
        self._auth_prefix = auth_prefix
        _log.info("Generic LLM client → %s  (auth header: %s)", urlparse(self._url).netloc, auth_header)

    async def chat(
        self,
        messages:   list[ChatMessage],
        model:      str           = "gpt-4o",
        max_tokens: int           = 1024,
        system:     Optional[str] = None,
    ) -> LLMResponse:
        payload_messages = []
        if system:
            payload_messages.append({"role": "system", "content": system})
        payload_messages += [{"role": m.role, "content": m.content} for m in messages]

        payload = {
            "model":      model,
            "messages":   payload_messages,
            "max_tokens": max_tokens,
        }

        async with httpx.AsyncClient(timeout=60.0) as http:
            resp = await http.post(
                self._url,
                headers={
                    self._auth_header: f"{self._auth_prefix}{self._key}",
                    "Content-Type":    "application/json",
                },
                content=json.dumps(payload),
            )

        if not resp.is_success:
            _log.error(
                "Generic LLM error: status=%d url=%s body=%s",
                resp.status_code, self._url, resp.text[:500],
            )
            resp.raise_for_status()

        raw = resp.json()
        try:
            text = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            _log.error("Generic LLM unexpected response shape: %s — body: %s", exc, str(raw)[:500])
            raise ValueError(f"Unexpected response format from generic endpoint: {exc}") from exc

        usage = raw.get("usage", {})
        return LLMResponse(
            content       = text,
            model         = raw.get("model", model),
            provider      = self.provider,
            raw           = raw,
            input_tokens  = usage.get("prompt_tokens",     0),
            output_tokens = usage.get("completion_tokens", 0),
        )


# ---------------------------------------------------------------------------
# Factory — call this once at startup
# ---------------------------------------------------------------------------

def build_llm_client() -> Optional[_BaseLLMClient]:
    """
    Read LLM_PROVIDER from the environment and return the appropriate client.
    Returns None if no provider is configured (server runs in echo/test mode).

    LLM_PROVIDER=anthropic
        Needs: ANTHROPIC_API_KEY

    LLM_PROVIDER=digitalocean
        Needs: DO_API_KEY, DO_ENDPOINT_URL

    LLM_PROVIDER=generic
        Needs: GENERIC_API_KEY, GENERIC_ENDPOINT_URL
        Optional: GENERIC_AUTH_HEADER, GENERIC_AUTH_PREFIX
    """
    provider = os.environ.get("LLM_PROVIDER", "").lower().strip()

    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            _log.warning("LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set — running in echo mode")
            return None
        _log.info("LLM backend: Anthropic")
        return AnthropicClient(api_key=key)

    if provider == "digitalocean":
        key = os.environ.get("DO_API_KEY", "")
        url = os.environ.get("DO_ENDPOINT_URL", "")
        if not key or not url:
            _log.warning(
                "LLM_PROVIDER=digitalocean but DO_API_KEY or DO_ENDPOINT_URL is not set "
                "— running in echo mode"
            )
            return None
        _log.info("LLM backend: DigitalOcean  url=%s", url)
        return DigitalOceanClient(api_key=key, endpoint_url=url)

    if provider == "generic":
        key = os.environ.get("GENERIC_API_KEY", "")
        url = os.environ.get("GENERIC_ENDPOINT_URL", "")
        if not key or not url:
            _log.warning(
                "LLM_PROVIDER=generic but GENERIC_API_KEY or GENERIC_ENDPOINT_URL is not set "
                "— running in echo mode"
            )
            return None
        auth_header = os.environ.get("GENERIC_AUTH_HEADER", "Authorization")
        auth_prefix = os.environ.get("GENERIC_AUTH_PREFIX", "Bearer ")
        _log.info("LLM backend: Generic  url=%s", url)
        return GenericOpenAIClient(
            api_key      = key,
            endpoint_url = url,
            auth_header  = auth_header,
            auth_prefix  = auth_prefix,
        )

    if provider:
        _log.warning("Unknown LLM_PROVIDER=%r — running in echo mode", provider)
    else:
        _log.info("LLM_PROVIDER not set — running in echo mode (no LLM forwarding)")

    return None
