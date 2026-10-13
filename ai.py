"""
AI provider layer for CybrWire

One async entry point, generate(), backed by whichever provider the user
configures under the `ai:` section of cybrwire_local.yaml / usrwire.yaml:

    ai:
      provider: "anthropic"   # anthropic | gemini | openai | openrouter | ollama | openai_compatible
      api_key: "..."          # not needed for ollama
      model: ""               # blank = provider default below
      base_url: ""            # only for ollama / openai_compatible overrides
"""

import asyncio
import logging
from typing import Any, Dict, Optional

import httpx

TIMEOUT = httpx.Timeout(120.0, connect=10.0)
MAX_OUTPUT_TOKENS = 16000
RETRIES = 2
RETRY_STATUSES = {429, 500, 502, 503, 504, 529}  # Overloaded / rate limited - usually temporary

PROVIDERS = {
    # name: (default model, default base URL)
    "anthropic": ("claude-opus-5-5", None),
    "gemini": ("gemini-flash-latest", "https://generativelanguage.googleapis.com/v1beta"),
    "openai": (None, "https://api.openai.com/v1"),
    "openrouter": (None, "https://openrouter.ai/api/v1"),
    "ollama": (None, "http://localhost:11434/v1"),
    "openai_compatible": (None, None),
}

# Claude models that accept server-side refusal fallbacks
ANTHROPIC_FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}


class AIError(Exception):
    """Raised with a short, user-facing message"""


def describe(settings: Dict[str, Any]) -> str:
    """Short label such as 'anthropic / claude-opus-5-5'"""
    provider = settings.get("provider", "")
    model = settings.get("model") or PROVIDERS.get(provider, (None, None))[0] or "?"
    return f"{provider} / {model}"


def configuration_problem(settings: Dict[str, Any]) -> Optional[str]:
    """Return a reason the AI settings can't work, or None if they look usable"""
    provider = settings.get("provider")
    if not provider:
        return "No AI provider configured (see the ai: section in usrwire.yaml)"
    if provider not in PROVIDERS:
        return f"Unknown AI provider '{provider}'. Use one of: {', '.join(PROVIDERS)}"
    default_model, default_url = PROVIDERS[provider]
    if not (settings.get("model") or default_model):
        return f"Set ai.model for provider '{provider}'"
    if provider not in ("ollama",) and not settings.get("api_key"):
        return f"Set ai.api_key for provider '{provider}'"
    if not (settings.get("base_url") or default_url) and provider != "anthropic":
        return f"Set ai.base_url for provider '{provider}'"
    return None


async def generate(settings: Dict[str, Any], system: str, prompt: str) -> str:
    """Send one prompt to the configured provider and return the text reply"""
    problem = configuration_problem(settings)
    if problem:
        raise AIError(problem)

    provider = settings["provider"]
    default_model, default_url = PROVIDERS[provider]
    model = settings.get("model") or default_model
    base_url = (settings.get("base_url") or default_url or "").rstrip("/")
    api_key = settings.get("api_key", "")

    if provider == "anthropic":
        return await _anthropic(api_key, model, system, prompt)  # The SDK retries on its own

    for attempt in range(RETRIES + 1):
        try:
            if provider == "gemini":
                return await _gemini(base_url, api_key, model, system, prompt)
            return await _openai_compatible(provider, base_url, api_key, model, system, prompt)
        except (httpx.HTTPStatusError, httpx.TransportError) as e:
            retryable = isinstance(e, httpx.TransportError) or e.response.status_code in RETRY_STATUSES
            if retryable and attempt < RETRIES:
                await asyncio.sleep(2 ** (attempt + 1))
                continue
            raise _friendly_error(provider, e)


def _friendly_error(provider: str, e: httpx.HTTPError) -> AIError:
    if isinstance(e, httpx.HTTPStatusError):
        logging.error(f"AI request failed: {e.response.status_code} {e.response.text[:500]}")
        if e.response.status_code in RETRY_STATUSES:
            return AIError(f"{provider} is busy or rate limited (HTTP {e.response.status_code}) - try again shortly")
        return AIError(f"{provider} returned HTTP {e.response.status_code} - see cybrwire.log")
    logging.error(f"AI request failed: {e!r}")
    return AIError(f"Could not reach {provider}: {type(e).__name__}")


async def _anthropic(api_key: str, model: str, system: str, prompt: str) -> str:
    try:
        import anthropic
    except ImportError:
        raise AIError("Install the Anthropic SDK: pip install anthropic")

    client = anthropic.AsyncAnthropic(api_key=api_key)
    request = dict(
        model=model,
        max_tokens=MAX_OUTPUT_TOKENS,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    try:
        if model in ANTHROPIC_FALLBACK_MODELS:
            # If a safety classifier declines (threat intel can trip the cyber
            # classifier), the API retries on a suitable fallback model.
            response = await client.beta.messages.create(
                **request, betas=["server-side-fallback-2026-07-01"], fallbacks="default"
            )
        else:
            response = await client.messages.create(**request)
    except anthropic.AuthenticationError:
        raise AIError("Anthropic rejected the API key")
    except anthropic.NotFoundError:
        raise AIError(f"Anthropic model '{model}' not found")
    except anthropic.RateLimitError:
        raise AIError("Anthropic rate limit hit - try again shortly")
    except anthropic.APIStatusError as e:
        logging.error(f"Anthropic API error {e.status_code}: {e.message}")
        raise AIError(f"Anthropic returned HTTP {e.status_code} - see cybrwire.log")
    except anthropic.APIConnectionError:
        raise AIError("Could not reach Anthropic")
    finally:
        await client.close()

    if response.stop_reason == "refusal":
        raise AIError("The model declined to produce this analysis")
    text = "".join(block.text for block in response.content if block.type == "text")
    if not text.strip():
        raise AIError("Anthropic returned an empty response")
    return text


async def _gemini(base_url: str, api_key: str, model: str, system: str, prompt: str) -> str:
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.post(
            f"{base_url}/models/{model}:generateContent",
            headers={"x-goog-api-key": api_key},
            json={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            },
        )
        r.raise_for_status()
        data = r.json()

    candidates = data.get("candidates") or []
    if not candidates:
        reason = (data.get("promptFeedback") or {}).get("blockReason", "no candidates")
        raise AIError(f"Gemini returned no answer ({reason})")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    if not text.strip():
        raise AIError(f"Gemini returned an empty response ({candidates[0].get('finishReason', '?')})")
    return text


async def _openai_compatible(provider: str, base_url: str, api_key: str, model: str, system: str, prompt: str) -> str:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        r.raise_for_status()
        data = r.json()

    choices = data.get("choices") or []
    text = ((choices[0].get("message") or {}).get("content") if choices else "") or ""
    if not text.strip():
        raise AIError(f"{provider} returned an empty response")
    return text
