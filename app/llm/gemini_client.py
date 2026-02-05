import httpx
import random
import time

from app.settings import settings

# Gemini Developer API (REST)
# POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

# Reuse a single client for keep-alive
_client = httpx.Client(timeout=15)


def _sleep_backoff(attempt: int, retry_after: float | None = None) -> None:
    """Small bounded exponential backoff with jitter (score-friendly)."""
    if retry_after is not None:
        time.sleep(retry_after)
        return
    base = min(2.0, 0.35 * (2 ** attempt))
    time.sleep(base + random.uniform(0.0, 0.2))


def generate_content(system_text: str, user_text: str, *, temperature: float = 0.2, max_tokens: int = 256) -> str:
    """Generate text via Gemini.

    Retries briefly on 429/5xx with bounded backoff.
    Raises RuntimeError if still failing after retries.
    """

    if not settings.GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set")

    url = f"{BASE_URL}/models/{settings.GEMINI_MODEL}:generateContent"

    body = {
        "systemInstruction": {"role": "system", "parts": [{"text": system_text}]},
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
        "generationConfig": {"temperature": float(temperature), "maxOutputTokens": int(max_tokens)},
    }

    headers = {
        "x-goog-api-key": settings.GEMINI_API_KEY,
        "Content-Type": "application/json",
    }

    last_error = None

    for attempt in range(3):
        resp = _client.post(url, headers=headers, json=body)

        if resp.status_code < 400:
            data = resp.json()
            try:
                return data["candidates"][0]["content"]["parts"][0]["text"]
            except Exception:
                return str(data)

        # Retry on rate limiting / transient server errors
        if resp.status_code in (429, 500, 503):
            last_error = f"{resp.status_code} {resp.text}"
            retry_after = None
            if "retry-after" in resp.headers:
                try:
                    retry_after = float(resp.headers["retry-after"])
                except Exception:
                    retry_after = None
            _sleep_backoff(attempt, retry_after=retry_after)
            continue

        # Non-retriable
        last_error = f"{resp.status_code} {resp.text}"
        break

    raise RuntimeError(f"Gemini API unavailable/rate-limited after retries: {last_error}")
