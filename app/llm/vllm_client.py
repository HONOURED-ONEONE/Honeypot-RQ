import os
import time
import random
import httpx

# Expect base url to include /v1
VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "").rstrip("/")
VLLM_API_KEY = os.getenv("VLLM_API_KEY", "")
VLLM_MODEL = os.getenv("VLLM_MODEL", "qwen/Qwen-2.5-14B-Instruct-AWQ")

_client = httpx.Client(timeout=90)


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if VLLM_API_KEY:
        h["Authorization"] = f"Bearer {VLLM_API_KEY}"
    return h


def chat_completion(system: str, user: str, *, temperature: float = 0.4, max_tokens: int = 120) -> str:
    """Call vLLM OpenAI-compatible chat endpoint.

    POST {VLLM_BASE_URL}/chat/completions
    """
    if not VLLM_BASE_URL:
        raise RuntimeError("VLLM_BASE_URL is not set")

    url = f"{VLLM_BASE_URL}/chat/completions"
    payload = {
        "model": VLLM_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
    }

    last_err = None
    for attempt in range(3):
        try:
            resp = _client.post(url, headers=_headers(), json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            last_err = e
            time.sleep(0.4 + random.uniform(0.0, 0.2))

    raise RuntimeError(f"vLLM call failed: {last_err}")
