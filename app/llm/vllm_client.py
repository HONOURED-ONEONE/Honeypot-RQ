import os
import time
import random
import httpx

# Expect base url to include /v1
VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "").rstrip("/")
VLLM_API_KEY = os.getenv("VLLM_API_KEY", "")
VLLM_MODEL = os.getenv("VLLM_MODEL", "Qwen/Qwen2.5-14B-Instruct-AWQ")

# ✅ P1.4: Evaluation requires response < 30s end-to-end.
# Add strict per-request timeout + overall client budget with limited retries.
# Defaults are hackathon-friendly; override via env if needed.
#   VLLM_REQUEST_TIMEOUT_SEC: per HTTP request timeout (default 8s)
#   VLLM_CLIENT_BUDGET_SEC : total time budget across retries (default 24s)
#   VLLM_MAX_RETRIES       : max retry attempts (default 2)
REQUEST_TIMEOUT_SEC = float(os.getenv("VLLM_REQUEST_TIMEOUT_SEC", "8.0"))
CLIENT_BUDGET_SEC  = float(os.getenv("VLLM_CLIENT_BUDGET_SEC", "24.0"))
MAX_RETRIES        = int(os.getenv("VLLM_MAX_RETRIES", "2"))

_client = httpx.Client(timeout=REQUEST_TIMEOUT_SEC)


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
    start = time.time()
    attempt = 0
    last_err = None
    # ✅ P1.4: keep total attempts within a strict wall-clock budget
    while (time.time() - start) < CLIENT_BUDGET_SEC and attempt < max(1, MAX_RETRIES):
        attempt += 1
        try:
            resp = _client.post(url, headers=_headers(), json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.TimeoutException) as e:
            last_err = e
            # Backoff, but do not exceed remaining budget
            remaining = CLIENT_BUDGET_SEC - (time.time() - start)
            if remaining <= 0:
                break
            time.sleep(min(0.2 + random.uniform(0.0, 0.1), max(0.0, remaining)))
        except Exception as e:
            # Non-timeout errors: keep one retry if budget allows, else fail fast
            last_err = e
            remaining = CLIENT_BUDGET_SEC - (time.time() - start)
            if remaining <= 0 or attempt >= MAX_RETRIES:
                break
            time.sleep(min(0.2 + random.uniform(0.0, 0.1), max(0.0, remaining)))
    # Propagate as a single, budget-aware error; callers (detector/responder) already have safe fallbacks.
    elapsed = round(time.time() - start, 3)
    raise RuntimeError(f"vLLM call failed (attempts={attempt}, elapsed={elapsed}s): {last_err}")