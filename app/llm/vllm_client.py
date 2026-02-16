import os
import time
import random
import httpx
from typing import Any, Dict

# RunPod Serverless base URL (NO /v1)
# Example:
# https://kfozaa65npdw6t.api.runpod.ai
VLLM_BASE_URL = os.getenv("VLLM_BASE_URL", "").rstrip("/")
VLLM_API_KEY = os.getenv("VLLM_API_KEY", "")
VLLM_MODEL = os.getenv("VLLM_MODEL", "qwen/Qwen-2.5-14B-Instruct-AWQ")

_client = httpx.Client(timeout=120)


def _headers() -> Dict[str, str]:
    if not VLLM_API_KEY:
        raise RuntimeError("VLLM_API_KEY is not set")

    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {VLLM_API_KEY}",
    }


def _extract_content(data: Dict[str, Any]) -> str:
    """
    Extract OpenAI-style content from RunPod serverless response.
    """
    if data.get("status") and data["status"] != "COMPLETED":
        raise RuntimeError(f"RunPod job not completed. Status={data['status']}")

    output = data.get("output")
    if not output:
        raise RuntimeError("RunPod response missing 'output'")

    try:
        return output["choices"][0]["message"]["content"]
    except Exception:
        raise RuntimeError(f"Unexpected RunPod output format: {output}")


def chat_completion(
    system: str,
    user: str,
    *,
    temperature: float = 0.4,
    max_tokens: int = 120,
) -> str:
    """
    Calls RunPod Serverless endpoint.

    POST {VLLM_BASE_URL}/run
    """

    if not VLLM_BASE_URL:
        raise RuntimeError("VLLM_BASE_URL is not set")

    url = f"{VLLM_BASE_URL}/run"

    payload = {
        "input": {
            "model": VLLM_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": float(temperature),
            "max_tokens": int(max_tokens),
        }
    }

    last_err = None

    for attempt in range(3):
        try:
            resp = _client.post(url, headers=_headers(), json=payload)
            resp.raise_for_status()
            data = resp.json()

            return _extract_content(data)

        except Exception as e:
            last_err = e
            time.sleep(0.6 + random.uniform(0.0, 0.3))

    raise RuntimeError(f"RunPod serverless call failed: {last_err}")