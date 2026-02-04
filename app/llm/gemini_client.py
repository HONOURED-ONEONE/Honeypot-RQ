import httpx
from app.settings import settings

# Gemini API (Developer API) - REST
# Endpoint format:
# POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
# Auth header: x-goog-api-key

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


def generate_content(system_text: str, user_text: str, *, temperature: float = 0.2, max_tokens: int = 256) -> str:
    if not settings.GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set")

    url = f"{BASE_URL}/models/{settings.GEMINI_MODEL}:generateContent"

    body = {
        "systemInstruction": {"role": "system", "parts": [{"text": system_text}]},
        "contents": [
            {"role": "user", "parts": [{"text": user_text}]}
        ],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        },
    }

    headers = {
        "x-goog-api-key": settings.GEMINI_API_KEY,
        "Content-Type": "application/json",
    }

    with httpx.Client(timeout=10) as client:
        resp = client.post(url, headers=headers, json=body)

    resp.raise_for_status()
    data = resp.json()
    # Standard response: candidates[0].content.parts[0].text
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return str(data)
