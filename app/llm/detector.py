import json
import re

from app.settings import settings
from app.llm.vllm_client import chat_completion


def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _extract_json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("No JSON found in model output")
    return json.loads(m.group(0))


def _keyword_fallback(text: str) -> dict:
    t = (text or "").lower()
    hits = []
    for k in ["otp", "pin", "verify", "blocked", "suspended", "upi", "click", "link", "kyc", "urgent"]:
        if k in t:
            hits.append(k)
    scam = len(hits) >= 2
    return {
        "scamDetected": scam,
        "confidence": 0.6 if scam else 0.3,
        "scamType": "UNKNOWN",
        "reasons": hits,
    }


def detect_scam(req, session) -> dict:
    # Reuse your existing detector system prompt if present
    system = _load_prompt("app/llm/prompts/detector_system.txt")

    history = session.conversation[-settings.MAX_CONTEXT_MESSAGES:]
    hist_lines = [f"{m.get('sender')}: {m.get('text')}" for m in history]

    user = (
        "You are a scam intent classifier.\n"
        "Return ONLY valid JSON with exactly these keys:\n"
        "{\"scamDetected\": boolean, \"confidence\": number(0..1), \"scamType\": string, \"reasons\": [string]}\n\n"
        "Conversation (most recent last):\n" + "\n".join(hist_lines) + "\n\n"
        f"Latest message:\n{req.message.text}\n\n"
        "Do not include any extra text, markdown, or explanations. JSON only."
    )

    try:
        out = chat_completion(system, user, temperature=0.0, max_tokens=160)
        data = _extract_json(out)

        scam = bool(data.get("scamDetected", False))
        try:
            conf = float(data.get("confidence", 0.5))
        except Exception:
            conf = 0.5
        conf = max(0.0, min(1.0, conf))
        scam_type = str(data.get("scamType") or "UNKNOWN")

        reasons = data.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        reasons = [str(x) for x in reasons][:6]

        if conf < settings.SCAM_THRESHOLD:
            scam = False

        return {
            "scamDetected": scam,
            "confidence": conf,
            "scamType": scam_type,
            "reasons": reasons,
        }

    except Exception:
        return _keyword_fallback(req.message.text)
