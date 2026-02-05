import json
import re

from app.settings import settings
from app.llm.gemini_client import generate_content


def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _extract_json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("No JSON found")
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
    system = _load_prompt("app/llm/prompts/detector_system.txt")

    history = session.conversation[-settings.MAX_CONTEXT_MESSAGES :]
    hist_lines = [f"{m.get('sender')}: {m.get('text')}" for m in history]
    user = "Conversation (most recent last):\n" + "\n".join(hist_lines) + "\n\n" + "Classify scam intent for the latest incoming message."

    try:
        out = generate_content(system, user, temperature=0.0, max_tokens=180)
        data = _extract_json(out)

        allowed = {"scamDetected", "confidence", "scamType", "reasons"}
        data = {k: data.get(k) for k in allowed}

        data["scamDetected"] = bool(data.get("scamDetected"))
        try:
            conf = float(data.get("confidence"))
        except Exception:
            conf = 0.5
        data["confidence"] = max(0.0, min(1.0, conf))
        data["scamType"] = str(data.get("scamType") or "UNKNOWN")

        reasons = data.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        data["reasons"] = [str(x) for x in reasons][:6]

        # Thresholding
        if data["confidence"] < settings.SCAM_THRESHOLD:
            data["scamDetected"] = False

        return data

    except Exception:
        return _keyword_fallback(req.message.text)
