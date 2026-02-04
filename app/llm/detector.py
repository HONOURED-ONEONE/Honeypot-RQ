import json
import re
from app.settings import settings
from app.llm.gemini_client import generate_content


def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _extract_json(text: str) -> dict:
    # Extract first JSON object from model output
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("No JSON found")
    return json.loads(m.group(0))


def detect_scam(req, session) -> dict:
    system = _load_prompt("app/llm/prompts/detector_system.txt")

    # Use a short context window for speed
    history = session.conversation[-settings.MAX_CONTEXT_MESSAGES :]
    hist_lines = []
    for msg in history:
        sender = msg.get("sender")
        text = msg.get("text")
        hist_lines.append(f"{sender}: {text}")

    user = "Conversation (most recent last):\n" + "\n".join(hist_lines) + "\n\n" + "Classify scam intent for the latest incoming message."

    try:
        out = generate_content(system, user, temperature=0.0, max_tokens=180)
        data = _extract_json(out)
        # strict key set
        allowed = {"scamDetected", "confidence", "scamType", "reasons"}
        data = {k: data.get(k) for k in allowed}
        # normalize types
        data["scamDetected"] = bool(data.get("scamDetected"))
        conf = data.get("confidence")
        try:
            conf = float(conf)
        except Exception:
            conf = 0.5
        data["confidence"] = max(0.0, min(1.0, conf))
        data["scamType"] = str(data.get("scamType") or "UNKNOWN")
        reasons = data.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        data["reasons"] = [str(x) for x in reasons][:6]
        # Apply threshold
        if data["confidence"] < settings.SCAM_THRESHOLD:
            data["scamDetected"] = False
        return data
    except Exception:
        # Minimal fallback: keyword-based
        t = req.message.text.lower()
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
