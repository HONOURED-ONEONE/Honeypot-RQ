import json
import re
import logging
from typing import Dict, Any, List, Tuple

from app.settings import settings
from app.llm.vllm_client import chat_completion
from app.llm.signals import score_conversation, score_message

logger = logging.getLogger("honeypot_detector")


def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _extract_json(text: str) -> Dict[str, Any]:
    """
    Robustly parse JSON from model output.
    1) Try json.loads on full string
    2) If that fails, find first '{' and use JSONDecoder.raw_decode to parse first JSON object
    """
    if not text:
        raise ValueError("Empty model output")

    s = text.strip()

    # Fast path: exact JSON
    try:
        return json.loads(s)
    except Exception:
        pass

    # Fallback: decode the first JSON object from the first '{'
    start = s.find("{")
    if start == -1:
        raise ValueError("No JSON object found in model output")

    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(s[start:])
    return obj


def _keyword_fallback(text: str) -> dict:
    """
    Conservative fallback:
    - Only classify scam when high-signal indicators exist.
    - Confidence >= threshold so true high-signal scams can still pass SCAM_THRESHOLD=0.75.
    """
    # Use the shared deterministic scorer for fallback robustness.
    s, rs, th = score_message(text or "")
    scam = bool(s >= 0.75)  # strict fallback: require strong evidence in one message
    conf = 0.82 if scam else 0.25
    return {
        "scamDetected": scam,
        "confidence": conf,
        "scamType": (th if scam else "UNKNOWN"),
        "reasons": rs[:4],
    }


def detect_scam(req, session) -> dict:
    system = _load_prompt("app/llm/prompts/detector_system.txt")

    # Keep context small; latest message is primary.
    history = session.conversation[-min(settings.MAX_CONTEXT_MESSAGES, 6):]
    hist_lines = [f"{m.get('sender')}: {m.get('text')}" for m in history]

    latest_text = req.message.text or ""

    # -----------------------------
    # Deterministic signal scoring (latest + cumulative)
    # -----------------------------
    try:
        # Score a window of recent scammer messages (latest included if scammer)
        recent_msgs: List[str] = []
        for m in reversed(session.conversation or []):
            if len(recent_msgs) >= int(getattr(settings, "DETECTOR_CUMULATIVE_WINDOW", 6) or 6):
                break
            if (m.get("sender") or "").lower() == "scammer":
                recent_msgs.append(m.get("text") or "")
        recent_msgs = list(reversed(recent_msgs))
        agg = score_conversation(recent_msgs if recent_msgs else [latest_text])
    except Exception:
        agg = {
            "cumulative_score": 0.0,
            "max_score": 0.0,
            "reasons": [],
            "type_hint": "UNKNOWN",
            "high_signal_seen": False,
        }

    user_prompt = (
        "Classify the latest message.\n"
        "Conversation context (most recent last):\n"
        + "\n".join(hist_lines)
        + "\n\n"
        f"Latest message:\n{latest_text}\n"
        "\n"
        "Deterministic signal summary (for calibration, not hard rules):\n"
        f"- cumulative_score: {agg.get('cumulative_score')}\n"
        f"- max_score: {agg.get('max_score')}\n"
        f"- high_signal_seen: {agg.get('high_signal_seen')}\n"
    )

    try:
        out = chat_completion(system, user_prompt, temperature=0.0, max_tokens=180)
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

        # Final decision (precision + recall) with SCAM_THRESHOLD
        if conf >= settings.SCAM_THRESHOLD:
            final_scam = scam
            final_conf = conf
            final_type = scam_type
            final_reasons = reasons
        else:
            final_scam = False
            final_conf = conf
            final_type = scam_type
            final_reasons = reasons

        # -----------------------------
        # Cumulative override (generic, scenario-agnostic):
        # If evidence accumulates across turns, avoid false negatives on slow-burn scams.
        # -----------------------------
        if getattr(settings, "DETECTOR_CUMULATIVE_MODE", True):
            try:
                cum = float(agg.get("cumulative_score", 0.0) or 0.0)
                mx = float(agg.get("max_score", 0.0) or 0.0)
                cum_thr = float(getattr(settings, "DETECTOR_CUMULATIVE_SCORE", 0.62) or 0.62)
                mx_thr = float(getattr(settings, "DETECTOR_MAX_SCORE", 0.75) or 0.75)
                # Trigger if either one strong message OR multiple moderate signals across turns
                if (mx >= mx_thr) or (cum >= cum_thr and bool(agg.get("high_signal_seen"))):
                    final_scam = True
                    final_type = str(final_type or agg.get("type_hint") or "UNKNOWN")
                    # Ensure confidence passes the global threshold while staying bounded
                    final_conf = max(float(final_conf), max(settings.SCAM_THRESHOLD, 0.82))
                    # Prefer deterministic reasons if LLM reasons are empty/weak
                    det_rs = agg.get("reasons") or []
                    if not final_reasons and det_rs:
                        final_reasons = [str(x) for x in det_rs][:4]
            except Exception:
                pass

        return {
            "scamDetected": bool(final_scam),
            "confidence": float(final_conf),
            "scamType": str(final_type or "UNKNOWN"),
            "reasons": list(final_reasons)[:6],
        }

    except Exception as e:
        logger.warning("detector_fallback_used err=%s", type(e).__name__)
        return _keyword_fallback(latest_text)
