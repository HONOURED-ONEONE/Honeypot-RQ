import json
import re
import logging
from typing import Dict, Any, List, Tuple

from app.settings import settings
from app.llm.vllm_client import chat_completion

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


# High-signal regexes (for fallback + borderline confirmation)
OTP_TERMS = re.compile(r"(otp|pin|password)", re.I)
PAY_TERMS = re.compile(r"(upi|pay|payment|transfer|send money|fee|charges)", re.I)
LINK_TERMS = re.compile(r"(https?://|www\.|bit\.ly|tinyurl|t\.co)", re.I)
KYC_TERMS = re.compile(r"(kyc|verify|verification|login|update)", re.I)
THREAT_TERMS = re.compile(r"(block|blocked|suspend|suspended|freeze|locked|fine|penalty)", re.I)
IMPERSONATION_TERMS = re.compile(
    r"(bank|sbi|hdfc|icici|rbi|customer care|support team|kyc team|fraud team)", re.I
)


def _high_signal_flags(text: str) -> Tuple[bool, List[str], str]:
    """
    Returns:
    - high_signal: bool
    - reasons: list[str] (<=6)
    - scam_type_hint: str
    """
    t = text or ""
    reasons: List[str] = []
    scam_type_hint = "UNKNOWN"
    high = False

    if OTP_TERMS.search(t):
        high = True
        reasons.append("otp/pin/password request")
        scam_type_hint = "BANK_IMPERSONATION"

    if PAY_TERMS.search(t):
        high = True
        reasons.append("payment/upi request")
        if scam_type_hint == "UNKNOWN":
            scam_type_hint = "UPI_FRAUD"

    if LINK_TERMS.search(t) and KYC_TERMS.search(t):
        high = True
        reasons.append("link + verify/kyc/login")
        scam_type_hint = "PHISHING"

    if IMPERSONATION_TERMS.search(t) and (OTP_TERMS.search(t) or PAY_TERMS.search(t) or LINK_TERMS.search(t)):
        high = True
        reasons.append("impersonation + high-signal request")
        scam_type_hint = "BANK_IMPERSONATION"

    if THREAT_TERMS.search(t) and (OTP_TERMS.search(t) or PAY_TERMS.search(t) or LINK_TERMS.search(t)):
        high = True
        reasons.append("threat + high-signal request")
        if scam_type_hint == "UNKNOWN":
            scam_type_hint = "BANK_IMPERSONATION"

    return high, reasons[:6], scam_type_hint


def _keyword_fallback(text: str) -> dict:
    """
    Conservative fallback:
    - Only classify scam when high-signal indicators exist.
    - Confidence >= threshold so true high-signal scams can still pass SCAM_THRESHOLD=0.75.
    """
    high, reasons, scam_type_hint = _high_signal_flags(text)

    scam = bool(high)
    conf = 0.80 if scam else 0.25  # ensures scam fallback can pass threshold=0.75

    return {
        "scamDetected": scam,
        "confidence": conf,
        "scamType": (scam_type_hint if scam else "UNKNOWN"),
        "reasons": reasons,
    }


def detect_scam(req, session) -> dict:
    system = _load_prompt("app/llm/prompts/detector_system.txt")

    # Keep context small; latest message is primary.
    history = session.conversation[-min(settings.MAX_CONTEXT_MESSAGES, 6):]
    hist_lines = [f"{m.get('sender')}: {m.get('text')}" for m in history]

    latest_text = req.message.text or ""

    user_prompt = (
        "Classify the latest message.
"
        "Conversation context (most recent last):
"
        + "
".join(hist_lines)
        + "

"
        f"Latest message:
{latest_text}
"
    )

    high_signal, hs_reasons, hs_type = _high_signal_flags(latest_text)

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

            # Borderline confirmation pass only when high-signal exists
            if high_signal and conf >= 0.55:
                confirm_prompt = (
                    "STRICT CONFIRMATION:
"
                    "Be conservative. Mark scamDetected=true only if there is a clear high-signal indicator.
"
                    "Return JSON only.

"
                    f"Latest message:
{latest_text}
"
                )
                out2 = chat_completion(system, confirm_prompt, temperature=0.0, max_tokens=140)
                data2 = _extract_json(out2)

                scam2 = bool(data2.get("scamDetected", False))
                try:
                    conf2 = float(data2.get("confidence", 0.5))
                except Exception:
                    conf2 = 0.5
                conf2 = max(0.0, min(1.0, conf2))

                scam_type2 = str(data2.get("scamType") or hs_type or "UNKNOWN")
                reasons2 = data2.get("reasons") or hs_reasons
                if not isinstance(reasons2, list):
                    reasons2 = [str(reasons2)]
                reasons2 = [str(x) for x in reasons2][:6]

                if scam2 and conf2 >= settings.SCAM_THRESHOLD:
                    final_scam = True
                    final_conf = conf2
                    final_type = scam_type2
                    final_reasons = reasons2

        return {
            "scamDetected": bool(final_scam),
            "confidence": float(final_conf),
            "scamType": str(final_type or "UNKNOWN"),
            "reasons": list(final_reasons)[:6],
        }

    except Exception as e:
        logger.warning("detector_fallback_used err=%s", type(e).__name__)
        return _keyword_fallback(latest_text)
