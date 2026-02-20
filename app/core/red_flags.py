"""
Red-flag tagger (deterministic)
--------------------------------
Goal: extract ONE high-signal red-flag tag from the latest scammer message,
then provide a short non-procedural statement usable as a prefix in the agent reply.

This supports Conversation Quality scoring by making red-flag identification explicit
and tying it to an investigative question each turn. [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class RedFlag:
    tag: str
    prefix: str  # statement (no question mark), safe and non-procedural


# Priority order matters: pick the FIRST match (strongest) to keep it deterministic.
# Keep patterns fast and conservative.
_OTP_RE = re.compile(r"\b(otp|one[- ]time password|pin|upi pin|password)\b", re.I)
_PAY_RE = re.compile(r"\b(upi|pay|payment|transfer|send money|fee|charges)\b", re.I)
_LINK_RE = re.compile(r"\b(https?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+|t\.co/\S+)\b", re.I)
_VERIFY_RE = re.compile(r"\b(verify|verification|kyc|login|update)\b", re.I)
_THREAT_RE = re.compile(r"\b(block|blocked|lock|locked|freeze|frozen|suspend|suspended|penalty|fine)\b", re.I)
_IMPERSONATION_RE = re.compile(
    r"\b(bank|sbi|hdfc|icici|rbi|customer care|support team|fraud team|kyc team)\b",
    re.I,
)
_URGENCY_RE = re.compile(r"\b(urgent|immediately|right now|within|minutes|hours|deadline)\b", re.I)


def choose_red_flag(latest_text: str, recent_tags: Optional[List[str]] = None) -> RedFlag:
    """
    Pick a single red-flag from latest_text, with optional rotation:
    if the best tag was used very recently, and another strong tag also matches,
    choose the next best to increase distinct red-flag mentions across turns.
    """
    t = latest_text or ""
    recent = [x for x in (recent_tags or []) if isinstance(x, str)]

    candidates: List[Tuple[str, bool]] = []

    # Strongest first
    candidates.append(("OTP_REQUEST", bool(_OTP_RE.search(t))))
    candidates.append(("PAYMENT_REQUEST", bool(_PAY_RE.search(t))))
    candidates.append(("SUSPICIOUS_LINK", bool(_LINK_RE.search(t) and _VERIFY_RE.search(t))))
    candidates.append(("THREAT_PRESSURE", bool(_THREAT_RE.search(t))))
    candidates.append(("IMPERSONATION_CLAIM", bool(_IMPERSONATION_RE.search(t))))
    candidates.append(("URGENCY_PRESSURE", bool(_URGENCY_RE.search(t))))

    # Filter matches in order
    matched = [tag for tag, ok in candidates if ok]
    if not matched:
        return RedFlag(tag="NONE", prefix="This message has some unusual pressure cues.")

    # Rotation: avoid repeating the same tag in the last 2 turns if possible
    if matched[0] in recent[-2:] and len(matched) > 1:
        chosen = matched[1]
    else:
        chosen = matched[0]

    # Safe, non-procedural prefixes (no steps, no navigation, no threats)
    prefixes = {
        "OTP_REQUEST": "Requesting an OTP or PIN over chat is a red flag.",
        "PAYMENT_REQUEST": "Asking for payments or transfers in a hurry is a red flag.",
        "SUSPICIOUS_LINK": "A verification link in a pressure message is suspicious.",
        "THREAT_PRESSURE": "Threats about blocking or locking the account are a red flag.",
        "IMPERSONATION_CLAIM": "Claiming to be an official team without proof is suspicious.",
        "URGENCY_PRESSURE": "Creating urgency to rush action is a common red flag.",
        "NONE": "This message has some unusual pressure cues.",
    }
    return RedFlag(tag=chosen, prefix=prefixes.get(chosen, prefixes["NONE"]))
