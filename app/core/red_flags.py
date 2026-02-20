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
    prefix: str  # persona cue statement (no question mark), safe and non-procedural
    style: str   # "CONFUSION" | "SKEPTICAL" | "TECH_FRICTION" | "DELAY"


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


def choose_red_flag(
    latest_text: str,
    recent_tags: Optional[List[str]] = None,
    escalation: bool = False,
    recent_styles: Optional[List[str]] = None,
) -> RedFlag:
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
        # Neutral but still human; prefer confusion in normal mode, delay in escalation.
        if escalation:
            return RedFlag(tag="NONE", prefix="I may need a moment before I can check this properly.", style="DELAY")
        return RedFlag(tag="NONE", prefix="I’m a bit unsure about this message.", style="CONFUSION")

    # Rotation: avoid repeating the same tag in the last 2 turns if possible
    if matched[0] in recent[-2:] and len(matched) > 1:
        chosen = matched[1]
    else:
        chosen = matched[0]

    # Persona style selection:
    # - Behavioral flags: CONFUSION / SKEPTICAL
    # - Escalation: TECH_FRICTION / DELAY
    styles_recent = [x for x in (recent_styles or []) if isinstance(x, str)]
    if escalation:
        # rotate between TECH_FRICTION and DELAY to avoid repetition
        style = "TECH_FRICTION" if (not styles_recent or styles_recent[-1] != "TECH_FRICTION") else "DELAY"
    else:
        style = "SKEPTICAL" if (not styles_recent or styles_recent[-1] != "SKEPTICAL") else "CONFUSION"

    # Cue lines: reference scammer request/behavior, without saying “red flag(s)”.
    CUES = {
        "OTP_REQUEST": {
            "CONFUSION": [
                "I’m not comfortable sharing an OTP on chat.",
                "I’m a bit unsure why an OTP is needed here.",
            ],
            "SKEPTICAL": [
                "I don’t usually share OTPs over messages.",
                "An OTP request on chat makes me hesitant.",
            ],
            "TECH_FRICTION": [
                "My phone is acting up and I can’t check messages properly right now.",
            ],
            "DELAY": [
                "I may need a little time before I can look into this.",
            ],
        },
        "THREAT_PRESSURE": {
            "CONFUSION": [
                "That ‘blocked in minutes’ warning is making me unsure.",
                "I’m confused why this needs to happen immediately.",
            ],
            "SKEPTICAL": [
                "I’m hesitant when I see lock/block threats in a message.",
                "This kind of urgency doesn’t feel right to me.",
            ],
            "TECH_FRICTION": [
                "The network is unstable here, so I can’t check things quickly.",
            ],
            "DELAY": [
                "I’ll need a moment before I can respond further.",
            ],
        },
        "IMPERSONATION_CLAIM": {
            "CONFUSION": [
                "I’m not sure how to verify someone’s role through chat.",
            ],
            "SKEPTICAL": [
                "I’m cautious about role claims made in messages.",
            ],
            "TECH_FRICTION": [
                "My connection is patchy right now, so I can’t verify this smoothly.",
            ],
            "DELAY": [
                "I may need some time before I can confirm anything.",
            ],
        },
        "SUSPICIOUS_LINK": {
            "CONFUSION": [
                "I’m unsure about opening a link from a message like this.",
            ],
            "SKEPTICAL": [
                "I’m cautious about clicking links sent under pressure.",
            ],
            "TECH_FRICTION": [
                "Links aren’t loading on my phone right now.",
            ],
            "DELAY": [
                "I can check links a bit later when I have stable access.",
            ],
        },
        "PAYMENT_REQUEST": {
            "CONFUSION": [
                "I’m unsure why a payment or transfer is being mentioned here.",
            ],
            "SKEPTICAL": [
                "I don’t want to do any transfer based on a message.",
            ],
            "TECH_FRICTION": [
                "My phone is lagging, so I can’t check payment screens right now.",
            ],
            "DELAY": [
                "I’ll need time before I can check anything related to payments.",
            ],
        },
        "URGENCY_PRESSURE": {
            "CONFUSION": [
                "I’m a bit unsure with this time pressure.",
            ],
            "SKEPTICAL": [
                "I’m hesitant when I’m asked to act immediately.",
            ],
            "TECH_FRICTION": [
                "My network is slow, so I can’t do quick checks right now.",
            ],
            "DELAY": [
                "I may need a moment before I can respond.",
            ],
        },
        "NONE": {
            "CONFUSION": ["I’m not sure about this message."],
            "SKEPTICAL": ["I’m being cautious with this message."],
            "TECH_FRICTION": ["My connection is unstable right now."],
            "DELAY": ["I may need a little time."],
        },
    }

    pool = CUES.get(chosen, CUES["NONE"]).get(style, CUES["NONE"]["CONFUSION"])
    # deterministic-ish rotation: pick the first cue unless it repeats the last style cue
    prefix = pool[0] if pool else "I’m being cautious with this message."
    return RedFlag(tag=chosen, prefix=prefix, style=style)
