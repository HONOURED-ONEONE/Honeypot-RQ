"""
Investigative Ladder (Scoring-Optimized + Adaptive)
---------------------------------------------------
Purpose:
1) Choose a varied, relevant investigative target category (IOC key) in a stable order
   per scam type to maximize Conversation Quality sub-scores (relevant questions, elicitation). [1](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)
2) Adaptive step: avoid immediately asking for a category that was newly extracted
   from the latest scammer message (timing/state sync redundancy fix). [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.1771597261347.log)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, List, Optional


@dataclass(frozen=True)
class LadderPlan:
    # Ordered IOC categories to pursue
    order: List[str]


# Ladder operates on IOC category keys used by scoring and your Intelligence model:
# phoneNumbers, phishingLinks, upiIds, bankAccounts, emailAddresses, caseIds,
# policyNumbers, orderNumbers. [1](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)[2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.1771597261347.log)
LADDER_BY_SCAMTYPE: Dict[str, LadderPlan] = {
    "BANK_IMPERSONATION": LadderPlan(
        order=["phoneNumbers", "caseIds", "phishingLinks", "department", "bankAccounts"]
    ),
    "UPI_FRAUD": LadderPlan(
        order=["upiIds", "phoneNumbers", "caseIds", "phishingLinks"]
    ),
    "PHISHING": LadderPlan(
        order=["phishingLinks", "emailAddresses", "orderNumbers", "phoneNumbers", "caseIds"]
    ),
    "JOB_SCAM": LadderPlan(
        order=["phoneNumbers", "upiIds", "policyNumbers", "phishingLinks", "emailAddresses"]
    ),
}


def normalize_scam_type(raw: str) -> str:
    """
    Normalize to the keys above.
    Your detector emits: UPI_FRAUD, PHISHING, BANK_IMPERSONATION, JOB_SCAM, UNKNOWN. [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.1771597261347.log)
    """
    t = (raw or "UNKNOWN").upper().strip()
    if t in ("BANK_IMPERSONATION", "UPI_FRAUD", "PHISHING", "JOB_SCAM"):
        return t
    if "BANK" in t:
        return "BANK_IMPERSONATION"
    return "UNKNOWN"


def _has_vals(intel_dict: Dict[str, Any], key: str) -> bool:
    try:
        vals = intel_dict.get(key) or []
        return isinstance(vals, list) and len(vals) > 0
    except Exception:
        return False


def choose_ladder_target(
    intel_dict: Dict[str, Any],
    scam_type: str,
    asked_last_turn: Dict[str, int],
    turn_index: int,
    cooldown_turns: int = 4,
    avoid_keys: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Choose the next IOC category (key) to pursue based on ladder order.
    Adaptive step: avoid selecting any key present in avoid_keys.
    Returns None if ladder cannot find a productive target (caller should fallback).
    """
    st = normalize_scam_type(scam_type)
    plan = LADDER_BY_SCAMTYPE.get(st)
    if not plan:
        return None

    avoid = set((avoid_keys or []))

    def blocked_by_cooldown(k: str) -> bool:
        try:
            last = int((asked_last_turn or {}).get(k, -10**9))
            return (int(turn_index) - last) < int(cooldown_turns)
        except Exception:
            return False

    # Prefer missing + not on cooldown + not avoided (adaptive)
    for k in plan.order:
        if k == "department":
            if "department" in avoid:
                continue
            if not blocked_by_cooldown("department"):
                return "department"
            continue
        if k in avoid:
            continue
        if _has_vals(intel_dict, k):
            continue
        if blocked_by_cooldown(k):
            continue
        return k

    # Relax: allow cooldown override if everything is missing but blocked,
    # still respecting avoid_keys to prevent ask-after-received.
    for k in plan.order:
        if k == "department":
            if "department" in avoid:
                continue
            return "department"
        if k in avoid:
            continue
        if not _has_vals(intel_dict, k):
            return k

    return None
