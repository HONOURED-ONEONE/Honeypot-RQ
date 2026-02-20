# app/llm/responder.py

"""
Responder Invariants (Phase-3)

- The responder NEVER decides what to ask; it only formats the selected intent.
- All content is intent-driven and registry-compliant.
- No procedural guidance (no steps, no navigation).
- No fabricated identifiers.
- At most ONE question per reply.
- No early closing unless finalize is true (enforced upstream).
"""

import random
import re
import logging
from typing import List, Dict, Optional
from pathlib import Path

from app.settings import settings
from app.llm.vllm_client import chat_completion
from app.core.broken_flow_constants import *
from app.observability.logging import log

logger = logging.getLogger("honeypot_agent")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Global caps & intent-scoped allowances
# ---------------------------------------------------------------------------

MAX_REPLY_SENTENCES = 3

INTENTS_ALLOW_3_SENTENCES = {
    INT_REFUSE_SENSITIVE_ONCE,
    INT_ASK_OFFICIAL_HELPLINE,
    INT_ASK_OFFICIAL_WEBSITE,
    INT_ASK_ALT_VERIFICATION,
    INT_SECONDARY_FAIL,
}

SINGLE_QUESTION_WRAPPER = (
    "You must respond with exactly one concise question that progresses the goal.\n"
    "Do not include procedures, disclaimers, or multiple questions.\n"
)

def _load_file_text(rel_path: str) -> str:
    try:
        base = Path(__file__).parent / "prompts"
        return (base / rel_path).read_text(encoding="utf-8")
    except Exception:
        return ""

# ---------------------------------------------------------------------------
# Templates (intent-driven only; no tactics, no procedures). Updated with subtle red-flag references.
# Each template is a list of candidate strings.
# ---------------------------------------------------------------------------

INTENT_TEMPLATES: Dict[str, List[str]] = {
    INT_ACK_CONCERN: [
        "Okay, I’m a bit concerned about this.",
        "I understand this sounds important.",
        "Alright, I want to be careful here.",
    ],

    INT_REFUSE_SENSITIVE_ONCE: [
        # Subtle red‑flag reference: OTP/PIN
        "Since this involves an OTP request, I can’t share OTP or PIN here. Which official channel should I use to verify this?",
        "I’m concerned about the OTP being requested on chat. What is the official way to check this myself?",
        "I want to verify this safely and won’t share OTP or PIN here. Which official contact should I use?",
    ],

    INT_CHANNEL_FAIL: [
        "The page isn’t opening on my phone right now. Which official page should I try instead?",
        "I’m seeing an error while trying to check this. What official place should I look at?",
        "The link doesn’t seem to load here. Which official site should I open directly?",
    ],

    INT_ASK_OFFICIAL_WEBSITE: [
        # Subtle red‑flag reference: suspicious link concerns
        "Before opening any link, I want to verify properly. What is the official website or domain I should check?",
        "I’d rather confirm this myself to avoid a wrong link. Which official website should I open?",
        "I’m trying to check this independently instead of using the link sent. What is the correct official site?",
    ],

    INT_ASK_OFFICIAL_HELPLINE: [
        # Subtle red‑flag reference: urgency → prefer official call
        "You mentioned this is urgent; I’d like to confirm directly. What is the official helpline number I should call?",
        "Given the urgency, I prefer to verify by phone. Which official helpline should I contact?",
        "Since this seems time‑sensitive, I’d rather call. What is the official support number?",
    ],

    INT_ASK_TICKET_REF: [
        "I want to keep a record of this. "
        "Is there a reference or complaint number for this case?",
        "I’d like to note this down properly. "
        "What is the reference number for this request?",
        "I want to track this later. "
        "Is there a reference ID associated with this?",
    ],

    INT_ASK_DEPARTMENT_BRANCH: [
        "I want to confirm this locally. "
        "Which department or branch is handling this?",
        "I’d like to verify with the right team. "
        "Which branch or department is responsible?",
        "I want to double-check this. "
        "Which office or department is managing it?",
    ],

    INT_ASK_ALT_VERIFICATION: [
        # Subtle red‑flag reference: fees/charges + payment link concerns
        "I’m not comfortable with any fees or charges link on chat. Is there another official way to verify this?",
        "I can’t get SMS on my phone currently and I prefer no payment links here. What alternate official method can I use?",
        "Messages aren’t coming through, and I don’t want to click a payment link. Is there a different official verification option?",
    ],

    INT_SECONDARY_FAIL: [
        "I’m still unable to complete this on my side. Is there another official option to check this?",
        "This doesn’t seem to be working for me yet. What other official channel can I try?",
        "I’m facing issues again while checking this. Is there an alternate official route?",
    ],

    INT_CLOSE_AND_VERIFY_SELF: [
        "Alright, I’ll verify this directly through official channels. "
        "Thank you for informing me.",
        "Okay, I’ll check this myself using the official contact. "
        "Thanks for letting me know.",
        "I understand, I’ll confirm this independently through official means. "
        "Thank you.",
    ],
}

# ---------------------------------------------------------------------------
# Safety & validation helpers
# ---------------------------------------------------------------------------

FORBIDDEN_TERMS = [
    "open sms", "sms inbox", "notifications", "copy otp",
    "enter otp", "tap confirm", "6-digit code", "share otp",
]

IDENTIFIER_PATTERNS = {
    "phone": re.compile(r"\+?\d{10,}", re.I),
    # Accept http(s)://... OR www....
    "url": re.compile(r"(?:https?://\S+|www\.\S+)", re.I),
    "bank": re.compile(r"\b\d{12,16}\b"),
    "upi": re.compile(r"\b[\w.\-]+@[\w\-]+\b", re.I),
}

#
# Procedural-language guard: block step-by-step/instructional phrasing
#
PROCEDURAL_PATTERNS = [
    r"\b(?:step|steps|follow these|do the following)\b",
    r"(?m)^\s*\d+\.",             # numbered list lines
    r"(?m)^\s*[-*•]\s+",          # bullets
    r"\b(?:click|open|go to|log ?in|enter|submit|navigate|install|download)\b",
]

def _looks_procedural(s: str) -> bool:
    t = (s or "").lower()
    return any(re.search(p, t, re.I) for p in PROCEDURAL_PATTERNS)

def _contains_forbidden(text: str) -> bool:
    t = (text or "").lower()
    return any(term in t for term in FORBIDDEN_TERMS)

def _count_questions(text: str) -> int:
    return text.count("?")

def _split_sentences(text: str) -> List[str]:
    parts = [p.strip() for p in re.split(r"(?<=[.!?])\s+", text) if p.strip()]
    return parts

def _limit_sentences(text: str, max_sentences: int) -> str:
    parts = _split_sentences(text)
    return " ".join(parts[:max_sentences])

def _registry_values(session) -> List[str]:
    intel = session.extractedIntelligence
    values: List[str] = []
    values.extend(intel.phoneNumbers or [])
    values.extend(intel.phishingLinks or [])
    values.extend(intel.bankAccounts or [])
    values.extend(intel.upiIds or [])
    return values

def _introduces_new_identifier(reply: str, session) -> bool:
    known = set(_registry_values(session))
    for pat in IDENTIFIER_PATTERNS.values():
        for m in pat.findall(reply or ""):
            if m not in known:
                return True
    return False

def _safe_fallback(intent: str) -> str:
    return random.choice(INTENT_TEMPLATES.get(intent, INTENT_TEMPLATES[INT_ACK_CONCERN]))

# ---------------------------------------------------------------------------
# Main responder
# ---------------------------------------------------------------------------

def generate_agent_reply(req, session, intent: str, instruction: Optional[str] = None) -> str:
    """
    Intent-driven responder.
    Applies framing only; no logic, no extraction, no state changes.
    `instruction` is a short "what to ask" phrase provided by the controller (or dynamic intent map).
    """

    # Select base template
    base = random.choice(INTENT_TEMPLATES.get(intent, INTENT_TEMPLATES[INT_ACK_CONCERN]))

    # Enforce sentence cap by intent
    max_sentences = MAX_REPLY_SENTENCES if intent in INTENTS_ALLOW_3_SENTENCES else 2
    reply = _limit_sentences(base, max_sentences)

    # Enforce one-question rule
    if _count_questions(reply) > 1:
        reply = _safe_fallback(intent)

    # Always run minimal safety on the template reply
    if _contains_forbidden(reply) or _introduces_new_identifier(reply, session):
        reply = _safe_fallback(intent)

    # If rephrase is disabled, return the safe template
    if not getattr(settings, "BF_LLM_REPHRASE", False):
        return reply

    # Optional LLM rephrase (strictly bounded)
    try:
        # Stricter system rules (non-negotiables) to prevent procedure/coaching
        agent_rules = (
            "You generate short, cautious replies for verification.\n"
            "NON-NEGOTIABLES:\n"
            "- Follow the given instruction strictly (no new goals).\n"
            "- NO procedures, steps, or instructions.\n"
            "- At most ONE question.\n"
            "- Do NOT invent or mention any identifiers.\n"
            "- Keep it concise (max 2–3 sentences based on intent).\n"
            "- Do NOT imply resolution or closure unless told.\n"
        )
        
        user_prompt = (instruction or "").strip() or reply
        
        # If instruction is present and rephrase is on, enforce single-question wrapper
        if instruction and instruction.strip():
             user_prompt = f"{instruction.strip()}\n\n{SINGLE_QUESTION_WRAPPER}"

        out = chat_completion(agent_rules, user_prompt, temperature=0.2, max_tokens=70)
        out = (out or "").strip()
        # Strip list markers to reduce accidental procedural formats before limit
        out = re.sub(r"(?m)^\s*(?:\d+\.|[-*•])\s+", "", out)
        out = _limit_sentences(out, max_sentences)
        if (not out
            or _contains_forbidden(out)
            or _count_questions(out) > 1
            or _introduces_new_identifier(out, session)
            or _looks_procedural(out)
        ):
            raise ValueError("unsafe_rephrase")
        return out
    except Exception:
        log(event="responder_fallback", intent=intent)
        # On failure, return the safe template (already screened above)
        return reply
