import random
import re
import logging
from difflib import SequenceMatcher
from collections import Counter

from app.settings import settings
from app.llm.vllm_client import chat_completion
from app.core.broken_flow_constants import *
from app.observability.logging import log

logger = logging.getLogger("honeypot_agent")
logger.setLevel(logging.INFO)

# Intent Templates (Template-First Approach)
INTENT_TEMPLATES = {
    INT_ACK_CONCERN: [
        "ok sir, this sounds serious — kindly tell what I should try first.",
        "acha beta, I am worried, please guide me step by step what to check.",
        "hmm sir, I don’t want any mistake; what is the first thing I should verify?"
    ],
    INT_REFUSE_SENSITIVE_ONCE: [
        "I can’t share OTP or PIN, sorry — kindly tell which official app/website I should verify on.",
        "wait sir, it says ‘do not share’ here, so please give the official helpline or portal to confirm.",
        "hmm I cannot send OTP/PIN, kindly advise the official number or site where I can check myself."
    ],
    INT_CHANNEL_FAIL: [
        "the page/link is not opening on my phone, it just keeps loading — which official page should I type?",
        "hmm my app is stuck on a blank screen, is there another official place I should check?",
        "wait sir, the site isn’t loading due to network here — what is the exact official section to try?"
    ],
    INT_ASK_OFFICIAL_WEBSITE: [
        "sir, what is the exact official website name or page section I should open and check?",
        "acha, can you tell the bank’s official portal address and which page to open there?",
        "hmm please tell the exact site name and the page (e.g., 'security' or 'alerts') so I’ll type it myself."
    ],
    INT_ASK_OFFICIAL_HELPLINE: [
        "can you share the official helpline number I should call to confirm this, sir?",
        "beta, is there a customer-care number I can ring so I can be sure this is official?",
        "ok sir, please give the official support number or department to call for verification."
    ],
    INT_ASK_TICKET_REF: [
        "sir, is there any complaint or reference number I should note down for this request?",
        "acha, please tell the reference/ticket id shown to you so I can check it with the bank.",
        "hmm, do you have a reference number for this case that I can keep for my records?"
    ],
    INT_ASK_DEPARTMENT_BRANCH: [
        "which department or branch are you calling from exactly, sir? I will verify locally.",
        "acha beta, which office or branch is handling this so I can contact them directly?",
        "hmm, can you tell the department name and branch city so I can confirm with the right team?"
    ],
    INT_ASK_ALT_VERIFICATION: [
        "the SMS is not coming here — is there any other official way customers are verifying today?",
        "hmm I can’t receive messages right now, what alternate safe method do people use to verify?",
        "wait sir, if OTP isn’t arriving, what official fallback are customers asked to use?"
    ],
    INT_SECONDARY_FAIL: [
        "it is still showing an error on my phone, maybe the page is down — is there another official option?",
        "hmm tried again but it failed, do others use a different method for urgent verification?",
        "acha, still not working here; can you suggest any other official channel or step?"
    ],
    INT_CLOSE_AND_VERIFY_SELF: [
        "ok sir, I will verify directly on the official website/branch and get back — thank you.",
        "acha, I’ll ask my son to check this on his phone and confirm from the official portal.",
        "wait, I will contact the official helpline and verify this personally now — thanks for guiding."
    ],
}

FORBIDDEN_TERMS = ["ai", "law enforcement", "detected", "detection", "honeypot", "fraud classifier"]
OTP_TERMS = re.compile(r"\b(otp|pin|password)\b", re.I)
OPENERS_TO_GUARD = {"ok", "wait", "hmm", "accha", "sir", "beta"}

def _two_lines_max(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return "\n".join(lines[:2])

def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, (a or "").lower().strip(), (b or "").lower().strip()).ratio()

def _contains_forbidden(reply: str) -> bool:
    r = (reply or "").lower()
    return any(term in r for term in FORBIDDEN_TERMS)

def _safety_filter(reply: str) -> bool:
    blocklist = [
        "open sms", "sms inbox", "notifications", "copy otp",
        "enter otp", "tap confirm", "6-digit code", "share otp"
    ]
    r = reply.lower()
    return any(p in r for p in blocklist)

def generate_agent_reply(req, session, intent: str = None) -> str:
    """
    Broken-flow–aware responder with IOC suppression and auto-closure.
    """

    # ============================================================
    # Lazy broken-flow state (backward compatible)
    # ============================================================
    if not hasattr(session, "bf_satisfied_intents"):
        session.bf_satisfied_intents = set()

    if not hasattr(session, "bf_ioc_counts"):
        session.bf_ioc_counts = {
            "phone": 0,
            "url": 0,
            "bank": 0,
            "reference": 0,
            "branch": 0,
        }

    if not hasattr(session, "bf_closed"):
        session.bf_closed = False

    last_text = (req.message.text or "").lower()

    # ============================================================
    # IOC extraction from scammer message
    # ============================================================
    if re.search(r"\+?\d{10,}", last_text):
        session.bf_ioc_counts["phone"] += 1
        session.bf_satisfied_intents.add(INT_ASK_OFFICIAL_HELPLINE)

    if re.search(r"https?://", last_text):
        session.bf_ioc_counts["url"] += 1
        session.bf_satisfied_intents.add(INT_ASK_OFFICIAL_WEBSITE)

    if re.search(r"\b\d{12,16}\b", last_text):
        session.bf_ioc_counts["bank"] += 1

    if re.search(r"\bref[-\s]?\w+", last_text):
        session.bf_ioc_counts["reference"] += 1
        session.bf_satisfied_intents.add(INT_ASK_TICKET_REF)

    if "branch" in last_text or "department" in last_text:
        session.bf_ioc_counts["branch"] += 1
        session.bf_satisfied_intents.add(INT_ASK_DEPARTMENT_BRANCH)

    # ============================================================
    # OTP is dead once any alternative channel exists
    # ============================================================
    if any(session.bf_ioc_counts[k] > 0 for k in ("phone", "url", "reference", "branch")):
        session.bf_satisfied_intents.update({
            INT_REFUSE_SENSITIVE_ONCE,
            INT_ASK_ALT_VERIFICATION,
        })

    # ============================================================
    # Auto-close once 2 distinct IOC categories are collected
    # ============================================================
    if sum(1 for v in session.bf_ioc_counts.values() if v > 0) >= 2:
        session.bf_closed = True
        return random.choice(INTENT_TEMPLATES[INT_CLOSE_AND_VERIFY_SELF])

    # ============================================================
    # Intent suppression (no loops)
    # ============================================================
    if intent in session.bf_satisfied_intents:
        intent = INT_ACK_CONCERN

    if not intent:
        intent = INT_ACK_CONCERN

    base_reply = random.choice(INTENT_TEMPLATES.get(intent, INTENT_TEMPLATES[INT_ACK_CONCERN]))

    # ============================================================
    # Template-only mode
    # ============================================================
    if not getattr(settings, "BF_LLM_REPHRASE", False):
        if _safety_filter(base_reply):
            return random.choice(INTENT_TEMPLATES[INT_ASK_OFFICIAL_HELPLINE])
        return base_reply

    # ============================================================
    # LLM rephrase path (unchanged safety guards)
    # ============================================================
    try:
        out = chat_completion(
            system_prompt="You are a cautious, elderly Indian customer.",
            user_prompt=base_reply,
            temperature=0.7,
            max_tokens=80,
        )
        reply = _two_lines_max((out or "").strip())
        if not reply or _contains_forbidden(reply) or _safety_filter(reply):
            raise ValueError("unsafe")
        return reply
    except Exception:
        session.bf_fallback_used = True
        return random.choice(INTENT_TEMPLATES[INT_ASK_OFFICIAL_HELPLINE])