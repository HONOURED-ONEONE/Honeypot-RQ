import random
import re
import logging
from difflib import SequenceMatcher

from app.settings import settings
from app.llm.vllm_client import chat_completion
from app.core.broken_flow_constants import *
from app.observability.logging import log

logger = logging.getLogger("honeypot_agent")
logger.setLevel(logging.INFO)

# ============================================================
# Intent Templates (Template-First, Controller-Driven)
# ============================================================

INTENT_TEMPLATES = {
    INT_ACK_CONCERN: [
        "ok sir, this sounds serious — kindly tell what I should try first.",
        "acha beta, I am worried, please guide me step by step what to check.",
        "hmm sir, I don’t want any mistake; what is the first thing I should verify?"
    ],
    INT_REFUSE_SENSITIVE_ONCE: [
        "I can’t share OTP or PIN, sorry — kindly tell which official app or website I should verify on.",
        "wait sir, it says ‘do not share’ here, so please give the official helpline or portal to confirm.",
        "hmm I cannot send OTP or PIN, kindly advise the official number or site where I can check myself."
    ],
    INT_CHANNEL_FAIL: [
        "the page is not opening on my phone, it just keeps loading — which official page should I type?",
        "hmm my app is stuck on a blank screen, is there another official place I should check?",
        "wait sir, the site isn’t loading due to network here — what exact official page should I open?"
    ],
    INT_ASK_OFFICIAL_WEBSITE: [
        "sir, what is the exact official website name or page section I should open and check?",
        "acha, can you tell the bank’s official portal address and which page to open there?",
        "hmm please tell the exact site name and the page so I’ll type it myself."
    ],
    INT_ASK_OFFICIAL_HELPLINE: [
        "can you share the official helpline number I should call to confirm this, sir?",
        "beta, is there a customer-care number I can ring so I can be sure this is official?",
        "ok sir, please give the official support number or department to call for verification."
    ],
    INT_ASK_TICKET_REF: [
        "sir, is there any complaint or reference number I should note down for this request?",
        "acha, please tell the reference or ticket id shown to you so I can check it with the bank.",
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
        "ok sir, I will verify directly on the official website or branch and get back — thank you.",
        "acha, I’ll ask my son to check this on his phone and confirm from the official portal.",
        "wait, I will contact the official helpline and verify this personally now — thanks for guiding."
    ],
}

# ============================================================
# Safety / Guard Rails
# ============================================================

FORBIDDEN_TERMS = [
    "ai", "law enforcement", "detected",
    "detection", "honeypot", "fraud classifier"
]

OTP_TERMS = re.compile(r"\b(otp|pin|password|cvv|code)\b", re.I)

def _two_lines_max(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return "\n".join(lines[:2])

def _contains_forbidden(reply: str) -> bool:
    r = (reply or "").lower()
    return any(term in r for term in FORBIDDEN_TERMS)

def _safety_filter(reply: str) -> bool:
    """
    Hard stop on any operational or instructional language
    that could help credential compromise.
    """
    blocklist = [
        "open sms",
        "sms inbox",
        "notifications",
        "copy otp",
        "enter otp",
        "tap confirm",
        "6-digit code",
        "share otp",
    ]
    r = reply.lower()
    return any(p in r for p in blocklist)

# ============================================================
# Core Responder (Intent-Driven Only)
# ============================================================

def generate_agent_reply(req, session, intent: str = None) -> str:
    """
    Responder is strictly intent-driven.
    - No state transitions
    - No IOC inference
    - No auto-closure
    Controller owns all flow decisions.
    """

    if not intent:
        intent = INT_ACK_CONCERN

    templates = INTENT_TEMPLATES.get(intent)
    if not templates:
        templates = INTENT_TEMPLATES[INT_ACK_CONCERN]

    base_reply = random.choice(templates)

    # ------------------------------------------------------------
    # Template-only mode (default, safest)
    # ------------------------------------------------------------
    if not getattr(settings, "BF_LLM_REPHRASE", False):
        if _safety_filter(base_reply):
            return random.choice(INTENT_TEMPLATES[INT_ASK_OFFICIAL_HELPLINE])
        return base_reply

    # ------------------------------------------------------------
    # Optional LLM rephrasing (guarded)
    # ------------------------------------------------------------
    try:
        out = chat_completion(
            system_prompt="You are a cautious, elderly Indian customer.",
            user_prompt=base_reply,
            temperature=0.7,
            max_tokens=80,
        )

        reply = _two_lines_max((out or "").strip())

        if (
            not reply
            or _contains_forbidden(reply)
            or _safety_filter(reply)
        ):
            raise ValueError("unsafe rephrase")

        return reply

    except Exception:
        log.warning("LLM rephrase failed, falling back to safe template")
        return random.choice(INTENT_TEMPLATES[INT_ASK_OFFICIAL_HELPLINE])
