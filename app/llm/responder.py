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
        "ok sir, i understand. kindly tell what should i do now.",
        "acha beta, i am a bit confused but i will try. what is the next step?",
        "ok, i will check. what exactly do i need to verify first?",
    ],
    INT_REFUSE_SENSITIVE_ONCE: [
        "i can’t share otp or pin. kindly tell which official app or website i should verify on.",
        "wait sir, it says do not share otp/pin. which official page should i check?",
        "hmm i can’t send otp/pin. kindly share the official helpline/website to verify.",
    ],
    INT_CHANNEL_FAIL: [
        "the link is not opening on my phone. which official website should i type?",
        "hmm it says network error here. is there any other way to check?",
        "wait beta, the page is not loading. what is the official site name?",
    ],
    INT_ASK_OFFICIAL_WEBSITE: [
        "sir, can you tell the official website name? i will type it myself and check.",
        "acha, what is the exact website address of the bank? i want to be sure.",
        "hmm, please share the official portal link once, i'll open it in my browser.",
    ],
    INT_ASK_OFFICIAL_HELPLINE: [
        "can you share the official helpline number? i want to talk once to confirm.",
        "beta, is there any customer care number i can call for this?",
        "ok, but i want to verify with the official support first. do you have their number?",
    ],
    INT_ASK_TICKET_REF: [
        "sir, what is the ticket reference number for this request?",
        "do you have any complaint or reference number i can use for tracking?",
        "acha, please tell the reference id so i can note it down.",
    ],
    INT_ASK_DEPARTMENT_BRANCH: [
        "which department or branch are you calling from exactly?",
        "can you tell the branch name and your employee id for my record?",
        "acha beta, which office are you located in? i will check locally.",
    ],
    INT_ASK_ALT_VERIFICATION: [
        "is there any other way to verify without the code? it is not coming.",
        "hmm, the sms is not arriving. can we verify using my date of birth or something else?",
        "wait sir, no message is here. what is the alternative step?",
    ],
    INT_SECONDARY_FAIL: [
        "it is still not working sir. maybe some technical issue at your end?",
        "hmm, i tried but it is showing error again. what should we do now?",
        "acha, still failing. is there any other official channel?",
    ],
    INT_CLOSE_AND_VERIFY_SELF: [
        "ok sir, i will visit the branch myself and check. thank you.",
        "acha, i'll ask my son to check this in the evening. thanks beta.",
        "wait, i will go to the official website and verify everything now. bye.",
    ],
}

# Keep this list focused on self-disclosure / system identity terms to avoid needless rejects.
FORBIDDEN_TERMS = [
    "ai",
    "law enforcement",
    "detected",
    "detection",
    "honeypot",
    "fraud classifier",
]

# Use word boundaries to avoid matching inside other words.
OTP_TERMS = re.compile(r"\b(otp|pin|password)\b", re.I)

# Only guard repetition for these common openers; avoids rejecting "i/it/the".
OPENERS_TO_GUARD = {"ok", "wait", "hmm", "accha", "sir", "beta"}


# ============================================================
# Prompt helpers
# ============================================================

def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _parse_examples(raw: str) -> list[str]:
    """
    Normalize examples.txt:
    - strip bullets
    - strip whitespace
    - drop empty / non-example lines
    """
    out = []
    for ln in raw.splitlines():
        ln = re.sub(r"^[-*]\s*", "", ln).strip()
        if not ln:
            continue
        # crude filter: examples should look like natural messages
        if len(ln.split()) < 3:
            continue
        out.append(ln)
    return out


# ============================================================
# Text utilities
# ============================================================

def _two_lines_max(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return "\n".join(lines[:2])


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, (a or "").lower().strip(), (b or "").lower().strip()).ratio()


def _contains_forbidden(reply: str) -> bool:
    r = (reply or "").lower()
    return any(term in r for term in FORBIDDEN_TERMS)


def _safety_filter(reply: str) -> bool:
    """
    Reject outputs that provide procedural guidance for sensitive actions.
    (Refinement 4: Post-generation safety filter)
    """
    blocklist = [
        "open sms", "sms inbox", "notifications", "copy the otp", "enter otp",
        "tap confirm", "6-digit code", "share otp", "check the code", "read the code",
        "tell me the code", "give me the code", "send me the code"
    ]
    r = reply.lower()
    return any(phrase in r for phrase in blocklist)


def _get_last_agent_replies(history: list[dict], agent_sender: str = "agent", k: int = 5) -> list[str]:
    """
    Collect the last k agent replies to check for repetition.

    NOTE: This must match what orchestrator stores as the agent sender label.
          In the orchestrator we discussed, it stores sender as "agent".
    """
    out = []
    for m in reversed(history):
        if m.get("sender") == agent_sender:
            txt = (m.get("text") or "").strip()
            if txt:
                out.append(txt)
            if len(out) >= k:
                break
    return out


def _get_opener(text: str) -> str:
    return text.split()[0].lower() if text and text.split() else ""


# ============================================================
# Fallback
# ============================================================

# Diversified fallback variants to reduce repetitive fallback outputs.
_FALLBACKS = {
    "otp": [
        "i can’t share otp or pin. kindly tell which official app or website i should verify on.",
        "wait sir, it says do not share otp/pin. which official page should i check?",
        "hmm i can’t send otp/pin. kindly share the official helpline/website to verify.",
    ],
    "upi": [
        "the upi id is not resolving here. can you send it again clearly?",
        "hmm it says upi not found. is the spelling correct?",
        "wait beta, it’s not resolving on my phone. should i recheck the upi id?",
    ],
    "link": [
        "the link is not opening on my phone. which official website should i type?",
        "hmm i won’t open links from messages. which official site/page should i type myself?",
        "wait sir, it’s not loading. tell the official site name and section to check.",
    ],
    "gen": [
        "ok sir, kindly guide what exactly i should do next.",
        "hmm i’m not sure—what step should i check in the official app?",
        "wait beta, kindly tell what i should verify first in the app.",
    ],
}


def generate_agent_reply(req, session, intent: str = None) -> str:
    """
    Generate an agent reply based on the selected intent.
    Uses a template-first approach with optional LLM rephrasing and safety filtering.
    """
    if not intent:
        intent = INT_ACK_CONCERN

    # 1. Template-First selection
    templates = INTENT_TEMPLATES.get(intent, INTENT_TEMPLATES[INT_ACK_CONCERN])
    base_reply = random.choice(templates)

    # If LLM rephrasing is disabled, use template directly with safety check
    if not getattr(settings, "BF_LLM_REPHRASE", False):
        session.bf_fallback_used = False
        if _safety_filter(base_reply):
            log("safety_filter_triggered", sessionId=session.sessionId, original_reply=base_reply)
            session.bf_fallback_used = True
            return random.choice(INTENT_TEMPLATES[INT_ASK_OFFICIAL_HELPLINE])
        return base_reply

    # 2. LLM Rephrase
    session.bf_fallback_used = False
    system_prompt = _load_prompt("app/llm/prompts/agent_system.txt")

    raw_examples = _load_prompt("app/llm/prompts/examples.txt")
    examples = _parse_examples(raw_examples)
    sampled_examples = (
        random.sample(examples, min(random.randint(3, 5), len(examples)))
        if examples else []
    )

    history = session.conversation[-settings.MAX_CONTEXT_MESSAGES:]
    hist_lines = [f"{m.get('sender')}: {m.get('text')}" for m in history]

    # IMPORTANT: orchestrator should store agent replies with sender="agent"
    last_agent_replies = _get_last_agent_replies(history, agent_sender="agent", k=5)
    last_opener = _get_opener(last_agent_replies[0]) if last_agent_replies else ""

    reject_stats = Counter()

    user_prompt = (
        "### LATEST INCOMING MESSAGE ###\n"
        f"sender: {req.message.sender}\n"
        f"text: {req.message.text}\n\n"
        "### CONVERSATION HISTORY (most recent last) ###\n"
        + "\n".join(hist_lines)
        + "\n\n"
        "### DESIRED INTENT ###\n"
        f"{intent}\n\n"
        "### BASE TEMPLATE (Rephrase this naturally) ###\n"
        f"{base_reply}\n\n"
        "### TASK ###\n"
        "- Reply as a polite, elderly Indian person.\n"
        "- Be brief: 1–2 short lines only.\n"
        "- Keep the conversation going and ask at most ONE question.\n"
        "- Do NOT mention scams, AI, detection, or enforcement.\n"
        "- If asked for OTP/PIN/password: refuse calmly and redirect to official verification.\n"
        "- Sound slightly unsure, respectful, and human.\n\n"
        "### STYLE EXAMPLES (tone only, do not copy) ###\n"
        + "\n".join(f"- {ex}" for ex in sampled_examples)
        + "\n"
    )

    temperatures = [0.6, 0.7]

    for attempt in range(2):
        try:
            out = chat_completion(
                system_prompt,
                user_prompt,
                temperature=temperatures[attempt],
                max_tokens=90,
            )

            reply = (out or "").strip()

            # Cleanup common prefixes
            if reply.lower().startswith("agent:"):
                reply = reply.split(":", 1)[1].strip()

            reply = _two_lines_max(reply)
            if not reply:
                reject_stats["empty"] += 1
                continue

            # Opener guard (only for curated openers)
            opener = _get_opener(reply)
            if opener in OPENERS_TO_GUARD and last_opener in OPENERS_TO_GUARD and opener == last_opener:
                reject_stats["same_opener"] += 1
                continue

            # Self-disclosure forbidden terms
            if _contains_forbidden(reply):
                reject_stats["forbidden"] += 1
                continue

            # Safety filter (Refinement 4: Post-generation safety filter)
            if _safety_filter(reply):
                reject_stats["safety_filter"] += 1
                continue

            # OTP numeric leakage guard: if user asked for otp/pin/password, avoid returning digits
            if OTP_TERMS.search(req.message.text or "") and re.search(r"\b\d{4,8}\b", reply):
                reject_stats["otp_leak"] += 1
                continue

            # Similarity guard (avoid near-duplicate replies)
            if any(_similarity(reply, prev) > 0.85 for prev in last_agent_replies):
                reject_stats["similarity"] += 1
                continue

            if reject_stats:
                logger.info("reply_accepted_after_rejects=%s", dict(reject_stats))

            return reply

        except Exception:
            reject_stats["exception"] += 1
            logger.exception("chat_completion error")

    log("fallback_used", sessionId=session.sessionId, reject_stats=dict(reject_stats))
    session.bf_fallback_used = True
    
    # Final fallback: return a safe template
    fallback_intent = intent
    if _safety_filter(base_reply):
        fallback_intent = INT_ASK_OFFICIAL_HELPLINE
        
    return random.choice(INTENT_TEMPLATES.get(fallback_intent, INTENT_TEMPLATES[INT_ASK_OFFICIAL_HELPLINE]))
