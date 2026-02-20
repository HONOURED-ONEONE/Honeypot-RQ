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
        # Keep ACK minimal; avoid turning it into vague meta questions.
        "Okay, I want to be careful about this.",
        "I understand—this sounds concerning.",
        "Alright, I’m being cautious here.",
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
        "I want to keep a record—what is the reference or complaint number for this case?",
        "I’d like to note it down—what reference number is associated with this request?",
        "To track this properly, what is the case or ticket ID for this issue?",
    ],

    INT_ASK_DEPARTMENT_BRANCH: [
        "Which department or branch is handling this case?",
        "Which office or team is responsible for this request?",
        "Which branch or department is managing this verification?",
    ],

    INT_ASK_ALT_VERIFICATION: [
        "Since you’re pressuring for a quick action, what alternative official method can I use to verify this?",
        "I’m not comfortable verifying through chat—what other official verification method is available?",
        "Instead of sharing anything here, what alternate official way can I confirm this request?",
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
# Intent → minimal fallback goal (used ONLY if instruction is missing)
# ---------------------------------------------------------------------------
INTENT_GOALS: Dict[str, str] = {
    INT_ACK_CONCERN: "Briefly acknowledge the concern; if you ask, make it one short question.",
    INT_REFUSE_SENSITIVE_ONCE: "Refuse to share OTP, PIN, or passwords and ask which official channel to verify.",
    INT_CHANNEL_FAIL: "Say the page is not loading and ask for an official source to check.",
    INT_ASK_OFFICIAL_WEBSITE: "Ask for the official website or domain in one short question.",
    INT_ASK_OFFICIAL_HELPLINE: "Ask for the official helpline number in one short question.",
    INT_ASK_TICKET_REF: "Ask for a reference or complaint number in one short question.",
    INT_ASK_DEPARTMENT_BRANCH: "Ask which department or branch is handling the case in one short question.",
    INT_ASK_ALT_VERIFICATION: "Ask for an alternative official verification method in one short question.",
    INT_SECONDARY_FAIL: "Say it still isn't working and ask for another official option.",
    INT_CLOSE_AND_VERIFY_SELF: "Politely close and state you will verify through official channels yourself. Do not ask a question.",
}

# ---------------------------------------------------------------------------
# Safety & validation helpers
# ---------------------------------------------------------------------------

FORBIDDEN_TERMS = [
    "open sms", "sms inbox", "notifications", "copy otp",
    "enter otp", "tap confirm", "6-digit code", "share otp",
]

# Reject these phrases because they produce low-signal, evaluator-unfriendly "meta" questions.
META_CONFIRM_PHRASES = [
    "will you please confirm",
    "can you confirm",
    "please confirm",
    "confirm that i should",
    "is there a specific aspect",
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

# ---------------------------------------------------------------------------
# Conversation-quality wording constraints
# ---------------------------------------------------------------------------
# Block low-value "meta" questions that don't extract intelligence and hurt
# "Relevant Questions" scoring. [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)
VAGUE_QUESTION_PATTERNS = [
    r"\bis there (something|anything) else\b",
    r"\bcan i assist\b",
    r"\bhow can i help\b",
    r"\bis there a specific aspect\b",
    r"\bwould you like to address first\b",
    r"\bwill you please confirm\b",  # meta-confirmation prompt
    r"\bcan you confirm\b",
]

# Per-intent "anchor terms" to make investigative questions clearly relevant.
# These ensure the question explicitly targets the intended artifact category,
# improving "Relevant Questions" scoring. [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)
INTENT_REQUIRED_TERMS: Dict[str, List[str]] = {
    INT_ASK_OFFICIAL_HELPLINE: ["helpline", "number", "call"],
    INT_ASK_OFFICIAL_WEBSITE: ["website", "domain", "site"],
    INT_ASK_TICKET_REF: ["reference", "ref", "ticket", "case", "complaint", "id"],
    INT_ASK_DEPARTMENT_BRANCH: ["department", "branch", "office", "team"],
    INT_ASK_ALT_VERIFICATION: ["alternative", "another", "official", "method", "verify"],
    INT_REFUSE_SENSITIVE_ONCE: ["official", "verify", "channel"],
    INT_CHANNEL_FAIL: ["official", "website", "domain", "site"],
    INT_SECONDARY_FAIL: ["official", "another", "option", "channel"],
}

def _looks_procedural(s: str) -> bool:
    t = (s or "").lower()
    return any(re.search(p, t, re.I) for p in PROCEDURAL_PATTERNS)

def _looks_vague_or_meta_question(s: str) -> bool:
    t = (s or "").lower()
    if "?" not in t:
        return False
    return any(re.search(p, t, re.I) for p in VAGUE_QUESTION_PATTERNS)

def _meets_intent_anchor(intent: str, s: str) -> bool:
    """
    Enforce that the investigative question contains at least one anchor term for its intent.
    This reduces accidental low-signal questions and improves evaluator scoring for relevance. [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)
    """
    t = (s or "").lower()
    terms = INTENT_REQUIRED_TERMS.get(intent) or []
    if not terms:
        return True
    return any(term in t for term in terms)

def _contains_forbidden(text: str) -> bool:
    t = (text or "").lower()
    return any(term in t for term in FORBIDDEN_TERMS)

def _contains_meta_confirm(text: str) -> bool:
    t = (text or "").lower()
    return any(p in t for p in META_CONFIRM_PHRASES)

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

def generate_agent_reply(
    req,
    session,
    intent: str,
    instruction: Optional[str] = None,
    red_flag_prefix: Optional[str] = None,
) -> str:
    """
    Intent-driven responder.
    Applies framing only; no logic, no extraction, no state changes.
    `instruction` is a short "what to ask" phrase provided by the controller (or dynamic intent map).
    """

    # Select base template (avoid repeating the last agent message when possible)
    choices = list(INTENT_TEMPLATES.get(intent, INTENT_TEMPLATES[INT_ACK_CONCERN]))
    last_agent = ""
    try:
        convo = getattr(session, "conversation", []) or []
        for m in reversed(convo):
            if (m.get("sender") or "").lower() == "agent":
                last_agent = (m.get("text") or "")
                break
    except Exception:
        last_agent = ""
    if last_agent and len(choices) > 1:
        # Try a few draws to avoid exact repetition
        base = random.choice(choices)
        for _ in range(3):
            if (base or "").strip() != last_agent.strip():
                break
            base = random.choice(choices)
    else:
        base = random.choice(choices)

    # Enforce sentence cap by intent
    max_sentences = MAX_REPLY_SENTENCES if intent in INTENTS_ALLOW_3_SENTENCES else 2
    reply = _limit_sentences(base, max_sentences)

    # --- Core upgrade: Red-flag -> investigative question ---
    # For investigative intents (most intents except terminal close), prepend a short
    # red-flag statement anchored to the latest scammer message.
    # Keep prefix as a statement (no '?') so we don't violate the one-question rule.
    try:
        pfx = (red_flag_prefix or "").strip()
        if pfx and intent != INT_CLOSE_AND_VERIFY_SELF:
            # Avoid double-prefixing if templates already include the same phrase
            if pfx.lower() not in reply.lower():
                reply = f"{pfx} {reply}".strip()
    except Exception:
        pass

    # Enforce one-question rule
    if _count_questions(reply) > 1:
        reply = _safe_fallback(intent)

    # Wording constraint 1: block vague/meta questions (not investigative)
    if _looks_vague_or_meta_question(reply):
        reply = _safe_fallback(intent)

    # Wording constraint 2: ensure question is anchored to the intent category
    if intent != INT_CLOSE_AND_VERIFY_SELF and "?" in (reply or "") and not _meets_intent_anchor(intent, reply):
        reply = _safe_fallback(intent)

    # Always run minimal safety on the template reply
    if _contains_forbidden(reply) or _contains_meta_confirm(reply) or _introduces_new_identifier(reply, session):
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
            "- Do NOT ask vague meta questions (e.g., 'can I assist' / 'which aspect first').\n"
            "- The single question MUST be investigative and match the intent’s target.\n"
        )
        
        # Instruction-aware prompt; if instruction missing, use intent fallback goal
        trimmed = (instruction or "").strip()
        pfx = (red_flag_prefix or "").strip()
        if trimmed:
            if pfx:
                user_prompt = f"{pfx}\n{trimmed}\n\n{SINGLE_QUESTION_WRAPPER}"
            else:
                user_prompt = f"{trimmed}\n\n{SINGLE_QUESTION_WRAPPER}"
        else:
            goal = INTENT_GOALS.get(intent, "")
            # Only apply fallback single-question shaping when the intent is not a terminal close
            if goal and intent != INT_CLOSE_AND_VERIFY_SELF:
                if pfx:
                    user_prompt = f"{pfx}\n{goal}\n\n{SINGLE_QUESTION_WRAPPER}"
                else:
                    user_prompt = f"{goal}\n\n{SINGLE_QUESTION_WRAPPER}"
                try:
                    log(event="responder_instruction_fallback",
                        intent=intent, used_goal=True)
                except Exception:
                    pass
            else:
                # No instruction and no applicable goal → keep safe template reply
                return reply

        out = chat_completion(agent_rules, user_prompt, temperature=0.2, max_tokens=70)
        out = (out or "").strip()
        # Strip list markers to reduce accidental procedural formats before limit
        out = re.sub(r"(?m)^\s*(?:\d+\.\s*|[-*•]\s+)", "", out)
        out = _limit_sentences(out, max_sentences)
        if (not out
            or _contains_forbidden(out)
            or _contains_meta_confirm(out)
            or _count_questions(out) > 1
            or _introduces_new_identifier(out, session)
            or _looks_procedural(out)
            or _looks_vague_or_meta_question(out)
            or (intent != INT_CLOSE_AND_VERIFY_SELF and "?" in (out or "") and not _meets_intent_anchor(intent, out))
        ):
            raise ValueError("unsafe_rephrase")
        try:
            log(event="responder_rephrase_applied",
                intent=intent,
                had_instruction=bool(trimmed),
                used_fallback_goal=bool(not trimmed))
        except Exception:
            pass
        return out
    except Exception:
        log(event="responder_fallback", intent=intent)
        # On failure, return the safe template (already screened above)
        return reply
