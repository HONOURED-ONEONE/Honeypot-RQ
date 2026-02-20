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
from functools import lru_cache
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
# Prompt pack wiring: agent_system.txt + examples.txt (few-shot)
# ---------------------------------------------------------------------------
@lru_cache(maxsize=4)
def _agent_system_prompt() -> str:
    """
    Load the long-form system prompt used for BF_LLM_REPHRASE generation.
    Falls back to empty string if not found.
    """
    return (_load_file_text("agent_system.txt") or "").strip()

@lru_cache(maxsize=4)
def _examples_text() -> str:
    """
    Load examples.txt. Expected format:
      [INTENT=INT_ASK_OFFICIAL_HELPLINE]
      <example line>
    """
    return (_load_file_text("examples.txt") or "").strip()

def _parse_examples(raw: str) -> Dict[str, List[str]]:
    """
    Parse examples into {INTENT: [example_str, ...]}.
    Best-effort:
    - Preferred: blocks starting with [INTENT=...]
    - Fallback: treat each non-empty line as a generic example under key "*"
    """
    out: Dict[str, List[str]] = {}
    if not raw:
        return out
    lines = [ln.rstrip() for ln in raw.splitlines()]
    current = None
    buf: List[str] = []
    def flush():
        nonlocal buf, current
        if current and buf:
            ex = " ".join([x.strip() for x in buf if x.strip()]).strip()
            if ex:
                out.setdefault(current, []).append(ex)
        buf = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        m = re.match(r"^\[INTENT\s*=\s*([A-Z0-9_]+)\]\s*$", s)
        if m:
            flush()
            current = m.group(1).strip()
            continue
        if s.startswith("#"):
            continue
        if current:
            buf.append(s)
        else:
            out.setdefault("*", []).append(s)
    flush()
    return out

@lru_cache(maxsize=8)
def _examples_map() -> Dict[str, List[str]]:
    return _parse_examples(_examples_text())

def _select_examples(intent: str, k: int = 3) -> List[str]:
    """
    Select up to k examples for the given intent.
    Falls back to "*" generic examples if intent-specific ones are unavailable.
    """
    mp = _examples_map() or {}
    intent_key = (intent or "").strip()
    candidates = mp.get(intent_key, []) or []
    if not candidates:
        candidates = mp.get("*", []) or []
    if not candidates:
        return []
    if len(candidates) <= k:
        return candidates
    start = random.randint(0, max(0, len(candidates) - k))
    return candidates[start:start + k]

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
        "The link doesn’t seem to load here. Which official site should I visit directly?",
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

# Block "trusted source / official channel" questions.
# These tend to loop and are not tied to a scoreable IOC category (phone/link/ID/etc.). [1](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/honoured-oneone-honeypot-rq-8a5edab282632443-2.txt)
TRUST_SOURCE_PATTERNS = [
    r"\btrusted source\b",
    r"\bofficial channel\b",
    r"\bunknown source\b",
    r"\bis this (really )?official\b",
    r"\bofficial alert\b",
    r"\bcoming from (a|an) (official|trusted)\b",
    r"\bcan i trust\b",
]

# Block open-ended "meta analysis" questions that don't elicit IOCs.
META_ANALYSIS_PATTERNS = [
    r"\bconcrete evidence\b",
    r"\bevidence\b",
    r"\binappropriate\b",
    r"\bseems inappropriate\b",
    r"\bdoes this urgency\b",
]

# Token sets used to enforce "single artifact target" per question.
# If a question hits 2+ sets, it likely asks for multiple artifacts in one question (e.g., "phone or email").
TARGET_TOKEN_SETS: Dict[str, List[str]] = {
    "phoneNumbers": ["helpline", "phone", "number", "call"],
    "emailAddresses": ["email", "mail", "e-mail"],
    "phishingLinks": ["website", "domain", "site", "link", "portal"],
    "caseIds": ["reference", "ref", "ticket", "case", "complaint", "id"],
    "department": ["department", "branch", "office", "team"],
    "upiIds": ["upi", "vpa", "handle", " @"],
    "bankAccounts": ["account", "a/c", "acct"],
}

# Per-intent "anchor terms" to make investigative questions clearly relevant.
# These ensure the question explicitly targets the intended artifact category,
# improving "Relevant Questions" scoring. [2](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/logs.txt)
INTENT_REQUIRED_TERMS: Dict[str, List[str]] = {
    INT_ASK_OFFICIAL_HELPLINE: ["helpline", "number", "call"],
    INT_ASK_OFFICIAL_WEBSITE: ["website", "domain", "site"],
    INT_ASK_TICKET_REF: ["reference", "ref", "ticket", "case", "complaint", "id"],
    INT_ASK_DEPARTMENT_BRANCH: ["department", "branch", "office", "team"],
    # Tighten ALT_VERIFICATION anchors: avoid overly-broad terms like "official" that can allow "is this official?"
    # Keep it focused on "alternate method/option" phrasing.
    INT_ASK_ALT_VERIFICATION: ["alternative", "alternate", "another", "different", "method", "option"],
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

def _looks_trust_source_question(s: str) -> bool:
    t = (s or "").lower()
    if "?" not in t:
        return False
    return any(re.search(p, t, re.I) for p in TRUST_SOURCE_PATTERNS)

def _looks_meta_analysis_question(s: str) -> bool:
    t = (s or "").lower()
    if "?" not in t:
        return False
    return any(re.search(p, t, re.I) for p in META_ANALYSIS_PATTERNS)

def _count_target_sets_hit(s: str) -> int:
    t = (s or "").lower()
    hits = 0
    for _, toks in TARGET_TOKEN_SETS.items():
        if any(tok in t for tok in toks):
            hits += 1
    return hits

def _violates_single_artifact(s: str) -> bool:
    # 2+ target set hits means the question likely asks for multiple artifacts at once.
    return _count_target_sets_hit(s) >= 2

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
    persona_style: Optional[str] = None,
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

    # Wording constraint 1b: block "trusted source / official channel" meta questions
    if _looks_trust_source_question(reply):
        reply = _safe_fallback(intent)

    # Wording constraint 1c: block open-ended meta-analysis questions
    if _looks_meta_analysis_question(reply):
        reply = _safe_fallback(intent)

    # Wording constraint 1d: enforce single-artifact target per question
    if intent != INT_CLOSE_AND_VERIFY_SELF and "?" in (reply or "") and _violates_single_artifact(reply):
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
        # --- Rephrase telemetry: count attempts ---
        try:
            session.rephraseAttempts = int(getattr(session, "rephraseAttempts", 0) or 0) + 1
        except Exception:
            pass

        # System prompt pack (preferred): app/llm/prompts/agent_system.txt
        # Fallback: inline rules if file missing.
        system_prompt = _agent_system_prompt()
        if not system_prompt:
            system_prompt = (
                "You generate short, cautious replies for verification.\n"
                "NON-NEGOTIABLES:\n"
                "- Follow the given instruction strictly (no new goals).\n"
                "- NO procedures, steps, or instructions.\n"
                "- At most ONE question.\n"
                "- Do NOT invent or mention any identifiers.\n"
                "- Keep it concise (max 2–3 sentences based on intent).\n"
                "- Do NOT imply resolution or closure unless told.\n"
                "- Do NOT ask vague meta questions.\n"
                "- The single question MUST be investigative and match the intent’s target.\n"
            )

        trimmed = (instruction or "").strip()
        pfx = (red_flag_prefix or "").strip()
        sty = (persona_style or "").strip()

        # Few-shot examples (optional)
        exs = _select_examples(intent, k=3)
        ex_block = ""
        if exs:
            ex_lines = "\n".join([f"- {e}" for e in exs])
            ex_block = f"EXAMPLES (follow the same format):\n{ex_lines}\n\n"

        # Build a structured user prompt to reduce drift and improve validity.
        if trimmed:
            core = (
                f"RED_FLAG_PREFIX: {pfx}\n"
                f"PERSONA_STYLE: {sty}\n"
                f"INTENT: {intent}\n"
                f"INSTRUCTION: {trimmed}\n\n"
                f"{SINGLE_QUESTION_WRAPPER}"
            )
            user_prompt = ex_block + core
        else:
            goal = INTENT_GOALS.get(intent, "")
            if goal and intent != INT_CLOSE_AND_VERIFY_SELF:
                core = (
                    f"RED_FLAG_PREFIX: {pfx}\n"
                    f"PERSONA_STYLE: {sty}\n"
                    f"INTENT: {intent}\n"
                    f"GOAL: {goal}\n\n"
                    f"{SINGLE_QUESTION_WRAPPER}"
                )
                user_prompt = ex_block + core
                try:
                    log(event="responder_instruction_fallback", intent=intent, used_goal=True)
                except Exception:
                    pass
            else:
                return reply

        out = chat_completion(system_prompt, user_prompt, temperature=0.2, max_tokens=70)
        out = (out or "").strip()
        # Strip list markers to reduce accidental procedural formats before limit
        out = re.sub(r"(?m)^\s*(?:\d+\.\s*|[-*•]\s+)", "", out)
        out = _limit_sentences(out, max_sentences)
        
        # --- Rephrase validation with reason capture (telemetry) ---
        reject_reason = None
        if not out:
            reject_reason = "empty"
        elif _contains_forbidden(out):
            reject_reason = "forbidden_terms"
        elif _contains_meta_confirm(out):
            reject_reason = "meta_confirm"
        elif _count_questions(out) > 1:
            reject_reason = "multi_question"
        elif _introduces_new_identifier(out, session):
            reject_reason = "new_identifier"
        elif _looks_procedural(out):
            reject_reason = "procedural"
        elif _looks_vague_or_meta_question(out):
            reject_reason = "vague_meta"
        elif _looks_trust_source_question(out):
            reject_reason = "trust_source"
        elif _looks_meta_analysis_question(out):
            reject_reason = "meta_analysis"
        elif (intent != INT_CLOSE_AND_VERIFY_SELF and "?" in out and _violates_single_artifact(out)):
            reject_reason = "multi_artifact"
        elif (intent != INT_CLOSE_AND_VERIFY_SELF and "?" in out and not _meets_intent_anchor(intent, out)):
            reject_reason = "anchor_miss"

        if reject_reason:
            try:
                session.rephraseRejected = int(getattr(session, "rephraseRejected", 0) or 0) + 1
                session.lastRephraseRejectReason = str(reject_reason)
            except Exception:
                pass
            raise ValueError(f"unsafe_rephrase:{reject_reason}")

        # Accept rephrase
        try:
            session.rephraseApplied = int(getattr(session, "rephraseApplied", 0) or 0) + 1
            session.lastRephraseRejectReason = None
        except Exception:
            pass

        # Log cumulative acceptance rate (non-influential)
        try:
            a = int(getattr(session, "rephraseAttempts", 0) or 0)
            ok = int(getattr(session, "rephraseApplied", 0) or 0)
            bad = int(getattr(session, "rephraseRejected", 0) or 0)
            rate = (ok / a) if a > 0 else 0.0
            log(event="rephrase_rate",
                intent=intent,
                attempts=a,
                applied=ok,
                rejected=bad,
                acceptRate=round(rate, 3))
        except Exception:
            pass

        return out
    except Exception as e:
        # Count rejection if we attempted rephrase but failed unexpectedly
        try:
            # Fix: avoid double counting if we already raised unsafe_rephrase
            if not str(e).startswith("unsafe_rephrase"):
                session.rephraseRejected = int(getattr(session, "rephraseRejected", 0) or 0) + 1
            
            if not getattr(session, "lastRephraseRejectReason", None):
                session.lastRephraseRejectReason = "exception"
        except Exception:
            pass
        try:
            a = int(getattr(session, "rephraseAttempts", 0) or 0)
            ok = int(getattr(session, "rephraseApplied", 0) or 0)
            bad = int(getattr(session, "rephraseRejected", 0) or 0)
            rate = (ok / a) if a > 0 else 0.0
            log(event="rephrase_rate",
                intent=intent,
                attempts=a,
                applied=ok,
                rejected=bad,
                acceptRate=round(rate, 3),
                lastRejectReason=str(getattr(session, "lastRephraseRejectReason", "") or ""))
        except Exception:
            pass
        log(event="responder_fallback", intent=intent)
        # On failure, return the safe template (already screened above)
        return reply
