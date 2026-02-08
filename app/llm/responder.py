import random
import re
import logging
from difflib import SequenceMatcher
from collections import Counter

from app.settings import settings
from app.llm.vllm_client import chat_completion

logger = logging.getLogger("honeypot_agent")
logger.setLevel(logging.INFO)

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


def _fallback_reply(req) -> str:
    text = (req.message.text or "").lower()

    if OTP_TERMS.search(text):
        return random.choice(_FALLBACKS["otp"])

    if "upi" in text:
        return random.choice(_FALLBACKS["upi"])

    if "http" in text or "www." in text or "link" in text:
        return random.choice(_FALLBACKS["link"])

    return random.choice(_FALLBACKS["gen"])


# ============================================================
# Main generator
# ============================================================

def generate_agent_reply(req, session) -> str:
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

    logger.warning("fallback_used reject_stats=%s", dict(reject_stats))
    return _fallback_reply(req)
