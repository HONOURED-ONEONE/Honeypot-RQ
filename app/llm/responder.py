import random
import re
import logging
from difflib import SequenceMatcher
from collections import Counter

from app.settings import settings
from app.llm.vllm_client import chat_completion

logger = logging.getLogger("honeypot_agent")
logger.setLevel(logging.INFO)

FORBIDDEN_TERMS = [
    "ai",
    "law enforcement",
    "detected",
    "detection",
    "honeypot",
    "fraud classifier",
]

OTP_TERMS = re.compile(r"(otp|pin|password)", re.I)
OPENERS_TO_GUARD = {"ok", "wait", "hmm", "accha", "sir", "beta"}


def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _parse_examples(raw: str) -> list[str]:
    out = []
    for ln in raw.splitlines():
        ln = re.sub(r"^[-*]\s*", "", ln).strip()
        if not ln:
            continue
        if len(ln.split()) < 3:
            continue
        out.append(ln)
    return out


def _two_lines_max(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return "
".join(lines[:2])


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, (a or "").lower().strip(), (b or "").lower().strip()).ratio()


def _contains_forbidden(reply: str) -> bool:
    r = (reply or "").lower()
    return any(term in r for term in FORBIDDEN_TERMS)


def _get_last_agent_replies(history: list[dict], agent_sender: str = "agent", k: int = 5) -> list[str]:
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


def generate_agent_reply(req, session) -> str:
    system_prompt = _load_prompt("app/llm/prompts/agent_system.txt")

    raw_examples = _load_prompt("app/llm/prompts/examples.txt")
    examples = _parse_examples(raw_examples)
    sampled_examples = random.sample(examples, min(random.randint(3, 5), len(examples))) if examples else []

    history = session.conversation[-settings.MAX_CONTEXT_MESSAGES:]
    hist_lines = [f"{m.get('sender')}: {m.get('text')}" for m in history]

    last_agent_replies = _get_last_agent_replies(history, agent_sender="agent", k=5)
    last_opener = _get_opener(last_agent_replies[0]) if last_agent_replies else ""

    reject_stats = Counter()

    user_prompt = (
        "### LATEST INCOMING MESSAGE ###
"
        f"sender: {req.message.sender}
"
        f"text: {req.message.text}

"
        "### CONVERSATION HISTORY (most recent last) ###
"
        + "
".join(hist_lines)
        + "

"
        "### TASK ###
"
        "- Reply as a polite, elderly Indian person.
"
        "- Be brief: 1–2 short lines only.
"
        "- Keep the conversation going and ask at most ONE question.
"
        "- Do NOT mention scams, AI, or enforcement.
"
        "- If asked for OTP/PIN/password: refuse calmly and redirect to official verification.
"
        "- Sound slightly unsure, respectful, and human.

"
        "### STYLE EXAMPLES (tone only, do not copy) ###
"
        + "
".join(f"- {ex}" for ex in sampled_examples)
        + "
"
    )

    temperatures = [0.6, 0.7]

    for attempt in range(2):
        try:
            out = chat_completion(system_prompt, user_prompt, temperature=temperatures[attempt], max_tokens=90)
            reply = (out or "").strip()

            if reply.lower().startswith("agent:"):
                reply = reply.split(":", 1)[1].strip()

            reply = _two_lines_max(reply)
            if not reply:
                reject_stats["empty"] += 1
                continue

            opener = _get_opener(reply)
            if opener in OPENERS_TO_GUARD and last_opener in OPENERS_TO_GUARD and opener == last_opener:
                reject_stats["same_opener"] += 1
                continue

            if _contains_forbidden(reply):
                reject_stats["forbidden"] += 1
                continue

            if OTP_TERMS.search(req.message.text or "") and re.search(r"\d{4,8}", reply):
                reject_stats["otp_leak"] += 1
                continue

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
