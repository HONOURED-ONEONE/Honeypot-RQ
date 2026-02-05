from app.settings import settings
from app.llm.gemini_client import generate_content


def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _rule_fallback(req) -> str:
    """Rule-based safe response that keeps the scammer talking."""
    text = (req.message.text or "").lower()
    if any(x in text for x in ["otp", "pin", "password"]):
        return "i can't share otp/pin. send the official website/helpline so i can verify."
    if "upi" in text:
        return "ok where exactly do i enter the upi id? can you send it again clearly"
    if "http" in text or "www." in text or "link" in text:
        return "the link isn't opening here. can you send the full link again?"
    return "ok, what exactly do i need to do next?"


def generate_agent_reply(req, session) -> str:
    system = _load_prompt("app/llm/prompts/agent_system.txt")
    examples = _load_prompt("app/llm/prompts/examples.txt")

    history = session.conversation[-settings.MAX_CONTEXT_MESSAGES :]
    hist_lines = [f"{m.get('sender')}: {m.get('text')}" for m in history]
    meta = req.metadata.model_dump() if req.metadata else {}

    user = (
        f"Latest incoming message:\n"
        f"sender: {req.message.sender}\n"
        f"text: {req.message.text}\n\n"
        f"Conversation (most recent last):\n" + "\n".join(hist_lines) + "\n\n"
        f"Metadata: {meta}\n\n"
        "Task: Reply as the persona. Be human and brief."
        " Ask for clarification about the next step and/or verification in a way that encourages the sender to reveal identifiers (UPI/phone/link/bank details) without exposing detection."
        " If asked for OTP/PIN/password, refuse calmly and ask for official website/helpline."
        " Return ONLY the message to send (1-2 short lines max).\n\n"
        f"Style examples:\n{examples}"
    )

    try:
        out = generate_content(system, user, temperature=0.4, max_tokens=80)
        reply = (out or "").strip()
        lines = [ln.strip() for ln in reply.splitlines() if ln.strip()]
        return "\n".join(lines[:2]) if lines else _rule_fallback(req)
    except Exception:
        return _rule_fallback(req)
