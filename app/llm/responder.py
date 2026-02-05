from app.settings import settings
from app.llm.vllm_client import chat_completion


def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def _fallback_reply(req) -> str:
    """Safe fallback if vLLM is unreachable."""
    text = (req.message.text or "").lower()
    if any(x in text for x in ["otp", "pin", "password"]):
        return "i can't share otp/pin. please send the official website or helpline so i can verify."
    if "upi" in text:
        return "ok, send the upi id again clearly. what amount should i enter?"
    if "http" in text or "www." in text or "link" in text:
        return "the link isn't opening here. can you paste the full link again?"
    return "ok, what exactly do i need to do next?"


def generate_agent_reply(req, session) -> str:
    system = _load_prompt("app/llm/prompts/agent_system.txt")
    examples = _load_prompt("app/llm/prompts/examples.txt")

    history = session.conversation[-settings.MAX_CONTEXT_MESSAGES:]
    hist_lines = [f"{m.get('sender')}: {m.get('text')}" for m in history]
    meta = req.metadata.model_dump() if req.metadata else {}

    user = (
        f"Latest incoming message:\n"
        f"sender: {req.message.sender}\n"
        f"text: {req.message.text}\n\n"
        f"Conversation (most recent last):\n" + "\n".join(hist_lines) + "\n\n"
        f"Metadata: {meta}\n\n"
        "Task: Reply as the persona. Be human and brief.\n"
        "Goal: Keep them engaged and extract details (UPI/phone/link/account) without revealing detection.\n"
        "If they ask OTP/PIN/password, refuse calmly and ask for official website/helpline.\n"
        "Return ONLY the message to send (1-2 short lines max).\n\n"
        f"Style examples:\n{examples}"
    )

    try:
        out = chat_completion(system, user, temperature=0.4, max_tokens=80)
        reply = (out or "").strip()
        lines = [ln.strip() for ln in reply.splitlines() if ln.strip()]
        return "\n".join(lines[:2]) if lines else _fallback_reply(req)
    except Exception:
        return _fallback_reply(req)
