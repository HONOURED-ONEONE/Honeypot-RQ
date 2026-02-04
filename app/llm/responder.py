from app.settings import settings
from app.llm.gemini_client import generate_content


def _load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def generate_agent_reply(req, session) -> str:
    system = _load_prompt("app/llm/prompts/agent_system.txt")
    examples = _load_prompt("app/llm/prompts/examples.txt")

    # Build a compact user prompt
    history = session.conversation[-settings.MAX_CONTEXT_MESSAGES :]
    hist_lines = []
    for msg in history:
        hist_lines.append(f"{msg.get('sender')}: {msg.get('text')}")

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

    out = generate_content(system, user, temperature=0.4, max_tokens=80)

    # Ensure we return a short, single message.
    reply = out.strip()
    # Trim excessive lines
    lines = [ln.strip() for ln in reply.splitlines() if ln.strip()]
    reply = "\n".join(lines[:2])
    return reply
