import os
import re

# Force rephrase path in tests
os.environ["BF_LLM_REPHRASE"] = "true"

from app.llm import responder as R

# Monkeypatch chat_completion to AVOID network calls.
# It returns the "user" prompt (our instruction) trimmed, so we test the guardrails
# and formatting that Responder applies (one question, non-procedural, artifact-strict).
R.chat_completion = lambda system, user, temperature=0.2, max_tokens=70: user.strip()

# Make sure settings flag is true at runtime
R.settings.BF_LLM_REPHRASE = True


class _FakeIntel:
    def __init__(self):
        self.phoneNumbers = []
        self.phishingLinks = []
        self.bankAccounts = []
        self.upiIds = []
        self.emailAddresses = []
        self.suspiciousKeywords = []
        self.dynamicArtifacts = {}

class _FakeSession:
    def __init__(self):
        self.extractedIntelligence = _FakeIntel()

class _FakeReq:
    class _Msg:
        def __init__(self, text=""):
            self.text = text
            self.timestamp = 0
            self.sender = "scammer"
    def __init__(self, text=""):
        self.message = _FakeReq._Msg(text)


def _one_question(reply: str) -> bool:
    return reply.count("?") == 1

_PROC_PATTERNS = [
    r"\b(step|steps|follow these|do the following)\b",
    r"(?m)^\s*\d+\.",            # numbered lists
    r"(?m)^\s*[-*•]\s+",         # bullets
    r"\b(click|open|go to|log ?in|enter|submit|navigate|install|download)\b",
]
def _non_procedural(reply: str) -> bool:
    t = reply.lower()
    return not any(re.search(p, t, re.I) for p in _PROC_PATTERNS)


def test_rse_feigned_phone_single_artifact_focus():
    """
    [STYLE:FEIGNED] Ask ONLY for phone number; no links/upi/bank, one question, non-procedural.
    """
    req = _FakeReq("Please verify now; share OTP or call us.")
    ses = _FakeSession()
    # Ensure there is a question mark so _one_question passes on the echoed mock
    instr = "[STYLE:FEIGNED] The page keeps timing out; could you share your official desk or direct number so I can confirm? Ask only for the phone number."
    out = R.generate_agent_reply(req=req, session=ses, intent=R.INT_ASK_OFFICIAL_HELPLINE, instruction=instr)
    assert _one_question(out), f"Must ask exactly one question: {out}"
    assert _non_procedural(out), f"Must not be procedural: {out}"
    assert not re.search(r"\bhttps?://|www\.", out, re.I), "Should not ask for links"
    assert not re.search(r"\b[A-Za-z0-9._-]+@[A-Za-z]+\b", out), "Should not ask for UPI/email"
    assert re.search(r"\b(number|call|helpline|phone)\b", out, re.I), "Should reference phone"


def test_rse_feigned_link_single_artifact_focus():
    """
    [STYLE:FEIGNED] Ask ONLY for link; no phone/upi/bank, one question, non-procedural.
    """
    req = _FakeReq("Use our secure portal immediately.")
    ses = _FakeSession()
    # Avoid "open" to prevent procedural trigger
    instr = "[STYLE:FEIGNED] The site isn’t loading here; do you have an official mirror or a short link I can access to check? Ask only for the link."
    out = R.generate_agent_reply(req=req, session=ses, intent=R.INT_ASK_OFFICIAL_WEBSITE, instruction=instr)
    assert _one_question(out)
    assert _non_procedural(out)
    assert not re.search(r"\bnumber|call|helpline|phone\b", out, re.I), "Should not ask for phone"
    assert re.search(r"\blink|website|site|domain|mirror\b", out, re.I), "Should reference link"


def test_rse_greed_upi_single_artifact_focus():
    """
    [STYLE:GREED] Ask ONLY for alternate UPI; no phone/link/bank, one question, non-procedural.
    """
    req = _FakeReq("Send payment to proceed.")
    ses = _FakeSession()
    instr = "[STYLE:GREED] My accountant queued a larger transfer but the first attempt showed a block; could you share a different UPI ID for a small test first? Ask only for the UPI ID."
    out = R.generate_agent_reply(req=req, session=ses, intent=R.INT_ASK_ALT_VERIFICATION, instruction=instr)
    assert _one_question(out)
    assert _non_procedural(out)
    assert not re.search(r"\bnumber|call|helpline|phone\b", out, re.I), "Should not ask for phone"
    assert not re.search(r"\bhttps?://|www\.", out, re.I), "Should not ask for links"
    assert re.search(r"\bupi\b", out, re.I), "Should reference UPI"


def test_rse_greed_bank_single_artifact_focus():
    """
    [STYLE:GREED] Ask ONLY for alternate bank account; no phone/link/upi, one question, non-procedural.
    """
    req = _FakeReq("Confirm transfer now.")
    ses = _FakeSession()
    instr = "[STYLE:GREED] The beneficiary shows maintenance; could you provide an alternate bank account so I can try a small test before the high-value wire? Ask only for the bank account."
    out = R.generate_agent_reply(req=req, session=ses, intent=R.INT_CHANNEL_FAIL, instruction=instr)
    assert _one_question(out)
    assert _non_procedural(out)
    assert not re.search(r"\bnumber|call|helpline|phone\b", out, re.I), "Should not ask for phone"
    assert not re.search(r"\bhttps?://|www\.", out, re.I), "Should not ask for links"
    assert not re.search(r"\bupi\b", out, re.I), "Should not ask for UPI"
    assert re.search(r"\baccount\b", out, re.I), "Should reference bank account"
