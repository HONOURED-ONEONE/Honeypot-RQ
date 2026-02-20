
import pytest
from unittest.mock import MagicMock, patch
from app.llm.responder import (
    generate_agent_reply,
    _looks_vague_or_meta_question,
    _meets_intent_anchor,
    _contains_meta_confirm,
    INTENT_REQUIRED_TERMS,
    VAGUE_QUESTION_PATTERNS
)
from app.core.broken_flow_constants import (
    INT_ASK_OFFICIAL_HELPLINE,
    INT_ASK_OFFICIAL_WEBSITE,
    INT_ASK_TICKET_REF,
    INT_ASK_DEPARTMENT_BRANCH,
    INT_ASK_ALT_VERIFICATION,
    INT_CLOSE_AND_VERIFY_SELF
)

# Mock session object
class MockSession:
    def __init__(self):
        self.extractedIntelligence = MagicMock()
        self.extractedIntelligence.phoneNumbers = []
        self.extractedIntelligence.phishingLinks = []
        self.extractedIntelligence.bankAccounts = []
        self.extractedIntelligence.upiIds = []
        self.conversation = []

@pytest.fixture
def session():
    return MockSession()

@pytest.fixture
def req():
    return MagicMock()

def test_vague_question_detection():
    # Test cases that should match vague patterns
    vague_examples = [
        "Is there something else you need?",
        "Can I assist you with anything?",
        "How can I help you today?",
        "Is there a specific aspect you want to discuss?",
        "Would you like to address first?",
        "Will you please confirm the details?",
        "Can you confirm this?"
    ]
    for q in vague_examples:
        assert _looks_vague_or_meta_question(q), f"Should detect vague question: {q}"

    # Test cases that should NOT match
    specific_examples = [
        "What is the official helpline number?",
        "Can you provide the reference ID?",
        "Which department should I contact?",
        "I need the official website link."
    ]
    for q in specific_examples:
        assert not _looks_vague_or_meta_question(q), f"Should not flag specific question: {q}"

def test_intent_anchor_enforcement():
    # Helper alias
    check = _meets_intent_anchor

    # Helpline
    intent = INT_ASK_OFFICIAL_HELPLINE
    assert check(intent, "What is the official helpline number?")
    assert check(intent, "Please give me the number to call.")
    assert not check(intent, "Where should I go?") # No anchor

    # Website
    intent = INT_ASK_OFFICIAL_WEBSITE
    assert check(intent, "What is the official website?")
    assert check(intent, "I need the domain name.")
    assert not check(intent, "Send me the link.") # "link" is not in anchor list for this intent (website, domain, site)

    # Ticket Ref
    intent = INT_ASK_TICKET_REF
    assert check(intent, "Do you have a reference number?")
    assert check(intent, "What is the case ID?")
    assert not check(intent, "What is the code?") # "code" not in anchor list

    # Department
    intent = INT_ASK_DEPARTMENT_BRANCH
    assert check(intent, "Which department handles this?")
    assert check(intent, "Is there a specific branch?")
    assert not check(intent, "Who is responsible?") # "team", "office" are allowed, but "who" is not sufficient alone

    # Alt Verification
    intent = INT_ASK_ALT_VERIFICATION
    assert check(intent, "Is there an alternative method?")
    assert check(intent, "Can I verify another way?")
    assert not check(intent, "How do I pay?") # Irrelevant

def test_meta_confirm_detection():
    assert _contains_meta_confirm("Will you please confirm that I should do this?")
    assert _contains_meta_confirm("Can you confirm the amount?")
    assert _contains_meta_confirm("Please confirm if this is correct.")
    assert not _contains_meta_confirm("I will confirm this with the bank.")

def test_generate_reply_blocks_vague_output(req, session):
    # If LLM produces a vague question, it should fallback to a safe template
    with patch("app.llm.responder.chat_completion") as mock_chat:
        # Mock LLM returning a vague question
        mock_chat.return_value = "Is there anything else I can assist with?"
        
        # We need settings.BF_LLM_REPHRASE = True
        with patch("app.settings.settings.BF_LLM_REPHRASE", True):
            reply = generate_agent_reply(req, session, INT_ASK_OFFICIAL_HELPLINE)
            
            # The reply should NOT be the vague one
            assert "assist with" not in reply.lower()
            # It should be one of the safe templates for HELPLINE
            assert "helpline" in reply.lower() or "number" in reply.lower()

def test_generate_reply_enforces_anchors(req, session):
    # If LLM produces a question without anchors, it should fallback
    with patch("app.llm.responder.chat_completion") as mock_chat:
        # Mock LLM returning a question without "helpline", "number", "call"
        mock_chat.return_value = "Where should I send the message?" 
        
        with patch("app.settings.settings.BF_LLM_REPHRASE", True):
            reply = generate_agent_reply(req, session, INT_ASK_OFFICIAL_HELPLINE)
            
            # Should fallback to template which has anchors
            assert "helpline" in reply.lower() or "number" in reply.lower() or "call" in reply.lower()

def test_generate_reply_blocks_meta_confirm(req, session):
    with patch("app.llm.responder.chat_completion") as mock_chat:
        mock_chat.return_value = "Can you confirm if I should click the link?"
        
        with patch("app.settings.settings.BF_LLM_REPHRASE", True):
            reply = generate_agent_reply(req, session, INT_ASK_OFFICIAL_WEBSITE)
            
            # Should fallback
            assert "confirm if i should" not in reply.lower()
            # Website template should be used
            assert "website" in reply.lower() or "domain" in reply.lower()

def test_close_intent_skips_anchor_check(req, session):
    # CLOSE intent typically doesn't ask a question, but if it did (or if it's a statement),
    # it shouldn't be blocked by anchor checks for other intents.
    # Actually the code says: if intent != INT_CLOSE... and "?" in reply...
    pass 
