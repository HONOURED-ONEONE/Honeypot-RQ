import pytest
from unittest.mock import patch, MagicMock
from app.llm.responder import generate_agent_reply, _parse_examples, _select_examples
from app.store.models import SessionState
from app.core.broken_flow_constants import INT_ASK_OFFICIAL_HELPLINE

def test_session_state_telemetry_fields():
    s = SessionState()
    assert s.rephraseAttempts == 0
    assert s.rephraseApplied == 0
    assert s.rephraseRejected == 0
    assert s.lastRephraseRejectReason is None

def test_parse_examples():
    raw = """
[INTENT=INT_A]
Example A1

[INTENT=INT_A]
Example A2

[INTENT=INT_B]
Example B1
    """
    parsed = _parse_examples(raw)
    assert "INT_A" in parsed
    assert len(parsed["INT_A"]) == 2
    assert parsed["INT_A"][0] == "Example A1"
    assert parsed["INT_B"][0] == "Example B1"

def test_select_examples_fallback():
    # If no specific intent examples, should fallback to * if available
    # But in the provided file, we don't have * examples explicitly, but the function handles it.
    # Let's mock _examples_map
    with patch("app.llm.responder._examples_map") as mock_map:
        mock_map.return_value = {
            "INT_A": ["ExA1", "ExA2"],
            "*": ["Generic1"]
        }
        
        # Exact match
        sel = _select_examples("INT_A", k=2)
        assert len(sel) == 2
        assert "ExA1" in sel
        
        # Fallback
        sel = _select_examples("INT_MISSING", k=2)
        assert len(sel) == 1
        assert "Generic1" in sel

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
@patch("app.llm.responder._agent_system_prompt")
@patch("app.llm.responder._select_examples")
def test_rephrase_telemetry_success(mock_select, mock_sys, mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    mock_sys.return_value = "SYSTEM_PROMPT"
    mock_select.return_value = ["Example 1"]
    # Must contain anchor for INT_ASK_OFFICIAL_HELPLINE (helpline, number, call)
    mock_chat.return_value = "What is the official helpline number?"
    
    session = SessionState(sessionId="test_tel")
    
    generate_agent_reply(None, session, INT_ASK_OFFICIAL_HELPLINE, instruction="Ask helpline")
    
    assert session.rephraseAttempts == 1
    assert session.rephraseApplied == 1
    assert session.rephraseRejected == 0
    assert session.lastRephraseRejectReason is None
    
    # Check prompt construction
    args, _ = mock_chat.call_args
    system_arg = args[0]
    user_arg = args[1]
    
    assert system_arg == "SYSTEM_PROMPT"
    assert "EXAMPLES" in user_arg
    assert "Example 1" in user_arg
    assert "INTENT: INT_ASK_OFFICIAL_HELPLINE" in user_arg

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_rephrase_telemetry_rejection(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    # Return unsafe reply (multi-question)
    mock_chat.return_value = "Question 1? Question 2?"
    
    session = SessionState(sessionId="test_rej")
    
    generate_agent_reply(None, session, INT_ASK_OFFICIAL_HELPLINE, instruction="Ask helpline")
    
    assert session.rephraseAttempts == 1
    assert session.rephraseApplied == 0
    # Double counting fixed
    assert session.rephraseRejected == 1
    assert session.lastRephraseRejectReason == "multi_question"

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_rephrase_telemetry_exception(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    mock_chat.side_effect = RuntimeError("API fail")
    
    session = SessionState(sessionId="test_exc")
    
    generate_agent_reply(None, session, INT_ASK_OFFICIAL_HELPLINE, instruction="Ask helpline")
    
    assert session.rephraseAttempts == 1
    assert session.rephraseApplied == 0
    assert session.rephraseRejected == 1
    # The logic sets reason to "exception" if not already set
    assert session.lastRephraseRejectReason == "exception"
