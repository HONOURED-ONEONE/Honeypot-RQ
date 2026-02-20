import pytest
from unittest.mock import patch, MagicMock
from app.llm.responder import _split_sentences, _limit_sentences, generate_agent_reply
from app.store.models import SessionState
from app.core.broken_flow_constants import INT_ASK_OFFICIAL_HELPLINE, INT_ACK_CONCERN, INT_REFUSE_SENSITIVE_ONCE

def test_split_sentences():
    text = "Sentence one. Sentence two! Sentence three? Sentence four."
    expected = ["Sentence one.", "Sentence two!", "Sentence three?", "Sentence four."]
    assert _split_sentences(text) == expected

def test_limit_sentences():
    text = "One. Two. Three. Four."
    assert _limit_sentences(text, 2) == "One. Two."
    assert _limit_sentences(text, 5) == "One. Two. Three. Four."

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_generate_agent_reply_rephrase_success(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    mock_chat.return_value = "Rephrased response?"
    
    session = SessionState(sessionId="test")
    # Use an intent in SAFE_FOR_REPHRASE
    reply = generate_agent_reply(None, session, INT_ACK_CONCERN)
    
    assert reply == "Rephrased response?"
    mock_chat.assert_called_once()
    args, _ = mock_chat.call_args
    # Check for the new, stricter system prompt
    assert "SAFETY CONSTRAINTS" in args[0]
    assert "At most ONE question." not in args[0] # Changed in new prompt
    assert "Exactly ONE investigative question" in args[0]

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_generate_agent_reply_gating(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    # The new logic allows rephrase for ALL intents if enabled.
    mock_chat.return_value = "Rephrased helpline query?"
    
    session = SessionState(sessionId="test")
    # Intent previously blocked from rephrase
    reply = generate_agent_reply(None, session, INT_ASK_OFFICIAL_HELPLINE)
    
    # Rephrase should NOT be skipped now
    assert mock_chat.called is True
    assert reply == "Rephrased helpline query?"

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_generate_agent_reply_procedural_fallback(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    # LLM returns something procedural
    mock_chat.return_value = "1. Open your browser. 2. Go to bank.com."
    
    session = SessionState(sessionId="test")
    reply = generate_agent_reply(None, session, INT_ACK_CONCERN)
    
    # Should fallback because it looks procedural
    assert "Open your browser" not in reply
    assert reply in [
        "Okay, I want to be careful about this.",
        "I understand—this sounds concerning.",
        "Alright, I’m being cautious here.",
    ]

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_generate_agent_reply_rephrase_failure_fallback(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    # LLM returns something forbidden
    mock_chat.return_value = "Please share otp now"
    
    session = SessionState(sessionId="test")
    reply = generate_agent_reply(None, session, INT_ACK_CONCERN)
    
    assert "share otp" not in reply.lower()

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_generate_agent_reply_rephrase_exception_fallback(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    mock_chat.side_effect = Exception("API Error")
    
    session = SessionState(sessionId="test")
    reply = generate_agent_reply(None, session, INT_ASK_OFFICIAL_HELPLINE)
    
    # Should fallback to a safe template
    assert isinstance(reply, str)
    assert len(reply) > 0
