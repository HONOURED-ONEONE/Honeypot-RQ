import pytest
from unittest.mock import MagicMock, patch
from app.llm.responder import generate_agent_reply
from app.store.models import SessionState
from app.core.broken_flow_constants import INT_ASK_OFFICIAL_HELPLINE

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_responder_persona_prompt(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    mock_chat.return_value = "Mocked reply?"
    
    session = SessionState(sessionId="test")
    
    # Test with a specific persona style
    generate_agent_reply(
        req=MagicMock(),
        session=session,
        intent=INT_ASK_OFFICIAL_HELPLINE,
        instruction="ask for help",
        red_flag_prefix="I'm unsure.",
        persona_style="CONFUSION"
    )
    
    # Verify the call to chat_completion contains PERSONA_STYLE: CONFUSION
    args, _ = mock_chat.call_args
    user_prompt = args[1]
    assert "PERSONA_STYLE: CONFUSION" in user_prompt
    assert "RED_FLAG_PREFIX: I'm unsure." in user_prompt
    assert "INTENT: INT_ASK_OFFICIAL_HELPLINE" in user_prompt
