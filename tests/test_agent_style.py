import pytest
from app.llm.responder import generate_agent_reply
from app.store.models import SessionState
from app.settings import settings
from unittest.mock import patch

def test_system_prompt_updates():
    # Verify that the system prompt file has been updated with STYLE tokens and STRICT ARTIFACT FOCUS
    with open("app/llm/prompts/agent_system.txt", "r") as f:
        content = f.read()
        assert "PERSONA_STYLE" in content
        assert "PERSONA STYLE GUIDANCE" in content
        assert "STRICT SINGLE-ARTIFACT RULE" in content

@patch("app.llm.responder.chat_completion")
@patch("app.llm.responder.settings")
def test_responder_incorporates_style_tokens(mock_settings, mock_chat):
    mock_settings.BF_LLM_REPHRASE = True
    mock_chat.return_value = "Feigned ignorance reply"
    
    session = SessionState(sessionId="test_style")
    instruction_with_style = "Ask for mirror link [STYLE:FEIGNED]"
    
    generate_agent_reply(None, session, "INT_ASK_OFFICIAL_WEBSITE", instruction=instruction_with_style)
    
    # Check that the prompt sent to LLM contains the system prompt which has the new instructions
    # Note: We can't easily check the system prompt content passed to chat_completion inside the function
    # unless we mock read_file or pass it in. But we can verify the function ran.
    assert mock_chat.called
    args, _ = mock_chat.call_args
    # args[0] is system prompt, args[1] is user prompt
    user_prompt = args[1]
    assert "[STYLE:FEIGNED]" in user_prompt
