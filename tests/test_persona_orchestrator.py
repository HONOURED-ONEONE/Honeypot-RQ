import pytest
from unittest.mock import MagicMock, patch
from app.core.orchestrator import handle_event
from app.store.models import SessionState
from app.api.schemas import HoneypotRequest, Message

@pytest.fixture
def mock_session_repo():
    with patch("app.core.orchestrator.load_session") as mock_load:
        with patch("app.core.orchestrator.save_session") as mock_save:
            yield mock_load, mock_save

@pytest.fixture
def mock_llm():
    with patch("app.core.orchestrator.detect_scam") as mock_detect:
        with patch("app.core.orchestrator.generate_agent_reply") as mock_reply:
            yield mock_detect, mock_reply

def test_orchestrator_persona_escalation(mock_session_repo, mock_llm):
    mock_load, mock_save = mock_session_repo
    mock_detect, mock_reply = mock_llm
    
    # 1. Normal mode (no escalation)
    session = SessionState(sessionId="test-session")
    session.bf_no_progress_count = 0
    session.bf_repeat_count = 0
    session.bf_state = "BF_S1"
    mock_load.return_value = session
    mock_detect.return_value = {"scamDetected": True, "confidence": 0.9, "scamType": "BANK_IMPERSONATION"}
    mock_reply.return_value = "Normal reply?"

    req = HoneypotRequest(
        sessionId="test-session",
        message=Message(sender="scammer", text="give me otp", timestamp=123456789)
    )
    
    handle_event(req)
    
    # Check that choose_red_flag was called with escalation=False
    # Since we can't easily mock choose_red_flag because it's imported as a function,
    # we check the session state which is updated by orchestrator.
    assert session.lastPersonaStyle in ["SKEPTICAL", "CONFUSION"]

    # 2. Escalation mode (high no_progress_count)
    session = SessionState(sessionId="test-session")
    session.bf_no_progress_count = 5 # settings.BF_NO_PROGRESS_TURNS is 3 by default
    session.bf_repeat_count = 0
    session.bf_state = "BF_S1"
    mock_load.return_value = session
    
    handle_event(req)
    assert session.lastPersonaStyle in ["TECH_FRICTION", "DELAY"]

    # 3. Escalation mode (high repeat_count)
    session = SessionState(sessionId="test-session")
    session.bf_no_progress_count = 0
    session.bf_repeat_count = 3 # settings.BF_REPEAT_LIMIT is 2 by default
    session.bf_state = "BF_S1"
    mock_load.return_value = session
    
    handle_event(req)
    assert session.lastPersonaStyle in ["TECH_FRICTION", "DELAY"]

    # 4. Escalation mode (state BF_S4)
    session = SessionState(sessionId="test-session")
    session.bf_no_progress_count = 0
    session.bf_repeat_count = 0
    session.bf_state = "BF_S4"
    mock_load.return_value = session
    
    handle_event(req)
    assert session.lastPersonaStyle in ["TECH_FRICTION", "DELAY"]
