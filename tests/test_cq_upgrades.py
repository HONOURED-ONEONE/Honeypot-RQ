import pytest
from unittest.mock import patch, MagicMock
from app.core.orchestrator import handle_event
from app.api.schemas import HoneypotRequest, Message
from app.store.models import SessionState, Intelligence
from app.core.broken_flow_constants import INT_ASK_TICKET_REF, INT_ASK_OFFICIAL_WEBSITE
from app.core.finalize import should_finalize
from app.core.broken_flow_controller import choose_next_action

class MockSettings:
    CQ_MIN_TURNS = 8
    CQ_MIN_REDFLAGS = 5
    CQ_MIN_RELEVANT_QUESTIONS = 3
    CQ_MAX_ELICITATION_ATTEMPTS = 5
    FINALIZE_MIN_IOC_CATEGORIES = 2
    BF_NO_PROGRESS_TURNS = 3
    BF_REPEAT_LIMIT = 2
    SCAM_THRESHOLD = 0.75
    MAX_CONTEXT_MESSAGES = 10
    DETECTOR_CUMULATIVE_MODE = True
    DETECTOR_CUMULATIVE_WINDOW = 6
    DETECTOR_CUMULATIVE_SCORE = 0.62
    DETECTOR_MAX_SCORE = 0.75

@pytest.fixture
def mock_settings():
    return MockSettings()

@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.detect_scam")
@patch("app.core.orchestrator.choose_next_action")
@patch("app.core.orchestrator.generate_agent_reply")
@patch("app.core.orchestrator.should_finalize")
@patch("app.core.orchestrator.settings", MockSettings())
def test_cq_counters_increment(
    mock_finalize, mock_reply, mock_choose, mock_detect, mock_save, mock_load
):
    session = SessionState(sessionId="test_cq")
    mock_load.return_value = session
    mock_detect.return_value = {"scamDetected": True, "confidence": 0.9, "scamType": "UPI_FRAUD"}
    # Investigative intent
    mock_choose.return_value = {"intent": INT_ASK_TICKET_REF, "bf_state": "BF_S1"}
    # Reply with a question
    mock_reply.return_value = "What is your ticket ID?"
    mock_finalize.return_value = None

    req = HoneypotRequest(
        sessionId="test_cq",
        message=Message(sender="scammer", text="give me money", timestamp=1234567890123),
        conversationHistory=[]
    )

    handle_event(req)

    # Verify counters
    assert session.cqQuestionsAsked == 1
    assert session.cqRelevantQuestions == 1
    assert session.cqElicitationAttempts == 1
    # Red flag identification happens if lastRedFlagTag is not NONE
    # handle_event calls choose_red_flag which sets lastRedFlagTag
    assert session.cqRedFlagMentions == 1

def test_finalize_min_turn_gate(mock_settings):
    session = SessionState(sessionId="test_gate")
    session.scamDetected = True
    session.extractedIntelligence.phoneNumbers = ["123"]
    session.extractedIntelligence.phishingLinks = ["http"]
    
    with patch("app.core.finalize.settings", mock_settings):
        # turnIndex = 0 < CQ_MIN_TURNS = 8
        assert should_finalize(session) is None
        
        session.turnIndex = 8
        assert should_finalize(session) == "ioc_milestone"

def test_controller_cq_catchup_rail(mock_settings):
    session = SessionState(sessionId="test_rail")
    session.turnIndex = 5 # approaching target (8 - 3 = 5)
    session.cqRelevantQuestions = 0
    intel_dict = {}
    
    with patch("app.core.broken_flow_controller.default_settings", mock_settings):
        # Should force an investigative intent
        action = choose_next_action(session, "hello", intel_dict, {}, mock_settings)
        assert action["reason"] == "cq_catchup_investigative"
        # Since intel_dict is empty, it should pick highest priority missing intel target
        # which is phishingLinks -> INT_ASK_OFFICIAL_WEBSITE
        assert action["intent"] == INT_ASK_OFFICIAL_WEBSITE

@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.detect_scam")
@patch("app.core.orchestrator.choose_next_action")
@patch("app.core.orchestrator.generate_agent_reply")
@patch("app.core.orchestrator.should_finalize")
@patch("app.core.orchestrator.settings", MockSettings())
@patch("app.core.orchestrator.choose_red_flag")
def test_force_flag_logic(
    mock_red_flag, mock_finalize, mock_reply, mock_choose, mock_detect, mock_save, mock_load
):
    session = SessionState(sessionId="test_force")
    session.scamDetected = True
    session.cqRedFlagMentions = 0
    session.turnIndex = 2
    mock_load.return_value = session
    mock_detect.return_value = {"scamDetected": True, "confidence": 0.9}
    mock_choose.return_value = {"intent": "INT_ACK_CONCERN"}
    mock_reply.return_value = "Reply"
    mock_finalize.return_value = None
    
    # We want to check if force_flag=True is passed to choose_red_flag
    req = HoneypotRequest(
        sessionId="test_force",
        message=Message(sender="scammer", text="URGENT!!!", timestamp=1234567890123),
        conversationHistory=[]
    )
    
    handle_event(req)
    
    # Check if choose_red_flag was called with force_flag=True
    # It's the 6th positional arg or a kwarg
    args, kwargs = mock_red_flag.call_args
    assert kwargs.get("force_flag") is True or args[4] is True
