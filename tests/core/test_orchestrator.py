import pytest
from unittest.mock import patch, MagicMock
from app.core.orchestrator import handle_event
from app.api.schemas import HoneypotRequest, Message
from app.store.models import SessionState, Intelligence

@pytest.fixture
def mock_req():
    return HoneypotRequest(
        sessionId="test_session",
        message=Message(sender="scammer", text="hello +919876543210", timestamp=1234567890123),
        conversationHistory=[]
    )

@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.detect_scam")
@patch("app.core.orchestrator.choose_next_action")
@patch("app.core.orchestrator.generate_agent_reply")
@patch("app.core.orchestrator.should_finalize")
@patch("app.core.orchestrator.log")
def test_handle_event_intel_extraction(
    mock_log, mock_finalize, mock_reply, mock_choose, mock_detect, mock_save, mock_load, mock_req
):
    session = SessionState(sessionId="test_session")
    mock_load.return_value = session
    mock_detect.return_value = {"scamDetected": True, "confidence": 0.9, "scamType": "UPI_FRAUD"}
    mock_choose.return_value = {"intent": "INT_ACK_CONCERN", "bf_state": "BF_S1"}
    mock_reply.return_value = "Okay"
    mock_finalize.return_value = None

    res = handle_event(mock_req)
    
    assert res["reply"] == "Okay"
    # Verify intel was extracted from latest message
    assert "+919876543210" in session.extractedIntelligence.phoneNumbers
    assert mock_save.called

@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.detect_scam")
@patch("app.core.orchestrator.choose_next_action")
@patch("app.core.orchestrator.generate_agent_reply")
@patch("app.core.orchestrator.should_finalize")
@patch("app.core.orchestrator.log")
def test_handle_event_history_extraction(
    mock_log, mock_finalize, mock_reply, mock_choose, mock_detect, mock_save, mock_load
):
    # Use dicts in history as expected by the buggy patch
    mock_req = MagicMock()
    mock_req.message.text = "hello"
    mock_req.conversationHistory = [
        {"sender": "scammer", "text": "visit http://scam.link", "timestamp": 123},
        {"sender": "user", "text": "no", "timestamp": 124}
    ]
    session = SessionState(sessionId="test_session")
    mock_load.return_value = session
    mock_detect.return_value = {"scamDetected": True, "confidence": 0.9, "scamType": "PHISHING"}
    mock_choose.return_value = {"intent": "INT_ACK_CONCERN", "bf_state": "BF_S1"}
    mock_reply.return_value = "Okay"
    mock_finalize.return_value = None

    handle_event(mock_req)
    
    # Verify intel was extracted from history
    assert "http://scam.link" in session.extractedIntelligence.phishingLinks

@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.detect_scam")
@patch("app.core.orchestrator.choose_next_action")
@patch("app.core.orchestrator.generate_agent_reply")
@patch("app.core.orchestrator.should_finalize")
@patch("app.core.orchestrator.log")
def test_handle_event_persistence_and_counters(
    mock_log, mock_finalize, mock_reply, mock_choose, mock_detect, mock_save, mock_load, mock_req
):
    session = SessionState(sessionId="test_session")
    mock_load.return_value = session
    mock_detect.return_value = {"scamDetected": False, "confidence": 0.1}
    mock_choose.return_value = {"intent": "INT_ACK_CONCERN", "bf_state": "BF_S1"}
    mock_reply.return_value = "Agent reply here"
    mock_finalize.return_value = None

    handle_event(mock_req)
    
    # turnIndex should be 2 (1 for incoming, 1 for outgoing)
    assert session.turnIndex == 2
    
    # Check conversation
    assert len(session.conversation) == 2
    assert session.conversation[0]["sender"] == "scammer"
    assert session.conversation[0]["text"] == "hello +919876543210"
    assert session.conversation[0]["timestamp"] == 1234567890123
    assert session.conversation[1]["sender"] == "agent"
    assert session.conversation[1]["text"] == "Agent reply here"
    assert isinstance(session.conversation[1]["timestamp"], int)

    # Verify engagement_snapshot log
    # log is called for turn_processed and engagement_snapshot
    snapshot_call = next((c for c in mock_log.call_args_list if c.kwargs.get("event") == "engagement_snapshot"), None)
    assert snapshot_call is not None
    assert snapshot_call.kwargs["sessionId"] == "test_session"
    assert "durationSec" in snapshot_call.kwargs
    assert snapshot_call.kwargs["turns"] == 2


@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.detect_scam")
@patch("app.core.orchestrator.choose_next_action")
@patch("app.core.orchestrator.generate_agent_reply")
@patch("app.core.orchestrator.should_finalize")
@patch("app.core.orchestrator.log")
def test_handle_event_scam_type_unification(
    mock_log, mock_finalize, mock_reply, mock_choose, mock_detect, mock_save, mock_load, mock_req
):
    session = SessionState(sessionId="test_session")
    mock_load.return_value = session
    mock_detect.return_value = {"scamDetected": True, "confidence": 0.9, "scamType": "PHISHING"}
    mock_choose.return_value = {"intent": "INT_ACK_CONCERN", "bf_state": "BF_S1"}
    mock_reply.return_value = "Okay"
    mock_finalize.return_value = None

    handle_event(mock_req)
    
    # Verify scamType and scam_type are unified
    assert session.scamType == "PHISHING"
    assert session.scam_type == "PHISHING"

    # Test UNKNOWN fallback when scamType is None
    session.scamType = None
    mock_detect.return_value = {"scamDetected": False, "confidence": 0.1, "scamType": "UNKNOWN"}
    handle_event(mock_req)
    assert session.scam_type == "UNKNOWN"

def test_coerce_history_items():
    from app.core.orchestrator import _coerce_history_items
    
    # Valid history
    history = [
        {"sender": "scammer", "text": "hello", "timestamp": 1234567890123},
        {"sender": "user", "text": "hi", "timestamp": 1234567890124}
    ]
    coerced = _coerce_history_items(history)
    assert len(coerced) == 2
    assert coerced[0]["sender"] == "scammer"
    assert coerced[0]["timestamp"] == 1234567890123
    
    # Missing fields
    history_incomplete = [
        {"text": "no sender/ts"},
        {"sender": "user"}
    ]
    coerced_inc = _coerce_history_items(history_incomplete)
    assert len(coerced_inc) == 2
    assert coerced_inc[0]["sender"] == "scammer" # default
    assert isinstance(coerced_inc[0]["timestamp"], int)
    assert coerced_inc[1]["text"] == ""
    
    # Empty/None
    assert _coerce_history_items([]) == []
    assert _coerce_history_items(None) == []

@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.detect_scam")
@patch("app.core.orchestrator.choose_next_action")
@patch("app.core.orchestrator.generate_agent_reply")
@patch("app.core.orchestrator.should_finalize")
@patch("app.core.orchestrator.log")
def test_handle_event_bootstrap_from_history(
    mock_log, mock_finalize, mock_reply, mock_choose, mock_detect, mock_save, mock_load
):
    req = MagicMock()
    req.sessionId = "new_session"
    req.message.text = "current msg"
    req.message.timestamp = 5000
    req.conversationHistory = [
        {"sender": "scammer", "text": "past 1", "timestamp": 1000},
        {"sender": "user", "text": "past 2", "timestamp": 2000}
    ]
    
    # Empty session
    session = SessionState(sessionId="new_session")
    assert len(session.conversation) == 0
    mock_load.return_value = session
    
    mock_detect.return_value = {"scamDetected": False, "confidence": 0.1}
    mock_choose.return_value = {"intent": "INT_ACK_CONCERN", "bf_state": "BF_S1"}
    mock_reply.return_value = "Response"
    mock_finalize.return_value = None

    handle_event(req)
    
    # Should have: 2 from history + 1 current + 1 reply = 4 total
    assert len(session.conversation) == 4
    assert session.conversation[0]["text"] == "past 1"
    assert session.conversation[1]["text"] == "past 2"
    assert session.conversation[2]["text"] == "current msg"
    assert session.conversation[3]["text"] == "Response"
    assert session.turnIndex == 4

@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.detect_scam")
@patch("app.core.orchestrator.choose_next_action")
@patch("app.core.orchestrator.generate_agent_reply")
@patch("app.core.orchestrator.should_finalize")
@patch("app.core.orchestrator.log")
def test_handle_event_detector_persistence(
    mock_log, mock_finalize, mock_reply, mock_choose, mock_detect, mock_save, mock_load, mock_req
):
    session = SessionState(sessionId="test_session")
    mock_load.return_value = session
    
    # Mock detector returning specific values
    mock_detect.return_value = {
        "scamDetected": True,
        "confidence": 0.85,
        "scamType": "BANK_IMPERSONATION"
    }
    mock_choose.return_value = {"intent": "INT_ACK_CONCERN", "bf_state": "BF_S1"}
    mock_reply.return_value = "Okay"
    mock_finalize.return_value = None

    handle_event(mock_req)
    
    # Verify persistence to session
    assert session.scamDetected is True
    assert session.confidence == 0.85
    assert session.scamType == "BANK_IMPERSONATION"
    assert session.scam_type == "BANK_IMPERSONATION"
