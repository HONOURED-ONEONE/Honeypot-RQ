import pytest
from unittest.mock import patch, MagicMock
from app.core.guvi_callback import enqueue_guvi_final_result, _build_payload
from app.queue.jobs import send_final_callback_job
from app.store.models import SessionState

def test_build_payload():
    session = SessionState(sessionId="test_session", turnIndex=5, scamDetected=True)
    session.extractedIntelligence.phoneNumbers = ["123"]
    payload = _build_payload(session, finalize_reason="milestone")
    
    assert payload["sessionId"] == "test_session"
    assert payload["scamDetected"] is True
    assert payload["totalMessagesExchanged"] == 5
    assert payload["extractedIntelligence"]["phoneNumbers"] == ["123"]

@patch("app.core.guvi_callback.Queue")
@patch("app.core.guvi_callback.get_redis")
def test_enqueue_guvi_final_result(mock_get_redis, mock_queue_class):
    mock_queue = MagicMock()
    mock_queue_class.return_value = mock_queue
    
    session = SessionState(sessionId="test_session")
    enqueue_guvi_final_result(session)
    
    assert mock_queue.enqueue.called

@patch("app.queue.jobs.log")
@patch("app.queue.jobs.send_final_result")
def test_send_final_callback_job(mock_send, mock_log):
    send_final_callback_job("test_session")
    mock_send.assert_called_with("test_session")
    mock_log.assert_called_once()
    assert mock_log.call_args.kwargs["event"] == "callback_job_start"
