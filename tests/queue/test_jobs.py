import pytest
from unittest.mock import patch, MagicMock
from app.core.guvi_callback import enqueue_guvi_final_result
from app.callback.payloads import build_final_payload
from app.queue.jobs import send_final_callback_job
from app.store.models import SessionState

def test_build_payload():
    session = SessionState(sessionId="test_session", turnIndex=5, scamDetected=True)
    session.extractedIntelligence.phoneNumbers = ["123"]
    # build_final_payload doesn't take finalize_reason directly anymore?
    # Let's check signature in app/callback/payloads.py
    # content from prompt: def build_final_payload(session: SessionState) -> dict:
    payload = build_final_payload(session)
    
    assert payload["sessionId"] == "test_session"
    assert payload["scamDetected"] is True
    assert payload["totalMessagesExchanged"] == 5
    assert payload["extractedIntelligence"]["phoneNumbers"] == ["123"]

@patch("app.core.guvi_callback.Queue")
def test_enqueue_guvi_final_result(mock_queue_class):
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
