import pytest
from unittest.mock import MagicMock, patch
from app.store.models import SessionState, Intelligence
from app.core.guvi_callback import enqueue_guvi_final_result
from app.settings import settings

@pytest.fixture
def mock_session():
    return SessionState(
        sessionId="test-session-123",
        scamDetected=True,
        callbackStatus="none",
        extractedIntelligence=Intelligence()
    )

@patch("app.core.guvi_callback.send_final_result_sync")
@patch("app.core.guvi_callback.get_queue")
def test_enqueue_hybrid_mode_sync_success(mock_get_queue, mock_send_sync, mock_session):
    # Setup
    settings.FINAL_OUTPUT_MODE = "hybrid"
    mock_send_sync.return_value = True
    
    # Execute
    enqueue_guvi_final_result(mock_session, finalize_reason="test")
    
    # Verify
    mock_send_sync.assert_called_once()
    mock_get_queue.assert_not_called()
    assert mock_session.callbackStatus == "sent"

@patch("app.core.guvi_callback.send_final_result_sync")
@patch("app.core.guvi_callback.get_queue")
def test_enqueue_hybrid_mode_sync_fails_fallback_to_rq(mock_get_queue, mock_send_sync, mock_session):
    # Setup
    settings.FINAL_OUTPUT_MODE = "hybrid"
    mock_send_sync.return_value = False
    mock_q = MagicMock()
    mock_get_queue.return_value = mock_q
    
    # Execute
    enqueue_guvi_final_result(mock_session, finalize_reason="test")
    
    # Verify
    mock_send_sync.assert_called_once()
    mock_get_queue.assert_called_once()
    mock_q.enqueue.assert_called_once()
    assert mock_session.callbackStatus == "queued"

@patch("app.core.guvi_callback.send_final_result_sync")
@patch("app.core.guvi_callback.get_queue")
def test_enqueue_rq_mode_skips_sync(mock_get_queue, mock_send_sync, mock_session):
    # Setup
    settings.FINAL_OUTPUT_MODE = "rq"
    mock_q = MagicMock()
    mock_get_queue.return_value = mock_q
    
    # Execute
    enqueue_guvi_final_result(mock_session, finalize_reason="test")
    
    # Verify
    mock_send_sync.assert_not_called()
    mock_get_queue.assert_called_once()
    assert mock_session.callbackStatus == "queued"

@patch("app.core.guvi_callback.send_final_result_sync")
def test_enqueue_idempotency(mock_send_sync, mock_session):
    # Setup
    mock_session.callbackStatus = "sent"
    
    # Execute
    enqueue_guvi_final_result(mock_session)
    
    # Verify
    mock_send_sync.assert_not_called()
