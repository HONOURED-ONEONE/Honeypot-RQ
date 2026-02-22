import pytest
from unittest.mock import patch, MagicMock
from app.callback.outbox import process_outbox_entry
from app.store.models import SessionState

@patch("app.callback.outbox.settings")
@patch("app.callback.outbox.session_repo")
@patch("app.callback.outbox.callback_client")
@patch("app.callback.outbox.metrics")
@patch("app.callback.outbox.get_redis")
def test_process_outbox_entry_success(mock_redis, mock_metrics, mock_client, mock_repo, mock_settings):
    # Setup
    mock_settings.ENABLE_OUTBOX = True
    mock_settings.CALLBACK_MAX_ATTEMPTS = 3
    mock_settings.CALLBACK_TIMEOUT_SEC = 5.0
    mock_settings.CALLBACK_PAYLOAD_VERSION = "1.1"

    session = SessionState(sessionId="test_sess")
    session.finalReport = {"some": "data"}
    session.reportId = "rep1"
    session.outboxEntry = {"attempts": 0, "status": "pending", "nextAttemptAt": 0}
    
    mock_repo.load_session.return_value = session
    
    # Mock successful send
    mock_client.send_final_result_http.return_value = (True, 200, None)
    
    # Act
    success = process_outbox_entry("test_sess")
    
    # Assert
    assert success is True
    assert session.callbackStatus == "sent"
    assert session.outboxEntry["status"] == "delivered"
    assert session.outboxEntry["attempts"] == 1
    assert session.outboxEntry["history"][0]["version"] == "1.1"
    
    mock_metrics.increment_callback_attempt.assert_called_once()
    mock_metrics.increment_callback_delivered.assert_called_once()
    mock_repo.save_session.assert_called_with(session)

@patch("app.callback.outbox.settings")
@patch("app.callback.outbox.session_repo")
@patch("app.callback.outbox.callback_client")
@patch("app.callback.outbox.metrics")
def test_process_outbox_entry_retry(mock_metrics, mock_client, mock_repo, mock_settings):
    # Setup
    mock_settings.ENABLE_OUTBOX = True
    
    session = SessionState(sessionId="test_sess")
    session.finalReport = {"some": "data"}
    session.outboxEntry = {"attempts": 0, "status": "pending", "nextAttemptAt": 0}
    mock_repo.load_session.return_value = session
    
    # Mock failure (retryable)
    mock_client.send_final_result_http.return_value = (False, 503, "Service Unavailable")
    
    # Act
    success = process_outbox_entry("test_sess")
    
    # Assert
    assert success is False
    assert session.outboxEntry["status"] == "pending"
    assert session.outboxEntry["attempts"] == 1
    assert session.outboxEntry["nextAttemptAt"] > 0
    
    mock_metrics.increment_callback_attempt.assert_called_once()
    mock_metrics.record_failed_callback.assert_called_once()
