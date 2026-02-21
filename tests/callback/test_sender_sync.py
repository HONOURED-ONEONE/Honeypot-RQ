import pytest
from unittest.mock import MagicMock, patch
import httpx
from app.callback.sender import send_final_result_sync
from app.store.models import SessionState, Intelligence
from app.settings import settings

@pytest.fixture
def mock_session():
    return SessionState(
        sessionId="test-session-123",
        scamDetected=True,
        callbackStatus="none",
        extractedIntelligence=Intelligence()
    )

@patch("app.callback.sender.load_session")
@patch("app.callback.sender.save_session")
@patch("httpx.Client.post")
def test_send_final_result_sync_success(mock_post, mock_save, mock_load, mock_session):
    # Setup
    mock_load.return_value = mock_session
    settings.GUVI_CALLBACK_URL = "http://example.com/callback"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response
    
    # Execute
    result = send_final_result_sync("test-session-123", deadline_sec=5.0)
    
    # Verify
    assert result is True
    assert mock_session.callbackStatus == "sent"
    assert mock_session.state == "REPORTED"
    mock_post.assert_called_once()

@patch("app.callback.sender.load_session")
@patch("app.callback.sender.save_session")
@patch("httpx.Client.post")
def test_send_final_result_sync_non_2xx(mock_post, mock_save, mock_load, mock_session):
    # Setup
    mock_load.return_value = mock_session
    settings.GUVI_CALLBACK_URL = "http://example.com/callback"
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_post.return_value = mock_response
    
    # Execute (with 0 retries to speed up)
    result = send_final_result_sync("test-session-123", deadline_sec=1.0, max_retries=0)
    
    # Verify
    assert result is False
    assert mock_session.callbackStatus == "failed"
    mock_post.assert_called_once()

@patch("app.callback.sender.load_session")
@patch("app.callback.sender.save_session")
@patch("httpx.Client.post")
def test_send_final_result_sync_timeout(mock_post, mock_save, mock_load, mock_session):
    # Setup
    mock_load.return_value = mock_session
    settings.GUVI_CALLBACK_URL = "http://example.com/callback"
    mock_post.side_effect = httpx.ReadTimeout("Timeout")
    
    # Execute
    result = send_final_result_sync("test-session-123", deadline_sec=0.1, max_retries=0)
    
    # Verify
    assert result is False
    assert mock_session.callbackStatus == "failed"

@patch("app.callback.sender.log")
def test_send_final_result_sync_no_url(mock_log, mock_session):
    # Setup
    settings.GUVI_CALLBACK_URL = ""
    
    # Execute
    result = send_final_result_sync("test-session-123")
    
    # Verify
    assert result is False
    mock_log.assert_called_with(event="final_output_sync_skipped_no_url", sessionId="test-session-123")
