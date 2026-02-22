import json
import time
from unittest.mock import patch, MagicMock
import pytest
from app.store.models import SessionState
from app.callback.outbox import process_outbox_entry

@pytest.fixture
def mock_session():
    s = SessionState(sessionId="test-session")
    s.finalReport = {"sessionId": "test-session", "data": "foo"}
    s.reportId = "test-session:1"
    return s

def test_outbox_process_success(mock_session):
    with patch("app.callback.outbox.settings") as mock_settings, \
         patch("app.store.session_repo.load_session") as mock_load, \
         patch("app.store.session_repo.save_session") as mock_save, \
         patch("app.callback.client.send_final_result_http") as mock_send, \
         patch("app.store.redis_conn.Redis"): # fallback safety
        
        mock_settings.ENABLE_OUTBOX = True
        mock_settings.CALLBACK_MAX_ATTEMPTS = 3
        mock_load.return_value = mock_session
        mock_send.return_value = (True, 200, None)

        # 1. First attempt
        done = process_outbox_entry("test-session")
        
        assert done is True
        assert mock_send.called
        assert mock_session.callbackStatus == "sent"
        assert mock_session.outboxEntry["status"] == "delivered"
        assert mock_session.outboxEntry["attempts"] == 1

def test_outbox_process_retry(mock_session):
    with patch("app.callback.outbox.settings") as mock_settings, \
         patch("app.store.session_repo.load_session") as mock_load, \
         patch("app.store.session_repo.save_session") as mock_save, \
         patch("app.callback.client.send_final_result_http") as mock_send, \
         patch("app.store.redis_conn.Redis"):

        mock_settings.ENABLE_OUTBOX = True
        mock_load.return_value = mock_session
        mock_send.return_value = (False, 500, "Server Error")

        # 1. First attempt (fails)
        done = process_outbox_entry("test-session")
        
        assert done is False
        assert mock_session.outboxEntry["status"] == "pending"
        assert mock_session.outboxEntry["attempts"] == 1
        assert mock_session.outboxEntry["nextAttemptAt"] > time.time() * 1000

        # 2. Immediate retry (should be skipped due to backoff)
        mock_send.reset_mock()
        done2 = process_outbox_entry("test-session")
        assert done2 is False
        assert not mock_send.called  # skipped

def test_outbox_terminal_failure(mock_session):
    with patch("app.callback.outbox.settings") as mock_settings, \
         patch("app.store.session_repo.load_session") as mock_load, \
         patch("app.store.session_repo.save_session") as mock_save, \
         patch("app.callback.client.send_final_result_http") as mock_send, \
         patch("app.store.redis_conn.Redis"):

        mock_settings.ENABLE_OUTBOX = True
        mock_load.return_value = mock_session
        mock_send.return_value = (False, 400, "Bad Request")

        done = process_outbox_entry("test-session")
        
        assert done is True  # Terminal
        assert mock_session.outboxEntry["status"] == "failed:terminal"
