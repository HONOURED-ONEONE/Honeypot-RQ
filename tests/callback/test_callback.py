import pytest
from unittest.mock import patch, MagicMock
import httpx
from app.callback.client import send_final_result
from app.store.models import SessionState

@patch("app.callback.client.settings")
@patch("app.callback.client.load_session")
@patch("app.callback.client.save_session")
@patch("app.callback.client.log")
@patch("httpx.Client")
def test_send_final_result_success(mock_client_class, mock_log, mock_save, mock_load, mock_settings):
    mock_settings.GUVI_CALLBACK_URL = "http://callback.url"
    mock_settings.CALLBACK_TIMEOUT_SEC = 5

    session = SessionState(sessionId="test_session")
    mock_load.return_value = session

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_client.post.return_value = mock_resp
    mock_client_class.return_value = mock_client

    res = send_final_result("test_session")

    assert res is True
    assert session.callbackStatus == "sent"
    assert session.state == "REPORTED"
    assert mock_save.called
    # Check logs
    assert any(c.kwargs.get("event") == "callback_send_attempt" for c in mock_log.call_args_list)
    assert any(c.kwargs.get("event") == "callback_send_success" for c in mock_log.call_args_list)

@patch("app.callback.client.settings")
@patch("app.callback.client.load_session")
@patch("app.callback.client.save_session")
@patch("app.callback.client.log")
@patch("httpx.Client")
def test_send_final_result_failure(mock_client_class, mock_log, mock_save, mock_load, mock_settings):
    mock_settings.GUVI_CALLBACK_URL = "http://callback.url"
    mock_settings.CALLBACK_TIMEOUT_SEC = 5

    session = SessionState(sessionId="test_session")
    mock_load.return_value = session

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Error"
    mock_client.post.return_value = mock_resp
    mock_client_class.return_value = mock_client

    with pytest.raises(RuntimeError, match="Callback failed: 500"):
        send_final_result("test_session")

    assert session.callbackStatus == "failed"
    assert mock_save.called
    # Check logs
    assert any(c.kwargs.get("event") == "callback_send_attempt" for c in mock_log.call_args_list)
    assert any(c.kwargs.get("event") == "callback_send_failed" for c in mock_log.call_args_list)

@patch("app.callback.client.settings")
@patch("app.callback.client.load_session")
@patch("app.callback.client.save_session")
@patch("app.callback.client.log")
@patch("httpx.Client")
def test_send_final_result_exception(mock_client_class, mock_log, mock_save, mock_load, mock_settings):
    mock_settings.GUVI_CALLBACK_URL = "http://callback.url"
    mock_settings.CALLBACK_TIMEOUT_SEC = 5

    session = SessionState(sessionId="test_session")
    mock_load.return_value = session

    mock_client = MagicMock()
    mock_client.__enter__.side_effect = Exception("Network error")
    mock_client_class.return_value = mock_client

    with pytest.raises(Exception, match="Network error"):
        send_final_result("test_session")

    assert session.callbackStatus == "failed"
    assert mock_save.called
    # Check logs
    assert any(c.kwargs.get("event") == "callback_send_attempt" for c in mock_log.call_args_list)
    assert any(c.kwargs.get("event") == "callback_send_exception" for c in mock_log.call_args_list)
