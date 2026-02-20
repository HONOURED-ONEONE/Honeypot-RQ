import pytest
from unittest.mock import patch, MagicMock
import httpx
from app.llm.vllm_client import chat_completion

@patch("app.llm.vllm_client.VLLM_BASE_URL", "http://vllm:8000")
@patch("app.llm.vllm_client._client")
@patch("time.sleep")
def test_chat_completion_retry_success(mock_sleep, mock_client):
    # Mock a failure followed by success
    mock_resp_fail = MagicMock()
    mock_resp_fail.raise_for_status.side_effect = httpx.ReadTimeout("Timeout")
    
    mock_resp_ok = MagicMock()
    mock_resp_ok.json.return_value = {
        "choices": [{"message": {"content": "Hello response"}}]
    }
    
    mock_client.post.side_effect = [mock_resp_fail, mock_resp_ok]
    
    res = chat_completion("system", "user")
    assert res == "Hello response"
    assert mock_client.post.call_count == 2
    assert mock_sleep.called

@patch("app.llm.vllm_client.VLLM_BASE_URL", "http://vllm:8000")
@patch("app.llm.vllm_client._client")
@patch("time.sleep")
def test_chat_completion_all_fail(mock_sleep, mock_client):
    mock_client.post.side_effect = httpx.HTTPError("Fail")
    
    with pytest.raises(RuntimeError, match="vLLM call failed"):
        chat_completion("system", "user")
    
    # MAX_RETRIES defaults to 2
    assert mock_client.post.call_count == 2

@patch("app.llm.vllm_client.VLLM_BASE_URL", "http://vllm:8000")
@patch("app.llm.vllm_client._client")
@patch("time.sleep")
@patch("time.time")
def test_chat_completion_budget_exceeded(mock_time, mock_sleep, mock_client):
    # Mock time to simulate budget exhaustion
    # start, attempt 1, remaining check, backoff calc, attempt 2 (should not happen if budget exceeded)
    mock_time.side_effect = [0, 0, 25, 25, 25] # Budget is 24.0
    
    mock_client.post.side_effect = httpx.ReadTimeout("Timeout")
    
    with pytest.raises(RuntimeError, match="elapsed=25s"):
        chat_completion("system", "user")
    
    assert mock_client.post.call_count == 1
