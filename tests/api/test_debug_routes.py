import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app
from app.settings import settings

from app.api.auth import require_api_key

client = TestClient(app)

@pytest.fixture(autouse=True)
def skip_auth():
    app.dependency_overrides[require_api_key] = lambda: None
    yield
    app.dependency_overrides = {}

@patch("app.api.routes.get_redis")
def test_debug_last_callback_payload_enabled(mock_get_redis):
    # Mock settings
    with patch.object(settings, "STORE_LAST_CALLBACK_PAYLOAD", True):
        mock_redis = MagicMock()
        mock_get_redis.return_value = mock_redis
        
        # Scenario 1: Payload exists
        mock_redis.get.return_value = '{"sessionId": "test_sid", "scamDetected": true}'
        response = client.get("/debug/last-callback/test_sid", headers={"x-api-key": "test"})
        assert response.status_code == 200
        assert response.json() == {
            "sessionId": "test_sid",
            "payload": {"sessionId": "test_sid", "scamDetected": True}
        }
        mock_redis.get.assert_called_with("session:test_sid:last_callback_payload")

        # Scenario 2: Payload missing
        mock_redis.get.return_value = None
        response = client.get("/debug/last-callback/missing_sid", headers={"x-api-key": "test"})
        assert response.status_code == 200
        assert response.json() == {"sessionId": "missing_sid", "payload": None}

def test_debug_last_callback_payload_disabled():
    with patch.object(settings, "STORE_LAST_CALLBACK_PAYLOAD", False):
        response = client.get("/debug/last-callback/test_sid", headers={"x-api-key": "test"})
        assert response.status_code == 200
        assert response.json() == {"enabled": False}
