import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.api.admin_routes import require_admin
from app.store.models import SessionState
from app.settings import settings

client = TestClient(app)

@pytest.fixture
def skip_auth():
    app.dependency_overrides[require_admin] = lambda: None
    yield
    app.dependency_overrides = {}

@patch("app.api.admin_routes.load_session")
def test_admin_session_snapshot(mock_load, skip_auth):
    s = SessionState(sessionId="test-123")
    s.scamDetected = True
    s.scamType = "UPI_FRAUD"
    s.cqQuestionsAsked = 5
    s.cqRelevantQuestions = 3
    s.cqRedFlagMentions = 2
    s.cqElicitationAttempts = 4
    s.finalizedAt = 1234567890
    s.engagementDurationSeconds = 60
    
    mock_load.return_value = s
    
    resp = client.get("/admin/session/test-123")
    assert resp.status_code == 200
    data = resp.json()
    assert data["sessionId"] == "test-123"
    assert data["scamDetected"] is True
    assert data["scamType"] == "UPI_FRAUD"
    assert data["cq"]["questionsAsked"] == 5
    assert data["durationSec"] == 60
    assert data["finalizedAt"] == 1234567890

@patch("app.observability.metrics.get_redis")
def test_slo_metrics(mock_get_redis, skip_auth):
    # Mock Redis responses for SLO
    mr = MagicMock()
    mock_get_redis.return_value = mr
    
    # metrics:finalize:success
    def get_side_effect(k):
        return {
            "metrics:finalize:success": "10",
            "metrics:finalize:attempt": "12",
            "metrics:callback:delivered": "9",
            "metrics:callback:attempts": "10",
        }.get(k)
    mr.get.side_effect = get_side_effect
    
    # samples (lrange)
    def lrange_side_effect(k, start, end):
        return {
            "metrics:finalize:latencies": ["1000", "2000", "3000"],
            "metrics:callback:latencies": ["100", "200", "300"],
            "metrics:callback:failed_recent": ["sess-1"],
        }.get(k, [])
    mr.lrange.side_effect = lrange_side_effect
    
    resp = client.get("/admin/slo")
    assert resp.status_code == 200
    data = resp.json()
    
    # 10/12 * 100 = 83.333...
    assert abs(data["finalize_success_rate"] - 83.33) < 0.1
    # 9/10 * 100 = 90.0
    assert data["callback_delivery_success_rate"] == 90.0
    # p50 of [1000, 2000, 3000] ms -> 2.0 s
    assert data["p50_finalize_latency"] == 2.0
    assert "sess-1" in data["recent_failed_callbacks"]

def test_rbac_enforcement():
    # Ensure RBAC is enabled for this test
    # We patch settings directly on admin_routes module if possible, or global settings
    with patch.object(settings, "ADMIN_RBAC_ENABLED", True), \
         patch.object(settings, "ADMIN_API_KEY", "secret"):
        
        # Ensure no override
        app.dependency_overrides = {}
        
        # No header -> 403
        resp = client.get("/admin/slo")
        assert resp.status_code == 403
        
        # Wrong header -> 403
        resp = client.get("/admin/slo", headers={"x-admin-key": "wrong"})
        assert resp.status_code == 403
        
        # Correct header -> 200 (need to mock redis again to avoid crash)
        with patch("app.observability.metrics.get_redis"):
            resp = client.get("/admin/slo", headers={"x-admin-key": "secret"})
            assert resp.status_code == 200

@patch("app.core.orchestrator.load_session")
@patch("app.core.orchestrator.save_session")
@patch("app.core.orchestrator.session_lock")
def test_finalize_invariant(mock_lock, mock_save, mock_load):
    # Mock session_lock context manager
    mock_lock.return_value.__enter__.return_value = None
    # Import inside to avoid patching issues
    from app.core.orchestrator import handle_event
    from app.api.schemas import HoneypotRequest, Message
    
    session = SessionState(sessionId="finalized_sess")
    session.state = "FINALIZED"
    session.postscript = []
    
    mock_load.return_value = session
    
    req = HoneypotRequest(
        sessionId="finalized_sess",
        message=Message(sender="scammer", text="Are you still there?", timestamp=123),
    )
    
    resp = handle_event(req)
    
    # Should return standard closed message
    assert "Session ended" in resp["reply"]
    
    # Should NOT process detection or reply generation (not mocked here, so if called, it would crash or we'd need more mocks)
    # But mainly, it should append to postscript
    assert len(session.postscript) == 1
    assert session.postscript[0]["text"] == "Are you still there?"
    assert session.postscript[0]["ignored"] is True
    
    # Should save the session with updated postscript
    mock_save.assert_called_with(session)
