from unittest.mock import patch, MagicMock
from app.store.models import SessionState
from app.api.admin_routes import get_session_snapshot

@patch("app.store.session_repo.get_redis")
def test_admin_session_snapshot_round_trip(mock_get_redis):
    # Mock Redis for save/load
    mock_redis = MagicMock()
    mock_get_redis.return_value = mock_redis
    
    # Mock load_session to return our object directly since we can't rely on real redis roundtrip
    with patch("app.api.admin_routes.load_session") as mock_load:
        s = SessionState(sessionId="s1")
        s.state = "READY_TO_REPORT"
        s.scamDetected = True
        s.scamType = "PHISHING"
        s.confidence = 0.9
        s.outboxEntry = {"attempts": 1, "history": [], "status": "pending"}
        s.cqQuestionsAsked = 3
        s.cqRelevantQuestions = 2
        s.cqRedFlagMentions = 4
        s.cqElicitationAttempts = 2
        s.turnsEngaged = 6
        s.engagementDurationSeconds = 42
        
        mock_load.return_value = s

        # Call the underlying function (bypass FastAPI Depends by using __wrapped__ if present)
        fn = getattr(get_session_snapshot, "__wrapped__", get_session_snapshot)
        snap = fn("s1")
        
        assert snap["sessionId"] == "s1"
        assert snap["scamDetected"] is True
        assert snap["scamType"] == "PHISHING"
        assert "cq" in snap and isinstance(snap["cq"], dict)
        assert "outboxLedger" in snap
        assert snap["turnsEngaged"] == 6
        assert snap["durationSec"] == 42
