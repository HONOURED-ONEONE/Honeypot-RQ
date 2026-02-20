import pytest
from app.store.session_repo import _migrate_session_data, _filter_session_kwargs, load_session
from app.store.models import SessionState
from unittest.mock import patch, MagicMock
import json

def test_migrate_session_data_turn_index():
    data = {
        "totalMessagesExchanged": 5,
        "conversation": [{"text": "hi"}, {"text": "hello"}]
    }
    migrated = _migrate_session_data(data)
    assert migrated["turnIndex"] == 5
    assert migrated["totalMessagesExchanged"] == 5

def test_migrate_session_data_no_turn_index_use_convo():
    data = {
        "totalMessagesExchanged": 0,
        "conversation": [{"text": "hi"}, {"text": "hello"}]
    }
    migrated = _migrate_session_data(data)
    assert migrated["turnIndex"] == 2
    assert migrated["totalMessagesExchanged"] == 2

def test_migrate_session_data_scam_type_harmonization():
    data = {
        "scam_type": "UPI_FRAUD"
    }
    migrated = _migrate_session_data(data)
    assert migrated["scamType"] == "UPI_FRAUD"
    assert "scam_type" not in migrated

def test_migrate_session_data_purge_undeclared():
    from app.store.models import Intelligence, SessionState
    data = {
        "sessionId": "test",
        "turnIndex": 5,
        "legacy_junk": "foo",
        "extractedIntelligence": {
            "bankAccounts": ["123"],
            "nested_junk": "bar"
        }
    }
    migrated = _migrate_session_data(data)
    
    # 1) Top-level junk should be purged
    assert "legacy_junk" not in migrated
    assert "sessionId" in migrated
    assert "turnIndex" in migrated
    
    # 2) Nested junk should be purged
    ei = migrated.get("extractedIntelligence")
    assert isinstance(ei, dict)
    assert "bankAccounts" in ei
    assert "nested_junk" not in ei

@patch("app.store.session_repo.get_redis")
def test_load_session_purges_junk(mock_get_redis):
    mock_redis = MagicMock()
    mock_get_redis.return_value = mock_redis
    
    junk_data = {
        "sessionId": "test-junk",
        "turnIndex": 5,
        "legacy_junk": "foo",
        "extractedIntelligence": {
            "bankAccounts": ["123"],
            "nested_junk": "bar"
        }
    }
    mock_redis.get.return_value = json.dumps(junk_data)
    
    # In current state, this might crash because rehydration happens before migration
    # Intelligence(**{"bankAccounts": ["123"], "nested_junk": "bar"}) will raise TypeError
    try:
        session = load_session("test-junk")
        assert session.sessionId == "test-junk"
        assert "legacy_junk" not in session.__dict__
        # Check Intelligence object
        assert "nested_junk" not in session.extractedIntelligence.__dict__
    except TypeError as e:
        pytest.fail(f"load_session failed due to unexpected field: {e}")

def test_filter_session_kwargs():
    data = {
        "sessionId": "test",
        "unknown_field": "val",
        "bf_state": "BF_S1"
    }
    filtered = _filter_session_kwargs(data)
    assert "sessionId" in filtered
    assert "bf_state" in filtered
    assert "unknown_field" not in filtered

def test_session_state_post_init_sync():
    s = SessionState(sessionId="test", totalMessagesExchanged=10)
    # turnIndex defaults to 0, but __post_init__ should sync it
    assert s.turnIndex == 10
    
    s2 = SessionState(sessionId="test2", turnIndex=5)
    assert s2.totalMessagesExchanged == 5

@patch("app.store.session_repo.log")
def test_migrate_session_data_logging(mock_log):
    data = {
        "sessionId": "test-log",
        "scam_type": "UPI_FRAUD",
        "legacy_junk": "foo",
        "extractedIntelligence": {
            "nested_junk": "bar"
        }
    }
    _migrate_session_data(data)
    
    # Verify log was called with expected fields
    mock_log.assert_called_once()
    args, kwargs = mock_log.call_args
    assert kwargs["event"] == "session_migrated"
    assert kwargs["scamType"] == "UPI_FRAUD"
    assert kwargs["backfilledScamType"] is True
    assert kwargs["droppedLegacyScamType"] is True
    assert kwargs["removedTopFields"] == 1
    assert kwargs["removedIntelFields"] == 1
