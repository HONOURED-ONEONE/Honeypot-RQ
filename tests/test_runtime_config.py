import pytest
import json
import time
from unittest.mock import MagicMock, patch
from app.intel.artifact_registry import ArtifactRegistry, ArtifactSpec

def test_registry_overrides_application():
    registry = ArtifactRegistry()
    
    # Mock artifact
    spec = ArtifactSpec(
        key="test_art",
        extract_fn=lambda x: [x],
        priority=10,
        ask_enabled=True,
        passive_only=False
    )
    registry.register(spec)
    
    # Verify defaults captured
    assert registry._defaults["test_art"]["priority"] == 10
    
    # Apply overrides
    overrides = {
        "test_art": {
            "priority": 50,
            "enabled": False,
            "ask_enabled": False,
            "passive_only": True
        },
        "unknown_art": { "priority": 100 } # Should be ignored safely
    }
    
    registry._apply_overrides(overrides)
    
    assert spec.priority == 50
    assert spec.enabled is False
    assert spec.ask_enabled is False
    assert spec.passive_only is True
    
    # Revert by applying empty overrides
    registry._apply_overrides({})
    assert spec.priority == 10
    assert spec.enabled is True
    assert spec.ask_enabled is True
    assert spec.passive_only is False

@patch("app.store.redis_conn.get_redis")
def test_maybe_refresh_overrides(mock_get_redis):
    registry = ArtifactRegistry()
    
    # We need to mock settings too because _maybe_refresh_overrides imports it
    with patch("app.settings.settings") as mock_settings:
        mock_settings.REGISTRY_TTL = 0
        mock_settings.REGISTRY_OVERRIDES_KEY = "test:overrides"
        
        spec = ArtifactSpec(key="art", extract_fn=lambda x: [])
        registry.register(spec)
        
        mock_redis = MagicMock()
        mock_get_redis.return_value = mock_redis
        
        # Case 1: Redis has data
        mock_redis.get.return_value = json.dumps({"art": {"priority": 99}})
        registry._maybe_refresh_overrides()
        assert spec.priority == 99
        
        # Case 2: Redis key missing (should revert to default)
        mock_redis.get.return_value = None
        registry._maybe_refresh_overrides()
        assert spec.priority == 0 # default from register()

def test_extract_all_respects_enabled():
    registry = ArtifactRegistry()
    # Mock _maybe_refresh_overrides to do nothing
    registry._maybe_refresh_overrides = lambda: None
    
    spec = ArtifactSpec(key="art", extract_fn=lambda x: ["match"])
    registry.register(spec)
    
    # Enabled
    res = registry.extract_all("text")
    assert "match" in res["art"]
    
    # Disabled
    spec.enabled = False
    res = registry.extract_all("text")
    assert "art" in res
    assert res["art"] == []

@patch("app.store.redis_conn.get_redis")
def test_controller_respects_overrides(mock_get_redis):
    from app.core.broken_flow_controller import _pick_missing_intel_intent
    from app.intel.artifact_registry import artifact_registry
    from app.core.broken_flow_constants import INT_ASK_OFFICIAL_HELPLINE, INT_ASK_OFFICIAL_WEBSITE

    # Setup mock redis
    mock_redis = MagicMock()
    mock_get_redis.return_value = mock_redis
    
    # We need to mock settings for the singleton's refresh
    with patch("app.settings.settings") as mock_settings:
        mock_settings.REGISTRY_TTL = 0
        mock_settings.REGISTRY_OVERRIDES_KEY = "registry:overrides"
        
        # phishingLinks priority is 20, phoneNumbers is 10 by default
        # Let's override phishingLinks to be disabled for asking
        mock_redis.get.return_value = json.dumps({
            "phishingLinks": {"ask_enabled": False}
        })
        
        # Trigger refresh via extract_all
        artifact_registry.extract_all("dummy")
        
        # Now phishingLinks should be skipped in _pick_missing_intel_intent
        intel = {"phishingLinks": [], "phoneNumbers": []}
        # Even though phishingLinks has higher priority (20 vs 10), 
        # it should pick phoneNumbers intent (INT_ASK_OFFICIAL_HELPLINE)
        intent = _pick_missing_intel_intent(intel, [])
        assert intent == INT_ASK_OFFICIAL_HELPLINE
        
        # Revert
        mock_redis.get.return_value = None
        artifact_registry.extract_all("dummy")
        intent = _pick_missing_intel_intent(intel, [])
        assert intent == INT_ASK_OFFICIAL_WEBSITE
