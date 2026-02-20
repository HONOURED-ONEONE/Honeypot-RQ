import json
import pytest
from unittest.mock import patch, MagicMock
from scripts.seed_intent_map import main, INTENT_MAP, KEY

@patch("scripts.seed_intent_map.Redis")
def test_seed_intent_map(mock_redis_cls):
    mock_redis = MagicMock()
    mock_redis_cls.from_url.return_value = mock_redis
    
    main()
    
    # Check that set was called with the correct key and JSON data
    assert mock_redis.set.called
    args, _ = mock_redis.set.call_args
    assert args[0] == KEY
    
    saved_data = json.loads(args[1])
    assert saved_data == INTENT_MAP
    assert "phoneNumbers" in saved_data
    assert "[STYLE:FEIGNED]" in saved_data["phoneNumbers"]["instruction"]
