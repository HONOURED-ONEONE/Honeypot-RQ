import sys
import pytest
from unittest.mock import patch, MagicMock

@pytest.mark.parametrize("enable_outbox", ["true", "false"])
@pytest.mark.parametrize("enable_guvi", ["true", "false"])
def test_import_graph_smoke(enable_outbox, enable_guvi):
    """
    Verify that the app can be imported without crashing,
    regardless of feature flags.
    """
    with patch.dict("os.environ", {
        "ENABLE_OUTBOX": enable_outbox,
        "ENABLE_GUVI_CALLBACK": enable_guvi,
        "REDIS_URL": "redis://localhost:6379/0",  # harmless default
    }):
        # Force reload of modules to test import side-effects
        if "app.main" in sys.modules:
            del sys.modules["app.main"]
        if "app.core.orchestrator" in sys.modules:
            del sys.modules["app.core.orchestrator"]
        if "app.callback.outbox" in sys.modules:
            del sys.modules["app.callback.outbox"]
        
        try:
            import app.main
            import app.core.orchestrator
            import app.callback.outbox
        except ImportError as e:
            pytest.fail(f"Import failed with flags outbox={enable_outbox} guvi={enable_guvi}: {e}")

def test_uvicorn_importable():
    """
    Simulate uvicorn import string loading.
    """
    from app.main import app
    assert app is not None
