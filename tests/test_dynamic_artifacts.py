import pytest
from unittest.mock import MagicMock, patch
from app.store.models import SessionState, Intelligence
from app.intel.artifact_registry import artifact_registry
from app.intel.extractor import update_intelligence_from_text
from app.core.finalize import _ioc_category_count
from app.callback.payloads import build_final_payload
from app.core.broken_flow_controller import choose_next_action
from app.llm.responder import generate_agent_reply
from app.settings import settings

def test_dynamic_artifact_extraction_and_storage():
    session = SessionState(sessionId="test-session")
    text = "Here is a weird artifact: XYZ-123"

    # Mock artifact registry to return a dynamic artifact
    # The extractor relies on artifact_registry.extract_all returning the dict
    with patch.object(artifact_registry, "extract_all", return_value={"myDynamicKey": ["XYZ-123"]}) as mock_extract:
        update_intelligence_from_text(session, text)
    
    assert "myDynamicKey" in session.extractedIntelligence.dynamicArtifacts
    assert session.extractedIntelligence.dynamicArtifacts["myDynamicKey"] == ["XYZ-123"]

def test_finalize_counts_dynamic_artifacts():
    session = SessionState(sessionId="test-session")
    # Add a static artifact
    session.extractedIntelligence.phoneNumbers = ["1234567890"]
    # Add a dynamic artifact
    session.extractedIntelligence.dynamicArtifacts = {"customKey": ["val1"]}
    
    # Mock registry artifacts to include 'customKey' (as if it was registered dynamically)
    # _ioc_category_count iterates over artifact_registry.artifacts.keys()
    with patch.dict(artifact_registry.artifacts, {"phoneNumbers": MagicMock(), "customKey": MagicMock()}):
        count = _ioc_category_count(session)
        assert count == 2

def test_callback_payload_includes_dynamic_artifacts():
    session = SessionState(sessionId="test-session")
    session.extractedIntelligence.dynamicArtifacts = {"hiddenKey": ["secret"]}
    
    # 1. Default (False)
    # We must patch the settings object instance that is imported by payloads
    with patch.object(settings, "INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK", False):
        payload = build_final_payload(session)
        assert "dynamicArtifacts" not in payload["extractedIntelligence"]
    
    # 2. Enabled (True)
    with patch.object(settings, "INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK", True):
        payload = build_final_payload(session)
        assert "dynamicArtifacts" in payload["extractedIntelligence"]
        assert payload["extractedIntelligence"]["dynamicArtifacts"] == {"hiddenKey": ["secret"]}

def test_controller_returns_instruction():
    session = SessionState(sessionId="test-session")
    intel_dict = {}
    detection_dict = {}
    
    # We want to verify that choose_next_action returns an 'instruction' key.
    # We don't need to force a specific intent, just check the key exists.
    out = choose_next_action(session, "hello", intel_dict, detection_dict, settings)
    assert "instruction" in out
    assert isinstance(out["instruction"], str)

def test_responder_uses_instruction():
    session = SessionState(sessionId="test-session")
    
    # Mock chat_completion to avoid actual LLM calls
    with patch("app.llm.responder.chat_completion", return_value="Rephrased reply") as mock_llm:
        # Enable rephrase
        with patch.object(settings, "BF_LLM_REPHRASE", True):
            reply = generate_agent_reply(MagicMock(), session, "INT_ACK_CONCERN", instruction="Do specific thing")
            
            # Check that the prompt passed to LLM contained the instruction
            args, _ = mock_llm.call_args
            prompt_text = args[1] # user prompt is 2nd arg
            assert "Do specific thing" in prompt_text
            assert reply == "Rephrased reply"
