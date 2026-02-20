# Testing Guide

## How to run tests
To run all unit tests, execute the following command from the project root:
```bash
PYTHONPATH=. pytest
```

## Coverage
The following modules are covered by automated unit tests:

### Intel
- `tests/intel/test_artifacts.py`: Artifact extraction (UPI, phone, bank, URL) and normalization.
- `tests/intel/test_extractor.py`: Intelligence state updates and deduplication.

### Core
- `tests/core/test_orchestrator.py`: Orchestrator event handling, intelligence extraction from latest messages and history, and session persistence.
- `tests/test_broken_flow.py`: Broken-flow state transitions, intent selection, and finalization triggers.
- `tests/test_honeypot_fixes.py`: Comprehensive fixes for extraction gating and progression.

### LLM
- `tests/llm/test_detector.py`: Regex-based high-signal scam detection fallback.
- `tests/llm/test_vllm_client.py`: vLLM client retry logic and timeout handling.

### Store
- `tests/store/test_session_migration.py`: Session data migration and backward compatibility.

### Callback & Queue
- `tests/callback/test_callback.py`: Final result callback success and failure handling.
- `tests/queue/test_jobs.py`: RQ job queuing and payload building.

### Runtime Config
- `tests/test_runtime_config.py`: Dynamic artifact registry overrides via Redis.

## Mocks
Tests use `unittest.mock` to isolate external dependencies such as Redis, vLLM endpoints, and HTTP callbacks.
