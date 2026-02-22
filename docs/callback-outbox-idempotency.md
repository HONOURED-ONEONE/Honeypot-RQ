# Idempotent Callback & Outbox Pattern

## Purpose
Ensures reliable delivery of the final report, even in the face of temporary network failures or process crashes.

## Design
- **Deterministic reportId**: `${sessionId}:${reportSequence}` (start at 1).
- **Outbox Persistence**: Ledger stored in `SessionState.outboxEntry`.
- **Idempotency Key**: Included in callback headers.
- **Contract Version**: `X-Report-Version` header.

## Logic
1.  **Generate & Persist**:
    - Build `finalReport`.
    - Set `reportId`.
    - Persist to Redis `SessionState` (single transaction via Orchestrator lock).
2.  **Process**:
    - Worker reads `outboxEntry`.
    - Check `nextAttemptAt`. If future, sleep/re-enqueue.
    - Attempt delivery.
3.  **Retry**:
    - Exponential backoff: `CALLBACK_BASE_DELAY_MS` * (2^(attempt-1)) + jitter.
    - Configurable attempts: `CALLBACK_MAX_ATTEMPTS` (default: 12).
    - Terminal failure: Move to `failed:dlq` (Dead Letter Queue) after max attempts.

## Configuration
- `CALLBACK_MAX_ATTEMPTS`: Max retry attempts.
- `CALLBACK_BASE_DELAY_MS`: Initial backoff delay (ms).
- `CALLBACK_MAX_DELAY_MS`: Max backoff delay (ms).
- `CALLBACK_DLQ_TTL_DAYS`: Retention for DLQ entries (not implemented yet).
