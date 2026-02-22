# Admin & Observability

## API Endpoints

### Session Management
- `GET /admin/session/{id}`: Compact session snapshot (status, confidence, key metrics).
- `GET /admin/session/{id}/timeline`: Ordered stream of session events (messages, postscripts, finalization).
- `GET /admin/callbacks?sessionId=...`: Callback attempt ledger, status, and DLQ preview.

### System Health (SLO)
- `GET /admin/slo`: Real-time observability snapshot backed by Redis counters.
  - **finalize_success_rate**: Percentage of successful finalizations vs attempts.
  - **p50/p95_finalize_latency**: Latency from session start to finalization (ms).
  - **callback_delivery_success_rate**: Percentage of successful callback deliveries vs attempts.
  - **recent_failed_callbacks**: List of session IDs that failed delivery recently.

## RBAC/ABAC
- Controlled via `ADMIN_RBAC_ENABLED` (true/false) in `.env`.
- API Key: `ADMIN_API_KEY` (must be provided in `x-admin-key` header).
- Scope: All `/admin/*` endpoints are guarded; public endpoints remain open.

## Structured Logging
- JSON format (`app/observability/logging.py`).
- PII Redaction: Enabled by default (`ENABLE_PII_REDACTION`).
- Redacts: `text`, `message`, `reply`, `payload` content, but preserves length.
- Retention: Log retention period configurable via `LOG_RETENTION_DAYS`.
