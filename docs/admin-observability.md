# Admin & Observability

## API Endpoints
- `GET /admin/session/:id/timeline`: Ordered stream of session events (messages, postscripts, finalization).
- `GET /admin/callbacks?sessionId=...`: Callback attempt ledger, status, and DLQ preview.
- `GET /admin/slo`: P50/P95 latency, success rate (metrics).

## RBAC/ABAC
- Controlled via `ADMIN_RBAC_ENABLED` (true/false) in `.env`.
- API Key: `ADMIN_API_KEY` (must be provided in `x-admin-key` header).
- Scope: Admin endpoints are guarded; public endpoints remain open.

## Structured Logging
- JSON format (`app/observability/logging.py`).
- PII Redaction: Enabled by default (`ENABLE_PII_REDACTION`).
- Redacts: `text`, `message`, `reply`, `payload` content, but preserves length.
- Retention: Log retention period configurable via `LOG_RETENTION_DAYS`.
