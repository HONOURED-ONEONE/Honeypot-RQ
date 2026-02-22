# Admin Observability & SLO Snapshot

## `GET /admin/slo`

Returns a rolling-window snapshot (approx. last 15 minutes unless overridden by `SLO_WINDOW_SECONDS`) with the following fields:

```json
{
  "finalize_success_rate": 100.0,
  "p50_finalize_latency": 1.2,
  "p95_finalize_latency": 3.4,
  "target_finalize_latency": 5.0,
  "callback_delivery_success_rate": 100.0,
  "p95_callback_delivery_latency": 1.0,
  "target_callback_latency": 3.0,
  "sessions_waiting_for_report": ["<sessionId>", "..."],
  "recent_failed_callbacks": ["<sessionId>", "..."],
  "window_seconds": 900,
  "snapshot_at": 1739999999
}
```

### Field Notes
- **finalize_success_rate** — percentage of finalized sessions vs attempts (if attempts unavailable, falls back to successes over max(1, successes)).  
- **p50/p95_finalize_latency** — computed from recent finalize latency samples (seconds).  
- **target_finalize_latency** — SLO target (seconds), from `TARGET_FINALIZE_P95_SEC`.  
- **callback_delivery_success_rate** — delivered vs attempts (%).  
- **p95_callback_delivery_latency** — p95 delivery time (seconds).  
- **target_callback_latency** — SLO target (seconds), from `TARGET_CALLBACK_P95_SEC`.  
- **sessions_waiting_for_report** — optional list, populated if producers maintain `metrics:sessions:waiting_for_report`.  
- **recent_failed_callbacks** — recent failing session IDs (last 20).  
- **window_seconds** — informational window setting.  

### RBAC
All `/admin/*` endpoints are protected by `x-admin-key` when `ADMIN_RBAC_ENABLED=true`.

### Configuration
Key environment variables:

- `SLO_WINDOW_SECONDS` (default 900)  
- `TARGET_FINALIZE_P95_SEC` (default 5.0)  
- `TARGET_CALLBACK_P95_SEC` (default 3.0)  
- `ADMIN_RBAC_ENABLED=true`  
- `ADMIN_API_KEY=<secret>`  

## Callback Contract Versioning
- Header **`X-Report-Version`** is set from `CALLBACK_PAYLOAD_VERSION`.  
- Payload embeds `payloadVersion` and `contractVersion` under `extractedIntelligence._meta`.  
- Outbox ledger records `version` for every attempt (auditable).

## Last Callback Payload
When `STORE_LAST_CALLBACK_PAYLOAD=true`, the final payload is stored per session at:
`session:{sessionId}:last_callback_payload` with a TTL (24h), visible via:
`GET /debug/last-callback/{session_id}`.
