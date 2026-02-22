# Admin API

## `GET /admin/session/{id}`

Returns a compact session snapshot:

```json
{
  "sessionId": "abc123",
  "state": "FINALIZED",
  "scamDetected": true,
  "scamType": "PHISHING",
  "confidence": 0.92,
  "finalizedAt": 1739999999000,
  "reportId": "abc123:1",
  "callbackStatus": "sent",
  "cq": {
    "questionsAsked": 5,
    "relevantQuestions": 4,
    "redFlagMentions": 5,
    "elicitationAttempts": 5
  },
  "timeline": null,
  "outboxLedger": {
    "attempts": 1,
    "history": [
      {
        "attempt": 1,
        "ts": 1739999999000,
        "duration": 320,
        "code": 200,
        "error": null,
        "success": true,
        "version": "1.1"
      }
    ],
    "status": "delivered"
  },
  "turnsEngaged": 8,
  "durationSec": 76
}
```

> RBAC: send `x-admin-key: <ADMIN_API_KEY>` when `ADMIN_RBAC_ENABLED=true`.

## `GET /admin/session/{id}/timeline`
Chronological event stream including conversation messages, postscript entries, and a `lifecycle_finalized` event when applicable.

## `GET /admin/callbacks?sessionId={id}`
Idempotency ledger and last finalized payload preview.

## `GET /admin/slo`
See [admin-observability.md](./admin-observability.md) for field details.
