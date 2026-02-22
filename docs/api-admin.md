# Admin API Reference

Base URL: `/admin`
Headers: `x-admin-key: <ADMIN_API_KEY>`

## 1. Session Snapshot
**GET** `/session/{sessionId}`

Returns a compact view of the session state, detection, and conversation quality metrics.

**Response:**
```json
{
  "sessionId": "12345",
  "state": "FINALIZED",
  "scamDetected": true,
  "scamType": "UPI_FRAUD",
  "confidence": 0.95,
  "finalizedAt": 1708560000123,
  "reportId": "12345:1",
  "callbackStatus": "sent",
  "cq": {
    "questionsAsked": 8,
    "relevantQuestions": 6,
    "redFlagMentions": 5,
    "elicitationAttempts": 6
  },
  "outboxLedger": {
    "attempts": 1,
    "status": "delivered",
    "history": [...]
  },
  "turnsEngaged": 10,
  "durationSec": 120
}
```

## 2. Session Timeline
**GET** `/session/{sessionId}/timeline`

Returns chronological events including messages, ignored post-finalization messages, and lifecycle events.

**Response:**
```json
[
  {
    "timestamp": 1708560000000,
    "type": "message",
    "sender": "scammer",
    "content": "Hello, pay me now"
  },
  {
    "timestamp": 1708560000123,
    "type": "lifecycle_finalized",
    "reportId": "12345:1",
    "reason": "evidence_quorum_iocs"
  },
  {
    "timestamp": 1708560005000,
    "type": "postscript_message",
    "sender": "scammer",
    "content": "Are you there?",
    "ignored": true
  }
]
```

## 3. SLO Metrics
**GET** `/slo`

Returns real-time operational metrics for finalization and callbacks.

**Response:**
```json
{
  "finalize_success_rate": 1.0,
  "finalize_count": 42,
  "p50_finalize_latency": 45000,
  "p95_finalize_latency": 120000,
  "target_finalize_latency": 100000,
  "callback_delivery_success_rate": 0.98,
  "p95_callback_delivery_latency": 1500,
  "target_callback_latency": 5000,
  "recent_failed_callbacks": ["sess-abc-failed"],
  "sessions_waiting_for_report": []
}
```
