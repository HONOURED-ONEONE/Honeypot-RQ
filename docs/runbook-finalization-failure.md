# Runbook: Finalization Failure

## Symptom
- Callback not received.
- Session stuck in `READY_TO_REPORT` or `ACTIVE`.
- `/admin/callbacks` shows "failed:dlq".

## Diagnosis
1.  **Check Status**:
    `curl -H "x-admin-key: <KEY>" /admin/callbacks?sessionId=<ID>`
    - If `status` is `delivered`: Check recipient logs.
    - If `status` is `failed:terminal`: Check `error` field (e.g. 400 Bad Request).
    - If `status` is `pending`: Check `nextAttemptAt` and worker logs.
    - If `status` is `failed:dlq`: Max retries exceeded.

2.  **Check Timeline**:
    `curl -H "x-admin-key: <KEY>" /admin/session/<ID>/timeline`
    - Verify `lifecycle_finalized` event exists.
    - If not, session never finalized. Check `turns` vs `BF_MAX_TURNS`.

3.  **Logs**:
    - Search for `event="callback_send_failed"` or `event="callback_dlq_moved"`.

## Recovery
1.  **Replay from DLQ**:
    - Use `RPUSH` on Redis to move from `callback:dlq` to active queue (manual fix).
    - Or manual trigger endpoint (future).

2.  **Force Finalize**:
    - If stuck in `ACTIVE` but should be closed:
      - (Future) `POST /admin/session/:id/finalize`
