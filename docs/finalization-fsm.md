# Finalization FSM & Deterministic Termination

This document describes the state machine governing session finalization.

## State Machine
- **INIT**: Session created, context initialized.
- **ACTIVE**: Ongoing conversation with scammer.
- **READY_TO_REPORT**: Termination trigger met, callback payload prepared.
- **FINALIZED**: Report frozen, callback queued, further intents blocked.
- **CLOSED**: Terminal state (archived).

## Triggers (First-Win)
1. **Evidence Quorum**:
   - DISTINCT IOC categories >= `FINALIZE_MIN_IOC_CATEGORIES` (default: 2)
   - AND/OR DISTINCT Red Flags >= `FINALIZE_MIN_REDFLAGS` (default: 4)
2. **Turn/Time Budget**:
   - Turns engaged >= `BF_MAX_TURNS` (default: 10)
   - Inactivity > `FINALIZE_INACTIVITY_SECONDS` (default: 30s) since last agent reply or IOC update.
3. **Escalation**:
   - Refusal loop (BF_S5) or controller force-finalize.

## Latch-and-Drain
Once `READY_TO_REPORT` is reached:
- **Lock**: Further scammer messages are accepted into `postscript` (immutable log) but **do not** trigger detector/controller logic.
- **Drain**: Any pending analysis completes.
- **Emit**: Final report is generated and persisted.
- **Mark**: State transitions to `FINALIZED`.

## Watchdog
- The `orchestrator` checks for inactivity on every incoming event.
- If a session is idle beyond `FINALIZE_INACTIVITY_SECONDS` *and* a subsequent event arrives (or worker scans), it is forced to finalize.
