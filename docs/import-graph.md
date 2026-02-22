# Import Graph & Module Architecture

## Problem
Previous circular imports caused startup failures:
`orchestrator` -> `guvi_callback` -> `jobs` -> `client` -> `outbox` -> `client` ...

## Solution
We enforce a strict Directed Acyclic Graph (DAG) for imports.

### Layers (Top to Bottom)
1.  **Entrypoints**: `main.py`, `worker.py`
2.  **API/Routes**: `app/api/`
3.  **Orchestrator**: `app/core/orchestrator.py`
    - Manages session lifecycle.
    - Imports `guvi_callback` (logic).
4.  **Callback Logic**: `app/core/guvi_callback.py`
    - Decides *when* to send.
    - **Lazy Imports**: `app/queue/jobs.py`, `app/callback/sender.py` (to break boot cycles).
5.  **Job Enqueueing**: `app/queue/jobs.py`
    - Enqueues jobs to Redis.
    - Imports `outbox.py` to run the job logic.
6.  **Outbox Logic**: `app/callback/outbox.py`
    - Manages persistence, retries, ledger.
    - Imports `client.py` (HTTP sender).
    - Imports `session_repo.py` (Store).
7.  **HTTP Client**: `app/callback/client.py`
    - **Pure**: Sends HTTP request only. No persistence, no deps on core/outbox.
8.  **Store/Models**: `app/store/`, `app/utils/`
    - Leaf nodes.

### Feature Flags
- `ENABLE_OUTBOX`: Toggles outbox processing.
- `ENABLE_GUVI_CALLBACK`: Toggles callback logic in orchestrator.

### Guidelines
- **Optional Features**: Import inside functions if they pull in heavy dependencies (e.g. `jobs` from `guvi_callback`).
- **Interfaces**: Keep `client.py` pure. Put complex state logic in `outbox.py`.
