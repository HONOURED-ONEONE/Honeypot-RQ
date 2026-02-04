# Agentic Honeypot (FastAPI + Redis + RQ + Gemini)

This repo implements the **Problem Statement 2** requirements:
- Public REST API that accepts message events (sessionId, message, conversationHistory, metadata)
- Scam detection + agent handoff
- Multi-turn engagement
- Structured intelligence extraction
- **Mandatory final callback** to GUVI endpoint via a reliable background worker (RQ)

## Quickstart (local)

### 1) Start Redis
```bash
docker compose up -d
```

### 2) Configure env
```bash
cp .env.example .env
# edit .env with your API_KEY and GEMINI_API_KEY
```

### 3) Install Python deps
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4) Run API
```bash
./scripts/run_api.sh
```

### 5) Run Worker (new terminal)
```bash
source .venv/bin/activate
export $(grep -v '^#' .env | xargs)  # load env into shell
./scripts/run_worker.sh
```

### 6) Test
```bash
curl -X POST http://localhost:8000/api/honeypot \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: change_me_super_secret' \
  -d '{
    "sessionId": "demo-1",
    "message": {"sender": "scammer", "text": "Your bank account will be blocked today. Verify immediately.", "timestamp": 1770005528731},
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
  }'
```

## Notes
- The API always returns `{ "status": "success", "reply": "..." }`.
- When finalize criteria is met, the worker sends the **mandatory** callback to GUVI.
