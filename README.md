# Honeypot-RQ — Agentic Honeypot API

This repository implements a FastAPI-based honeypot that engages scam conversations, detects scam intent, extracts intelligence (IOCs), and produces a final session output payload suitable for automated evaluation.

## Tech Stack
- **API:** FastAPI
- **State:** Redis (session persistence)
- **Async Jobs:** RQ worker (optional, deployment dependent)
- **LLM (optional):** vLLM OpenAI-compatible endpoint

## Deployment Notes (Evaluation)
The evaluation system sends **POST** requests with:
`{ sessionId, message, conversationHistory, metadata }`
and expects a **200 OK** JSON response containing a reply field. The system examples use paths like `/detect`.

This API supports multiple compatibility paths:
- `POST /api/honeypot` (primary)
- `POST /detect` (compat)
- `POST /honeypot` (compat)
- `POST /api/detect` (compat)

Health & ping:
- `GET /health`
- `GET /ping`

## Setup (Local)

### 1) Create a virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

### 3) Configure environment
Copy `.env.example` to `.env` and fill values as needed.

### 4) Run API
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API Contract

### Request (POST)
```json
{
  "sessionId": "uuid-v4-string",
  "message": { "sender": "scammer", "text": "message text", "timestamp": 1739279400000 },
  "conversationHistory": [],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

### Response (200 OK)
```json
{ "status": "success", "reply": "text reply to scammer" }
```

## Environment Variables
See `.env.example` for the complete list.

## Notes on Code Quality
The evaluation rubric reserves a portion of the final score for code quality and requires a valid GitHub repository URL.
