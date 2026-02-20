from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.settings import settings
from app.intel.artifact_registry import snapshot_intent_map

app = FastAPI(title="Agentic Honeypot API")

# Allow cross-origin requests (useful if a web-based tester runs in the browser).
# This is permissive by design for hackathon validation.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    # Some endpoint testers call GET / first.
    return {"status": "ok", "message": "Honeypot API is running. Use /health and POST /api/honeypot"}


@app.get("/health")
def health():
    return {"status": "ok"}


# Optional: log a minimal boot snapshot (stdout)
try:
    im = snapshot_intent_map()
    print(f"[boot] BF_LLM_REPHRASE={settings.BF_LLM_REPHRASE} | intent_map_keys={len(im)}")
except Exception:
    pass
