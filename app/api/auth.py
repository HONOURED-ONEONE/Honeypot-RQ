from fastapi import Header, HTTPException
from app.settings import settings


def require_api_key(x_api_key: str = Header(default="", alias="x-api-key")):
    if not settings.API_KEY or x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
