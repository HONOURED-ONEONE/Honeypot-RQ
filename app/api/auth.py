from fastapi import Header, HTTPException
from app.settings import settings


def require_api_key(x_api_key: str = Header(default="", alias="x-api-key")):
    """
    API key is OPTIONAL per evaluator docs.
    - If API_KEY env is empty: allow all requests.
    - If API_KEY env is set: require matching x-api-key header.
    """
    if not getattr(settings, "API_KEY", ""):
        return
    if x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
