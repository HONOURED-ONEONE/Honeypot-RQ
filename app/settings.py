import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    API_KEY: str = os.getenv("API_KEY", "")

    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    RQ_QUEUE_NAME: str = os.getenv("RQ_QUEUE_NAME", "callback")

    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    SCAM_THRESHOLD: float = float(os.getenv("SCAM_THRESHOLD", "0.75"))
    MAX_CONTEXT_MESSAGES: int = int(os.getenv("MAX_CONTEXT_MESSAGES", "10"))

    FINALIZE_MIN_TURNS: int = int(os.getenv("FINALIZE_MIN_TURNS", "12"))
    FINALIZE_MIN_IOC_CATEGORIES: int = int(os.getenv("FINALIZE_MIN_IOC_CATEGORIES", "2"))
    INACTIVITY_TIMEOUT_SEC: int = int(os.getenv("INACTIVITY_TIMEOUT_SEC", "180"))

    # Broken-Flow Knobs
    BF_ENABLED: bool = os.getenv("BF_ENABLED", "true").lower() == "true"
    BF_MAX_TURNS: int = int(os.getenv("BF_MAX_TURNS", "15"))
    BF_NO_PROGRESS_TURNS: int = int(os.getenv("BF_NO_PROGRESS_TURNS", "2"))
    BF_REPEAT_LIMIT: int = int(os.getenv("BF_REPEAT_LIMIT", "2"))
    BF_SECONDARY_BOUNCE_LIMIT: int = int(os.getenv("BF_SECONDARY_BOUNCE_LIMIT", "1"))
    BF_LLM_REPHRASE: bool = os.getenv("BF_LLM_REPHRASE", "false").lower() == "true"

    GUVI_CALLBACK_URL: str = os.getenv("GUVI_CALLBACK_URL", "")
    CALLBACK_TIMEOUT_SEC: int = int(os.getenv("CALLBACK_TIMEOUT_SEC", "5"))

settings = Settings()
