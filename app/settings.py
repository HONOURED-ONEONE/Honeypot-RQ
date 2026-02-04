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

    GUVI_CALLBACK_URL: str = os.getenv("GUVI_CALLBACK_URL", "")
    CALLBACK_TIMEOUT_SEC: int = int(os.getenv("CALLBACK_TIMEOUT_SEC", "5"))

settings = Settings()
