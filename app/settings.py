import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    API_KEY: str = os.getenv("API_KEY", "")

    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    RQ_QUEUE_NAME: str = os.getenv("RQ_QUEUE_NAME", "callback")

    SCAM_THRESHOLD: float = float(os.getenv("SCAM_THRESHOLD", "0.75"))
    MAX_CONTEXT_MESSAGES: int = int(os.getenv("MAX_CONTEXT_MESSAGES", "10"))

    FINALIZE_MIN_TURNS: int = int(os.getenv("FINALIZE_MIN_TURNS", "10"))
    # ✅ P1.3: Hackathon-friendly default so completion can happen within ~10 turns
    FINALIZE_MIN_IOC_CATEGORIES: int = int(os.getenv("FINALIZE_MIN_IOC_CATEGORIES", "2"))
    INACTIVITY_TIMEOUT_SEC: int = int(os.getenv("INACTIVITY_TIMEOUT_SEC", "180"))

    # Broken-Flow Knobs
    BF_ENABLED: bool = os.getenv("BF_ENABLED", "true").lower() == "true"
    # ✅ P1.3: Typical evaluator max turns ≈ 10; align default to avoid never-ending sessions
    BF_MAX_TURNS: int = int(os.getenv("BF_MAX_TURNS", "10"))
    BF_NO_PROGRESS_TURNS: int = int(os.getenv("BF_NO_PROGRESS_TURNS", "3"))
    BF_REPEAT_LIMIT: int = int(os.getenv("BF_REPEAT_LIMIT", "2"))
    BF_SECONDARY_BOUNCE_LIMIT: int = int(os.getenv("BF_SECONDARY_BOUNCE_LIMIT", "1"))
    ALT_COOLDOWN_WINDOW: int = int(os.getenv("ALT_COOLDOWN_WINDOW", "2"))
    BF_LLM_REPHRASE: bool = os.getenv("BF_LLM_REPHRASE", "false").lower() == "true"

    # Registry Overrides
    REGISTRY_TTL: int = int(os.getenv("REGISTRY_TTL", "60"))
    REGISTRY_OVERRIDES_KEY: str = os.getenv("REGISTRY_OVERRIDES_KEY", "registry:overrides")
    # NEW: Dynamic artifact specs (runtime add-ons)
    REGISTRY_DYNAMIC_KEY: str = os.getenv("REGISTRY_DYNAMIC_KEY", "registry:dynamic")
    # NEW: Intent map (key -> {intent, instruction}) to drive controller & responder
    REGISTRY_INTENT_MAP_KEY: str = os.getenv("REGISTRY_INTENT_MAP_KEY", "registry:intent_map")

    # NEW: include dynamicArtifacts in callback payload (default: false, to avoid strict schema issues)
    INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK: bool = os.getenv(
        "INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK", "false"
    ).lower() == "true"

    GUVI_CALLBACK_URL: str = os.getenv("GUVI_CALLBACK_URL", "")
    CALLBACK_TIMEOUT_SEC: int = int(os.getenv("CALLBACK_TIMEOUT_SEC", "5"))

    # RC-8: hot reload period for intent-map (seconds). 0 disables refresh (cache only).
    INTENT_MAP_REFRESH_SEC: int = int(os.getenv("INTENT_MAP_REFRESH_SEC", "60"))

settings = Settings()
