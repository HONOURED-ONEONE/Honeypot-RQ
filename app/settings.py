import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    API_KEY: str = os.getenv("API_KEY", "")

    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    RQ_QUEUE_NAME: str = os.getenv("RQ_QUEUE_NAME", "callback")

    SCAM_THRESHOLD: float = float(os.getenv("SCAM_THRESHOLD", "0.75"))
    MAX_CONTEXT_MESSAGES: int = int(os.getenv("MAX_CONTEXT_MESSAGES", "10"))

    # Conversation Quality targets (rubric-aligned thresholds)
    CQ_MIN_TURNS: int = int(os.getenv("CQ_MIN_TURNS", "8"))
    CQ_MIN_QUESTIONS: int = int(os.getenv("CQ_MIN_QUESTIONS", "5"))
    CQ_MIN_RELEVANT_QUESTIONS: int = int(os.getenv("CQ_MIN_RELEVANT_QUESTIONS", "3"))
    CQ_MIN_REDFLAGS: int = int(os.getenv("CQ_MIN_REDFLAGS", "5"))
    CQ_MAX_ELICITATION_ATTEMPTS: int = int(os.getenv("CQ_MAX_ELICITATION_ATTEMPTS", "5"))  # 5 * 1.5 = 7.5 (cap at 7)

    # Detector robustness knobs (generic, scenario-agnostic)
    DETECTOR_CUMULATIVE_MODE: bool = os.getenv("DETECTOR_CUMULATIVE_MODE", "true").lower() == "true"
    DETECTOR_CUMULATIVE_WINDOW: int = int(os.getenv("DETECTOR_CUMULATIVE_WINDOW", "6"))  # recent scammer msgs
    DETECTOR_CUMULATIVE_SCORE: float = float(os.getenv("DETECTOR_CUMULATIVE_SCORE", "0.62"))
    DETECTOR_MAX_SCORE: float = float(os.getenv("DETECTOR_MAX_SCORE", "0.75"))

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
    # Group B: semantic cooldown & pressure knobs
    ALT_SEMANTIC_WINDOW: int = int(os.getenv("ALT_SEMANTIC_WINDOW", "5"))        # lookback turns
    ALT_MAX_USES_IN_WINDOW: int = int(os.getenv("ALT_MAX_USES_IN_WINDOW", "1"))  # max ALT occurrences allowed in window
    OTP_PRESSURE_WINDOW: int = int(os.getenv("OTP_PRESSURE_WINDOW", "4"))        # last N scammer msgs to scan
    OTP_PRESSURE_THRESHOLD: int = int(os.getenv("OTP_PRESSURE_THRESHOLD", "2"))  # occurrences needed to trigger pivot

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

    # Final-output delivery reliability (10s wait window) [1](https://kcetvnrorg-my.sharepoint.com/personal/24ucs160_kamarajengg_edu_in/Documents/Microsoft%20Copilot%20Chat%20Files/Honeypot%20API%20Evaluation%20System%20Documentation%20Updated%20-%20feb%2019.pdf)
    # Modes:
    # - "sync": send final output inline only (no RQ)
    # - "rq": queue only (old behavior)
    # - "hybrid": try sync first (deadline-bounded), then queue as backup
    FINAL_OUTPUT_MODE: str = os.getenv("FINAL_OUTPUT_MODE", "hybrid").lower()
    FINAL_OUTPUT_DEADLINE_SEC: float = float(os.getenv("FINAL_OUTPUT_DEADLINE_SEC", "8.0"))
    FINAL_OUTPUT_SYNC_RETRIES: int = int(os.getenv("FINAL_OUTPUT_SYNC_RETRIES", "1"))

    # RC-8: hot reload period for intent-map (seconds). 0 disables refresh (cache only).
    INTENT_MAP_REFRESH_SEC: int = int(os.getenv("INTENT_MAP_REFRESH_SEC", "60"))

    # Group D: payload contract integrity & observability
    CALLBACK_PAYLOAD_VERSION: str = os.getenv("CALLBACK_PAYLOAD_VERSION", "1.0.0")
    PAYLOAD_FINGERPRINT_ALGO: str = os.getenv("PAYLOAD_FINGERPRINT_ALGO", "sha256")
    # Store the last payload per session under a debug key in Redis for retrieval
    STORE_LAST_CALLBACK_PAYLOAD: bool = os.getenv("STORE_LAST_CALLBACK_PAYLOAD", "true").lower() == "true"

    # Objective 1: Finalization FSM + Watchdog
    FINALIZE_MIN_REDFLAGS: int = int(os.getenv("FINALIZE_MIN_REDFLAGS", "4"))
    FINALIZE_INACTIVITY_SECONDS: int = int(os.getenv("FINALIZE_INACTIVITY_SECONDS", "30"))
    FINALIZE_FORCE_ON_ESCALATION: bool = os.getenv("FINALIZE_FORCE_ON_ESCALATION", "true").lower() == "true"

    # Objective 2: Idempotent Callback + Outbox
    CALLBACK_MAX_ATTEMPTS: int = int(os.getenv("CALLBACK_MAX_ATTEMPTS", "12"))
    CALLBACK_BASE_DELAY_MS: int = int(os.getenv("CALLBACK_BASE_DELAY_MS", "1000"))
    CALLBACK_MAX_DELAY_MS: int = int(os.getenv("CALLBACK_MAX_DELAY_MS", "3600000"))
    CALLBACK_DLQ_TTL_DAYS: int = int(os.getenv("CALLBACK_DLQ_TTL_DAYS", "7"))

    # Objective 5: Enhanced Intelligence Extraction
    EXTRACTION_ID_ENABLED: bool = os.getenv("EXTRACTION_ID_ENABLED", "true").lower() == "true"
    NO_NEW_IOC_TURNS: int = int(os.getenv("NO_NEW_IOC_TURNS", "2"))

    # Objective 6: Sensitive-Action Refusal & Budget
    ESCALATED_OTP_THRESHOLD: int = int(os.getenv("ESCALATED_OTP_THRESHOLD", "1"))
    NORMAL_OTP_THRESHOLD: int = int(os.getenv("NORMAL_OTP_THRESHOLD", "2"))
    CQ_MIN_REDFLAGS: int = int(os.getenv("CQ_MIN_REDFLAGS", "6"))
    CQ_NO_DUPLICATE_WINDOW: int = int(os.getenv("CQ_NO_DUPLICATE_WINDOW", "2"))

    # Objective 8: Security & Privacy
    LOG_RETENTION_DAYS: int = int(os.getenv("LOG_RETENTION_DAYS", "180"))
    EVIDENCE_RETENTION_DAYS: int = int(os.getenv("EVIDENCE_RETENTION_DAYS", "365"))
    ENABLE_PII_REDACTION: bool = os.getenv("ENABLE_PII_REDACTION", "true").lower() == "true"
    ADMIN_RBAC_ENABLED: bool = os.getenv("ADMIN_RBAC_ENABLED", "true").lower() == "true"
    # Used for rudimentary RBAC/ABAC if enabled
    ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY", "")

settings = Settings()
