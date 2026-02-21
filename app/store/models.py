from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class Intelligence:
    bankAccounts: List[str] = field(default_factory=list)
    upiIds: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    # ✅ NEW: First-class support for emails (recognized in evaluation)
    emailAddresses: List[str] = field(default_factory=list)
    # ✅ NEW: ID-like categories from updated rubric (scored as intelligence)
    caseIds: List[str] = field(default_factory=list)
    policyNumbers: List[str] = field(default_factory=list)
    orderNumbers: List[str] = field(default_factory=list)
    # ✅ P0.2: Required by callback payload and evaluation docs
    suspiciousKeywords: List[str] = field(default_factory=list)
    # ✅ NEW: Runtime IOC add-ons (key -> list[str])
    dynamicArtifacts: Dict[str, List[str]] = field(default_factory=dict)

@dataclass
class SessionState:
    # Core identifiers
    sessionId: str = ""

    # Conversation counters (canonical)
    turnIndex: int = 0  # ✅ always present
    # ✅ NEW: Exchange-turn counter (counts agent replies, aligns with evaluator "turns")
    turnsEngaged: int = 0

    # Keep for backward-compat / reporting, but derive from turnIndex when needed
    totalMessagesExchanged: int = 0

    # State
    state: str = "INIT"  # INIT/MONITORING/ENGAGED/READY_TO_REPORT/REPORTED/CLOSED
    scamDetected: bool = False
    confidence: float = 0.0
    scamType: Optional[str] = None

    # --- Detector evidence (for agentNotes summarization) ---
    # Persisted to make agentNotes deterministic and consistent across callback time.
    detectorReasons: List[str] = field(default_factory=list)

    # Conversation storage
    conversation: List[dict] = field(default_factory=list)
    extractedIntelligence: Intelligence = field(default_factory=Intelligence)

    # Ops
    agentNotes: str = ""
    callbackStatus: str = "none"  # none/queued/sent/failed
    lastUpdatedAtEpoch: Optional[int] = None

    # Engagement metrics (for callback/reporting)
    engagementDurationSeconds: int = 0

    # --- Engagement wall-clock tracking (robust vs timestamp quirks) ---
    # Set on first observed request; updated on each request/reply cycle.
    # Stored in epoch milliseconds to match other timestamps.
    sessionFirstSeenAtMs: int = 0
    sessionLastSeenAtMs: int = 0

    # Optional reporting fields (Response Structure bonus)
    confidenceLevel: float = 0.0

    # Broken-Flow state + counters
    bf_state: str = "BF_S0"
    bf_last_intent: Optional[str] = None
    bf_repeat_count: int = 0
    bf_no_progress_count: int = 0
    bf_policy_refused_once: bool = False
    bf_secondary_bounce_count: int = 0
    bf_last_ioc_signature: str = ""
    bf_recent_intents: List[str] = field(default_factory=list)
    bf_fallback_used: bool = False

    # --- Fix B: ACK gating ---
    # Allow INT_ACK_CONCERN at most once per session to avoid low-yield loops.
    bf_ack_used_count: int = 0

    # --- Red-flag state (Conversation Quality support) ---
    # lastRedFlagTag: single chosen tag for the latest scammer message
    # redFlagHistory: rolling history to enable rotation and reduce redundant flags
    lastRedFlagTag: Optional[str] = None
    redFlagHistory: List[str] = field(default_factory=list)

    # --- Persona style state (Behavior cue) ---
    # lastPersonaStyle: "CONFUSION", "SKEPTICAL", "TECH_FRICTION", "DELAY"
    lastPersonaStyle: Optional[str] = None
    personaStyleHistory: List[str] = field(default_factory=list)
    # --- Anti-redundancy state (Conversation Quality support) ---
    # Track when an IOC category was last asked, to prevent repeated questions.
    # key: artifact category (e.g., "phoneNumbers"), value: last turnIndex when asked
    askedArtifactLastTurn: Dict[str, int] = field(default_factory=dict)

    # Keep a small rolling window of recent agent reply fingerprints to avoid repeating
    # nearly identical responses across turns.
    recentAgentReplyFingerprints: List[str] = field(default_factory=list)

    # --- Investigative Ladder state (debug/observability) ---
    # lastLadderTarget: last chosen ladder key (e.g., "phoneNumbers", "phishingLinks", "department")
    lastLadderTarget: Optional[str] = None

    # --- Adaptive ladder support ---
    # Keys (IOC categories) that were newly added/expanded in the latest processed scammer message.
    # Used to avoid immediately asking for the same category next turn (timing/state sync redundancy).
    lastNewIocKeys: List[str] = field(default_factory=list)

    # --- Rephrase telemetry (BF_LLM_REPHRASE acceptance rate) ---
    # Counts are per-session and are safe to persist in Redis via session_repo.
    rephraseAttempts: int = 0
    rephraseApplied: int = 0
    rephraseRejected: int = 0
    lastRephraseRejectReason: Optional[str] = None

    # --- Conversation Quality tracker (rubric-aligned)
    cqQuestionsAsked: int = 0
    cqRelevantQuestions: int = 0
    cqRedFlagMentions: int = 0
    cqElicitationAttempts: int = 0

    def __post_init__(self):
        """
        Keep counters consistent:
        - If older sessions only had totalMessagesExchanged, populate turnIndex.
        - Always keep totalMessagesExchanged in sync with turnIndex.
        """
        if self.turnIndex is None:
            self.turnIndex = 0
        # If loaded session had totalMessagesExchanged but not turnIndex, use it.
        if self.turnIndex == 0 and self.totalMessagesExchanged:
            self.turnIndex = int(self.totalMessagesExchanged)
        # Last-resort: infer from conversation length if both are missing/zero.
        if self.turnIndex == 0 and self.conversation:
            self.turnIndex = len(self.conversation)
        # Sync the legacy field to canonical field
        self.totalMessagesExchanged = int(self.turnIndex)

        # Backfill turnsEngaged for existing sessions (best-effort):
        # Count agent messages in stored conversation as a proxy for "turns".
        try:
            if int(getattr(self, "turnsEngaged", 0) or 0) <= 0 and self.conversation:
                self.turnsEngaged = sum(1 for m in (self.conversation or []) if (m.get("sender") or "").lower() == "agent")
        except Exception:
            pass
