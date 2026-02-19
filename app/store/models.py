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

    # Keep for backward-compat / reporting, but derive from turnIndex when needed
    totalMessagesExchanged: int = 0

    # State
    state: str = "INIT"  # INIT/MONITORING/ENGAGED/READY_TO_REPORT/REPORTED/CLOSED
    scamDetected: bool = False
    confidence: float = 0.0
    scamType: Optional[str] = None

    # Conversation storage
    conversation: List[dict] = field(default_factory=list)
    extractedIntelligence: Intelligence = field(default_factory=Intelligence)

    # Ops
    agentNotes: str = ""
    callbackStatus: str = "none"  # none/queued/sent/failed
    lastUpdatedAtEpoch: Optional[int] = None

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
