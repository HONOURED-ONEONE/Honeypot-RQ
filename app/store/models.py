from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Intelligence:
    bankAccounts: List[str] = field(default_factory=list)
    upiIds: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)


@dataclass
class SessionState:
    sessionId: str
    state: str = "INIT"  # INIT|MONITORING|ENGAGED|READY_TO_REPORT|REPORTED|CLOSED
    scamDetected: bool = False
    confidence: float = 0.0
    scamType: Optional[str] = None
    totalMessagesExchanged: int = 0
    conversation: List[dict] = field(default_factory=list)
    extractedIntelligence: Intelligence = field(default_factory=Intelligence)
    agentNotes: str = ""
    callbackStatus: str = "none"  # none|queued|sent|failed
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
