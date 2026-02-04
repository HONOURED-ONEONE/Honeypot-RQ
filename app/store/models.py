from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Intelligence:
    bankAccounts: List[str] = field(default_factory=list)
    upiIds: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)


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
