from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field

Sender = Literal["scammer", "user"]

class Message(BaseModel):
    sender: Sender
    text: str
    # PDF examples use epoch ms; field description mentions ISO-8601.
    timestamp: Union[int, str]

class Metadata(BaseModel):
    channel: Optional[str] = None  # SMS / WhatsApp / Email / Chat
    language: Optional[str] = None
    locale: Optional[str] = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    detection: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    settings: Optional[Dict[str, Any]] = None

class HoneypotResponse(BaseModel):
    status: Literal["success", "error"] = "success"
    reply: str