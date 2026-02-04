
def build_agent_notes(detection: dict) -> str:
    # Short behavioral summary based on reasons + type
    parts = []
    scam_type = detection.get("scamType")
    if scam_type:
        parts.append(f"Type: {scam_type}")
    reasons = detection.get("reasons") or []
    if reasons:
        parts.append("Signals: " + "; ".join(reasons[:4]))
    return " | ".join(parts) if parts else "Scam-like patterns detected."
