from app.store.models import SessionState
from app.settings import settings
from app.utils.time import now_ms, compute_engagement_seconds
import json, hashlib
from app.core.notes import build_agent_notes
from app.callback.contract import sanitize_final_payload, validate_contract

def build_final_payload(session: SessionState) -> dict:
    intel = session.extractedIntelligence
    
    # Robust duration:
    # Prefer wall-clock first/last seen times; fall back to conversation timestamps.
    engagement_duration_seconds = compute_engagement_seconds(
        session.conversation or [],
        first_seen_ms=int(getattr(session, "sessionFirstSeenAtMs", 0) or 0),
        last_seen_ms=int(getattr(session, "sessionLastSeenAtMs", 0) or 0),
    )

    extracted = {
        "sessionId": session.sessionId,
        "scamDetected": bool(session.scamDetected),
        "totalMessagesExchanged": int(session.totalMessagesExchanged),
        # ✅ NEW: Engagement duration now included (per Feb-19 example)
        "engagementDurationSeconds": engagement_duration_seconds,
        # Optional structure bonuses
        "scamType": (session.scamType or ""),
        "confidenceLevel": float(getattr(session, "confidence", 0.0) or 0.0),
    }
    ei = {
        "bankAccounts": intel.bankAccounts,
        "upiIds": intel.upiIds,
        "phishingLinks": intel.phishingLinks,
        "phoneNumbers": intel.phoneNumbers,
        # ✅ NEW: include emails in final payload (supported by evaluator schema)
        "emailAddresses": intel.emailAddresses,
        # ✅ NEW: ID-like categories now included by Feb-19 rubric
        "caseIds": intel.caseIds,
        "policyNumbers": intel.policyNumbers,
        "orderNumbers": intel.orderNumbers,
    }
    
    # Ensure ID-like categories are present (empty lists if none) to avoid evaluator misses
    # (Though extractedIntelligence dataclass defaults are lists, ensure presence in dict output)
    if "caseIds" not in ei: ei["caseIds"] = []
    if "policyNumbers" not in ei: ei["policyNumbers"] = []
    if "orderNumbers" not in ei: ei["orderNumbers"] = []

    if getattr(settings, "INCLUDE_DYNAMIC_ARTIFACTS_CALLBACK", False):
        ei["dynamicArtifacts"] = getattr(intel, "dynamicArtifacts", {}) or {}

    # Move keyword signals under a nested container to keep non-core keys scoped
    # strictly inside extractedIntelligence (and avoid polluting the top-level EI keys).
    try:
        sig = ei.get("_signals")
        if not isinstance(sig, dict):
            sig = {}
        sig["suspiciousKeywords"] = list(getattr(intel, "suspiciousKeywords", []) or [])
        ei["_signals"] = sig
    except Exception:
        pass

    # ---- Extra keys allowed ONLY inside extractedIntelligence (per constraint) ----
    # Keep payload contract metadata here (not top-level).
    try:
        meta = {
            "payloadVersion": getattr(settings, "CALLBACK_PAYLOAD_VERSION", "1.1"),
            "contractVersion": getattr(settings, "CALLBACK_PAYLOAD_VERSION", "1.1"), # Objective 3
        }
        ei["_meta"] = meta
    except Exception:
        pass

    extracted["extractedIntelligence"] = ei
    # agentNotes: prefer explicitly stored notes; else build from persisted detector fields
    try:
        notes = (session.agentNotes or "").strip()
        if not notes:
            det = {
                "scamType": (session.scamType or ""),
                "reasons": list(getattr(session, "detectorReasons", []) or []),
            }
            notes = build_agent_notes(det)
        extracted["agentNotes"] = notes or "Scam-like patterns detected."
    except Exception:
        extracted["agentNotes"] = session.agentNotes or "Scam-like patterns detected."

    try:
        algo = getattr(settings, "PAYLOAD_FINGERPRINT_ALGO", "sha256").lower()
        # Canonicalization: Sort keys, separators=(",", ":") for compact JSON
        canonical = json.dumps(extracted, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        h = hashlib.new(algo)
        h.update(canonical.encode("utf-8"))
        # Store fingerprint under extractedIntelligence._meta (allowed zone)
        try:
            extracted["extractedIntelligence"].setdefault("_meta", {})
            extracted["extractedIntelligence"]["_meta"]["payloadFingerprint"] = f"{algo}:{h.hexdigest()}"
        except Exception:
            pass
    except Exception:
        # keep payload even if hashing fails
        try:
            extracted["extractedIntelligence"].setdefault("_meta", {})
            extracted["extractedIntelligence"]["_meta"]["payloadFingerprint"] = "na"
        except Exception:
            pass

    # Final step: sanitize/lock contract for evaluator scoring.
    sanitized = sanitize_final_payload(extracted)

    # Best-effort: ensure we didn't accidentally break the contract.
    ok, _reason = validate_contract(sanitized)
    if not ok:
        # Even if validation fails (should be rare), return the sanitized payload anyway.
        # The sender will re-sanitize again before POST.
        return sanitized

    return sanitized

def validate_final_payload(payload: dict) -> (bool, str):
    """
    Minimal, dependency-free schema validation to catch shape drift before POST.
    Returns (ok, reason).
    """
    # Delegate to centralized contract validator to avoid drift across modules.
    return validate_contract(payload)
