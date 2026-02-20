from app.store.models import SessionState
from app.settings import settings
from app.utils.time import now_ms, compute_engagement_seconds
import json, hashlib
from app.core.notes import build_agent_notes

def build_final_payload(session: SessionState) -> dict:
    intel = session.extractedIntelligence
    
    # Robust duration computed from persisted session timeline:
    engagement_duration_seconds = compute_engagement_seconds(session.conversation or [])

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
            "payloadVersion": getattr(settings, "CALLBACK_PAYLOAD_VERSION", "1.0.0"),
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
        canonical = json.dumps(extracted, sort_keys=True, separators=(",", ":"))
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
    return extracted

def validate_final_payload(payload: dict) -> (bool, str):
    """
    Minimal, dependency-free schema validation to catch shape drift before POST.
    Returns (ok, reason).
    """
    try:
        # Required top-level keys
        req = [
            ("sessionId", str),
            ("scamDetected", bool),
            ("totalMessagesExchanged", int),
            ("engagementDurationSeconds", int),
            ("extractedIntelligence", dict),
        ]
        for k, v in req:
            if k not in payload:
                return False, f"missing:{k}"
            # allow int-like floats only for ints that are whole numbers
            val = payload[k]
            if v is int and isinstance(val, float) and val.is_integer():
                continue
            if not isinstance(val, v):
                return False, f"type:{k}"
        ei = payload.get("extractedIntelligence") or {}
        # EI should contain lists for known keys; tolerate empties
        for name in ("phoneNumbers", "phishingLinks", "upiIds", "bankAccounts", "emailAddresses"):
            if name in ei and not isinstance(ei.get(name), list):
                return False, f"type:ei.{name}"

        # Optional: _signals container (where suspiciousKeywords live)
        if "_signals" in ei and not isinstance(ei.get("_signals"), dict):
            return False, "type:ei._signals"
        if isinstance(ei.get("_signals"), dict):
            sk = ei["_signals"].get("suspiciousKeywords")
            if sk is not None and not isinstance(sk, list):
                return False, "type:ei._signals.suspiciousKeywords"

        # Optional: _meta must be dict if present (extras allowed here)
        if "_meta" in ei and not isinstance(ei.get("_meta"), dict):
            return False, "type:ei._meta"

        return True, "ok"
    except Exception as e:
        return False, f"exception:{type(e).__name__}"
