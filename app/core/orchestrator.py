# app/core/orchestrator.py
"""
Orchestrator Invariants (Non-Negotiable)
- Conversation turns must be persisted for context and counting.
- The orchestrator NEVER decides what to ask.
- The orchestrator ONLY coordinates:
  - session lifecycle
  - intent sequencing
  - responder invocation
  - finalize gating
"""
import time
from typing import List, Dict, Any
from app.llm.detector import detect_scam
from app.store.session_repo import load_session, save_session
from app.core.broken_flow_controller import choose_next_action
from app.llm.responder import generate_agent_reply
from app.core.finalize import should_finalize
from app.observability.logging import log

from app.settings import settings
from app.core.guvi_callback import enqueue_guvi_final_result # ✅ NEW
from app.intel.extractor import update_intelligence_from_text # ✅ P0.1: registry-driven extraction
from app.core.guarded_config import begin_session_overlay, end_session_overlay # ✅ NEW (session-scoped config)
from app.intel.artifact_registry import get_intent_instruction
from app.core.red_flags import choose_red_flag
import re
import hashlib
from datetime import datetime


def _coerce_history_items(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    P2.1: Normalize evaluator-provided conversationHistory into our
    canonical {sender,text,timestamp} dicts for session storage.
    Defensive against missing/odd fields.
    """
    out: List[Dict[str, Any]] = []
    now_ms = int(time.time() * 1000)
    for m in history or []:
        try:
            sender = (m.get("sender") or "scammer")
            text = (m.get("text") or "")
            ts = m.get("timestamp")
            # Accept either epoch ms or iso strings; if absent, use now.
            if isinstance(ts, (int, float)):
                tsv = int(ts)
            else:
                tsv = now_ms
            out.append({"sender": sender, "text": text, "timestamp": tsv})
        except Exception:
            # Skip malformed entries; keep the session stable
            continue
    return out


def handle_event(req):
    # Load session
    session = load_session(req.sessionId)

    # ✅ P2.1: Bootstrap conversation from evaluator-provided history (first load / empty session)
    try:
        if not session.conversation:
            req_hist = getattr(req, "conversationHistory", None) or []
            boot = _coerce_history_items(req_hist)
            if boot:
                session.conversation.extend(boot)
                session.turnIndex = int(len(session.conversation))
    except Exception:
        # Non-influential safety net
        pass

    # ✅ P0.3: Persist the incoming message and increment counters
    try:
        incoming_ts = req.message.timestamp
    except Exception:
        incoming_ts = int(time.time() * 1000)
    try:
        session.conversation.append({
            "sender": getattr(req.message, "sender", "scammer"),
            "text": getattr(req.message, "text", "") or "",
            "timestamp": incoming_ts,
        })
        session.turnIndex = int(getattr(session, "turnIndex", 0) or 0) + 1
        # Persist after ingest so BF memory, counters, and timestamps survive next turn
        save_session(session)
    except Exception:
        # Keep processing even if persistence fails (non-influential)
        pass

    result = detect_scam(req, session)
    # ✅ P0.4: Persist detector outcome to session (required for finalize + callback)
    try:
        session.scamDetected = bool(result.get("scamDetected", False))
    except Exception:
        session.scamDetected = False
    try:
        session.confidence = float(result.get("confidence", 0.0) or 0.0)
    except Exception:
        session.confidence = 0.0

    # Maintain scam type consistently
    try:
        detected_type = str(result.get("scamType") or "UNKNOWN")
        # Prefer keeping previously set scamType if already present and non-empty
        if not getattr(session, "scamType", None):
            session.scamType = detected_type
        else:
            # ensure it is a string
            session.scamType = str(session.scamType)
    except Exception:
        session.scamType = "UNKNOWN"
    # ✅ P1.1: Keep controller-facing alias in sync
    session.scam_type = session.scamType or "UNKNOWN"

    # ✅ P0.1: Intelligence extraction BEFORE controller/finalize
    #    - Extract from the latest incoming message
    #    - Optionally catch up on a small recent window of conversationHistory
    latest_text = req.message.text or ""
    if latest_text:
        # --- Adaptive ladder: snapshot IOC counts before extraction ---
            try:
                intel0 = session.extractedIntelligence
                before = {
                    "phoneNumbers": len(getattr(intel0, "phoneNumbers", []) or []),
                    "phishingLinks": len(getattr(intel0, "phishingLinks", []) or []),
                    "upiIds": len(getattr(intel0, "upiIds", []) or []),
                    "bankAccounts": len(getattr(intel0, "bankAccounts", []) or []),
                    "emailAddresses": len(getattr(intel0, "emailAddresses", []) or []),
                    "caseIds": len(getattr(intel0, "caseIds", []) or []),
                    "policyNumbers": len(getattr(intel0, "policyNumbers", []) or []),
                    "orderNumbers": len(getattr(intel0, "orderNumbers", []) or []),
                }
            except Exception:
                before = {}
    
            update_intelligence_from_text(session, latest_text)
    
            # --- Adaptive ladder: compute which IOC keys grew this turn ---
            try:
                intel1 = session.extractedIntelligence
                after = {
                    "phoneNumbers": len(getattr(intel1, "phoneNumbers", []) or []),
                    "phishingLinks": len(getattr(intel1, "phishingLinks", []) or []),
                    "upiIds": len(getattr(intel1, "upiIds", []) or []),
                    "bankAccounts": len(getattr(intel1, "bankAccounts", []) or []),
                    "emailAddresses": len(getattr(intel1, "emailAddresses", []) or []),
                    "caseIds": len(getattr(intel1, "caseIds", []) or []),
                    "policyNumbers": len(getattr(intel1, "policyNumbers", []) or []),
                    "orderNumbers": len(getattr(intel1, "orderNumbers", []) or []),
                }
                new_keys = []
                for k, a in after.items():
                    b = int(before.get(k, 0) or 0)
                    if int(a or 0) > b:
                        new_keys.append(k)
                session.lastNewIocKeys = new_keys[:8]
            except Exception:
                session.lastNewIocKeys = []
    try:
        history = getattr(req, "conversationHistory", None) or []
        for m in history[-6:]:
            text = (m.get("text") if isinstance(m, dict) else "") or ""
            if text:
                update_intelligence_from_text(session, text)
    except Exception:
        # Maintain stability if history parsing fails (non-influential)
        pass

    # Controller
    # ✅ NEW: Flatten dynamicArtifacts so controller/finalize see runtime IOC keys
    try:
        # --- SESSION OVERLAY START (LLM-suggested, session-scoped rules) ---
        # Ensures any rule changes (intent-map/dynamic artifacts) apply
        # only to this session/turn and are reset afterward.
        begin_session_overlay(session.sessionId)
        intel_dict = dict(session.extractedIntelligence.__dict__ or {})
        dyn = intel_dict.pop("dynamicArtifacts", None)
        if isinstance(dyn, dict):
            for k, v in dyn.items():
                if isinstance(v, list):
                    intel_dict[k] = v
    except Exception:
        intel_dict = session.extractedIntelligence.__dict__

    # --- Red-flag tagger (deterministic, per latest scammer message) ---
    # Store on session for rotation and for debugging/observability.
    try:
        rf = choose_red_flag(latest_text, getattr(session, "redFlagHistory", []) or [])
        session.lastRedFlagTag = rf.tag
        hist = list(getattr(session, "redFlagHistory", []) or [])
        hist.append(rf.tag)
        session.redFlagHistory = hist[-10:]
    except Exception:
        rf = None

    controller_out = choose_next_action(
        session=session,
        latest_text=req.message.text or "",
        intel_dict=intel_dict,
        detection_dict=req.detection or {}, # ✅ detection is dict per schema
        settings=settings,
        red_flag=(rf.tag if rf else "NONE"),
    )

    intent = controller_out.get("intent")
    bf_state = controller_out.get("bf_state")
    force_finalize = controller_out.get("force_finalize", False)
    target_key = controller_out.get("target_key")
    # Prefer the controller's reason when it asserts finalize; only fallback otherwise
    if force_finalize:
        finalize_reason = controller_out.get("reason") or "controller_finalize"
    else:
        # should_finalize(...) may return None or a string
        finalize_reason = should_finalize(session)
    
    # We might have been finalized by controller OR fallback
    finalized = finalize_reason is not None

    # Resolve instruction from Redis-driven intent-map (same runtime env)
    # The controller might have already populated 'instruction' in its output, 
    # but we double check against registry just in case.
    instruction = controller_out.get("instruction")
    responder_key = None
    if not instruction:
        # Fallback: check if we can resolve instruction by intent or a hypothetical responder key
        responder_key = controller_out.get("responder_key") or intent
        instruction = get_intent_instruction(responder_key) or ""
    
    # Log instruction resolution for observability (even if instruction is empty)
    try:
        log(event="responder_instruction", sessionId=session.sessionId,
            intent=intent, responder_key=responder_key,
            has_instruction=bool(instruction), llm_rephrase=settings.BF_LLM_REPHRASE)
    except Exception:
        pass

    # --- Track recent intents for cooldown/loop prevention ---
    try:
        session.bf_last_intent = intent
        recent = list(getattr(session, "bf_recent_intents", []) or [])
        # Avoid back-to-back duplicates; duplicates distort cooldown windows.
        if not recent or recent[-1] != intent:
            recent.append(intent)
        # keep only the last 10 to cap memory
        session.bf_recent_intents = recent[-10:]
    except Exception:
        pass

    assert intent is not None, "Intent must be resolved before response generation"

    # Generate reply
    reply_text = generate_agent_reply(
        req=req,
        session=session,
        intent=intent,
        instruction=instruction,
        red_flag_prefix=(rf.prefix if rf else ""),
    )

    # ------------------------------------------------------------
    # Anti-redundancy: reply similarity guard (one retry pivot)
    # ------------------------------------------------------------
    def _fingerprint(text: str) -> str:
        t = (text or "").lower()
        t = re.sub(r"[^a-z0-9\s?]", " ", t)
        t = re.sub(r"\s+", " ", t).strip()
        return hashlib.md5(t.encode("utf-8")).hexdigest()

    try:
        fp = _fingerprint(reply_text)
        recent_fps = list(getattr(session, "recentAgentReplyFingerprints", []) or [])
        # If we've used this fingerprint very recently, pivot once.
        if fp in recent_fps[-3:]:
            controller_out2 = choose_next_action(
                session=session,
                latest_text=req.message.text or "",
                intel_dict=intel_dict,
                detection_dict=req.detection or {},
                settings=settings,
                red_flag=(rf.tag if rf else "NONE"),
            )
            intent2 = controller_out2.get("intent")
            # If controller gave us the same intent again, force a pivot by adding it to recent intents
            if intent2 == intent:
                # simulate avoidance: extend recent intent history temporarily and re-choose
                tmp_recent = list(getattr(session, "bf_recent_intents", []) or [])
                tmp_recent.append(intent)
                session.bf_recent_intents = tmp_recent[-10:]
                controller_out2 = choose_next_action(
                    session=session,
                    latest_text=req.message.text or "",
                    intel_dict=intel_dict,
                    detection_dict=req.detection or {},
                    settings=settings,
                    red_flag=(rf.tag if rf else "NONE"),
                )
                intent2 = controller_out2.get("intent")
            instruction2 = controller_out2.get("instruction") or instruction
            reply_text2 = generate_agent_reply(
                req=req,
                session=session,
                intent=intent2,
                instruction=instruction2,
                red_flag_prefix=(rf.prefix if rf else ""),
            )
            fp2 = _fingerprint(reply_text2)
            # Accept the retry if it differs; otherwise keep original
            if fp2 != fp:
                intent = intent2
                reply_text = reply_text2
                fp = fp2
        # Update fingerprint history
        recent_fps.append(fp)
        session.recentAgentReplyFingerprints = recent_fps[-10:]
    except Exception:
        pass

    # ✅ P0.3: Persist the agent reply and increment counters
    try:
        reply_ts = int(time.time() * 1000)
        session.conversation.append({
            "sender": "agent",
            "text": reply_text or "",
            "timestamp": reply_ts,
        })
        session.turnIndex = int(getattr(session, "turnIndex", 0) or 0) + 1
        # Persist after reply so duration & intel accumulation grow across turns
        save_session(session)
    except Exception:
        # Non-influential; continue even if append fails
        pass

    # --- Update engagement metrics on session for callback ---
    try:
        # first scammer timestamp
        first_ts = None
        for m in session.conversation:
            if (m.get("sender") == "scammer") and m.get("timestamp"):
                first_ts = m["timestamp"]
                break
        # last agent reply timestamp
        last_ts = None
        for m in reversed(session.conversation):
            if (m.get("sender") == "agent") and m.get("timestamp"):
                last_ts = m["timestamp"]
                break
        if isinstance(first_ts, (int, float)) and isinstance(last_ts, (int, float)) and last_ts >= first_ts:
            session.engagementDurationSeconds = int((last_ts - first_ts) / 1000)
        else:
            # best-effort fallback: zero
            session.engagementDurationSeconds = int(getattr(session, "engagementDurationSeconds", 0) or 0)
    except Exception:
        # retain existing value if any
        pass

    # Per-turn engagement snapshot (observability)
    try:
        log(
            event="engagement_snapshot",
            sessionId=session.sessionId,
            durationSec=int(getattr(session, "engagementDurationSeconds", 0) or 0),
            turns=int(getattr(session, "turnIndex", 0) or 0),
            messages=len(session.conversation or []),
        )
    except Exception:
        pass

    # --- Mandatory Callback Trigger (PS-2) ---
    # Only when scamDetected is true and finalization condition is met
    # Ensure it triggers exactly once.
    if (force_finalize or finalize_reason) and session.scamDetected and session.callbackStatus in ("none", "failed"):
        # Keep counters synced for callback payload
        session.totalMessagesExchanged = int(getattr(session, "turnIndex", 0) or 0)

        # Mark lifecycle and enqueue callback
        session.state = "READY_TO_REPORT"
        try:
            # Pass through the controller's reason so evaluator sees the specific gate
            enqueue_guvi_final_result(session, finalize_reason=finalize_reason)
            session.callbackStatus = "queued"
        except Exception:
            session.callbackStatus = "failed"
        # Persist session (kept as-is)
        save_session(session)

    # Persist session
    save_session(session)

    # Observability (non-influential)
    try:
        log(
            event="turn_processed",
            sessionId=session.sessionId,
            bf_state=bf_state,
            intent=intent,
            responder_key=responder_key,
            finalize_reason=finalize_reason or "",
            totalMessagesExchanged=getattr(session, "turnIndex", 0),
        )
    except Exception:
        pass

    # --- SESSION OVERLAY END (restore global state) ---
    try:
        end_session_overlay()
    except Exception:
        # ensure no leakage even if overlay end fails
        pass

    # PS-2 API output should be: {"status":"success","reply":"..."} (routes adds status)
    return {"reply": reply_text}
