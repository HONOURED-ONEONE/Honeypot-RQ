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
from app.core.termination import decide_termination  # ✅ NEW unified termination policy
from app.observability.logging import log

from app.settings import settings
from app.core.guvi_callback import enqueue_guvi_final_result # ✅ NEW
from app.intel.extractor import update_intelligence_from_text # ✅ P0.1: registry-driven extraction
from app.core.guarded_config import begin_session_overlay, end_session_overlay # ✅ NEW (session-scoped config)
from app.intel.artifact_registry import get_intent_instruction
from app.core.red_flags import choose_red_flag
from app.core.broken_flow_constants import INT_ASK_OFFICIAL_HELPLINE, INT_ASK_OFFICIAL_WEBSITE, INT_ASK_TICKET_REF, INT_ASK_DEPARTMENT_BRANCH, INT_ASK_ALT_VERIFICATION
import re
import hashlib
from datetime import datetime
from app.utils.time import parse_timestamp_ms, now_ms, compute_engagement_seconds
from app.utils.lock import session_lock
from app.callback.payloads import build_final_payload
import json
from app.store.redis_conn import get_redis
import app.observability.metrics as metrics


def _coerce_history_items(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    P2.1: Normalize evaluator-provided conversationHistory into our
    canonical {sender,text,timestamp} dicts for session storage.
    Defensive against missing/odd fields.
    """
    out: List[Dict[str, Any]] = []
    now_ms_val = now_ms()
    for m in history or []:
        try:
            sender = (m.get("sender") or "scammer")
            text = (m.get("text") or "")
            ts = m.get("timestamp")
            # Accept either epoch ms or ISO strings; normalize to epoch ms
            tsv = parse_timestamp_ms(ts) if ts is not None else now_ms_val
            out.append({"sender": sender, "text": text, "timestamp": tsv})
        except Exception:
            # Skip malformed entries; keep the session stable
            continue
    return out


def handle_event(req):
    # Single-Writer Guard
    with session_lock(req.sessionId):
        # Load session
        session = load_session(req.sessionId)

        # Latch-and-Drain: If already FINALIZED, accept postscript but do not process.
        if session.state == "FINALIZED":
            try:
                msg_text = getattr(req.message, "text", "") or ""
                if msg_text:
                    entry = {
                        "timestamp": now_ms(),
                        "sender": getattr(req.message, "sender", "scammer"),
                        "text": msg_text,
                        "ignored": True
                    }
                    ps = list(getattr(session, "postscript", []) or [])
                    ps.append(entry)
                    session.postscript = ps
                    save_session(session)
            except Exception:
                pass
            return {"reply": "Session ended. Thank you."}

        # ✅ P2.1: Bootstrap conversation from evaluator-provided history (first load / empty session)
        try:
            if not session.conversation:
                req_hist = getattr(req, "conversationHistory", None) or []
                boot = _coerce_history_items(req_hist)
                if boot:
                    session.conversation.extend(boot)
                    session.turnIndex = int(len(session.conversation))
                    # Backfill turnsEngaged from bootstrapped conversation history
                    try:
                        session.turnsEngaged = sum(1 for m in session.conversation if (m.get("sender") or "").lower() == "agent")
                    except Exception:
                        pass
        except Exception:
            # Non-influential safety net
            pass

        # ✅ P0.3: Persist the incoming message and increment counters
        try:
            incoming_ts = parse_timestamp_ms(getattr(req.message, "timestamp", None))
        except Exception:
            incoming_ts = now_ms()

        # --- Engagement wall-clock tracking (request side) ---
        try:
            now_wall = now_ms()
            if int(getattr(session, "sessionFirstSeenAtMs", 0) or 0) <= 0:
                session.sessionFirstSeenAtMs = int(now_wall)
            session.sessionLastSeenAtMs = int(now_wall)
        except Exception:
            pass

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

        # Persist detector reasons for better agentNotes later
        try:
            reasons = result.get("reasons") or []
            if not isinstance(reasons, list):
                reasons = [str(reasons)]
            # Deduplicate while preserving order
            seen = set()
            clean = []
            for r in reasons:
                s = str(r).strip()
                if s and s not in seen:
                    seen.add(s)
                    clean.append(s)
            # Merge into session.detectorReasons (keep last ~12 unique)
            prev = list(getattr(session, "detectorReasons", []) or [])
            for r in clean:
                if r not in prev:
                    prev.append(r)
            session.detectorReasons = prev[-12:]
        except Exception:
            pass

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
                # Update Watchdog timer if we got new IOCs
                if new_keys:
                    session.lastIocAtMs = now_ms()
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
            # Escalation heuristic: if we are already in a stuck/looping regime, use tech_friction/delay persona.
            try:
                esc = (
                    int(getattr(session, "bf_no_progress_count", 0) or 0) >= int(getattr(settings, "BF_NO_PROGRESS_TURNS", 3) or 3)
                    or int(getattr(session, "bf_repeat_count", 0) or 0) >= int(getattr(settings, "BF_REPEAT_LIMIT", 2) or 2)
                    or (str(getattr(session, "bf_state", "")) in ("BF_S4", "BF_S5"))
                )
            except Exception:
                esc = False

            # Force a non-NONE red-flag cue only if we are below the rubric target and still building turns.
            try:
                force_flag = bool(
                    bool(getattr(session, "scamDetected", False))
                    and int(getattr(session, "cqRedFlagMentions", 0) or 0) < int(getattr(settings, "CQ_MIN_REDFLAGS", 5) or 5)
                    and int(getattr(session, "turnIndex", 0) or 0) < int(getattr(settings, "CQ_MIN_TURNS", 8) or 8)
                )
            except Exception:
                force_flag = False

            rf = choose_red_flag(
                latest_text,
                getattr(session, "redFlagHistory", []) or [],
                escalation=bool(esc),
                recent_styles=getattr(session, "personaStyleHistory", []) or [],
                force_flag=force_flag,
            )
            session.lastRedFlagTag = rf.tag
            hist = list(getattr(session, "redFlagHistory", []) or [])
            hist.append(rf.tag)
            session.redFlagHistory = hist[-10:]
            # Persist persona style for rotation/debug
            try:
                session.lastPersonaStyle = getattr(rf, "style", None)
                sh = list(getattr(session, "personaStyleHistory", []) or [])
                if session.lastPersonaStyle:
                    sh.append(session.lastPersonaStyle)
                session.personaStyleHistory = sh[-10:]
            except Exception:
                pass
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
        # ✅ Unified termination policy (controller + finalize in one place)
        finalize_reason = decide_termination(session=session, controller_out=controller_out)
        
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
            persona_style=(getattr(rf, "style", "") if rf else ""),
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
            # ✅ Exchange-turn increment (one per agent reply)
            session.turnsEngaged = int(getattr(session, "turnsEngaged", 0) or 0) + 1

            # --- Engagement wall-clock tracking (reply side) ---
            try:
                now_wall2 = now_ms()
                if int(getattr(session, "sessionFirstSeenAtMs", 0) or 0) <= 0:
                    session.sessionFirstSeenAtMs = int(now_wall2)
                session.sessionLastSeenAtMs = int(now_wall2)
            except Exception:
                pass

            # Persist after reply so duration & intel accumulation grow across turns
            save_session(session)
        except Exception:
            # Non-influential; continue even if append fails
            pass

        # -----------------------------------------------------------------------
        # Conversation Quality tracker updates (rubric-aligned)
        # -----------------------------------------------------------------------
        try:
            # Questions Asked: count "?" in agent reply (responder enforces 0/1 question).
            if "?" in (reply_text or ""):
                session.cqQuestionsAsked = int(getattr(session, "cqQuestionsAsked", 0) or 0) + 1

            # Relevant Questions: count investigative intents (explicitly tied to verification artifacts).
            investigative_intents = {
                INT_ASK_OFFICIAL_HELPLINE,
                INT_ASK_OFFICIAL_WEBSITE,
                INT_ASK_TICKET_REF,
                INT_ASK_DEPARTMENT_BRANCH,
                INT_ASK_ALT_VERIFICATION,
            }
            if intent in investigative_intents and "?" in (reply_text or ""):
                session.cqRelevantQuestions = int(getattr(session, "cqRelevantQuestions", 0) or 0) + 1

            # Red Flag Identification: count whenever we emit a non-NONE tag cue.
            if getattr(session, "lastRedFlagTag", None) and str(session.lastRedFlagTag) != "NONE":
                session.cqRedFlagMentions = int(getattr(session, "cqRedFlagMentions", 0) or 0) + 1

            # Information Elicitation: treat each investigative intent as an elicitation attempt (1 per turn).
            if intent in investigative_intents:
                session.cqElicitationAttempts = int(getattr(session, "cqElicitationAttempts", 0) or 0) + 1

            save_session(session)
        except Exception:
            pass

        # --- Update engagement metrics on session for callback ---
        try:
            session.engagementDurationSeconds = compute_engagement_seconds(
                session.conversation or [],
                first_seen_ms=int(getattr(session, "sessionFirstSeenAtMs", 0) or 0),
                last_seen_ms=int(getattr(session, "sessionLastSeenAtMs", 0) or 0),
            )
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
            try:
                log(
                    event="finalize_snapshot",
                    sessionId=session.sessionId,
                    firstSeenMs=int(getattr(session, "sessionFirstSeenAtMs", 0) or 0),
                    lastSeenMs=int(getattr(session, "sessionLastSeenAtMs", 0) or 0),
                    durationSec=int(getattr(session, "engagementDurationSeconds", 0) or 0),
                    turnsEngaged=int(getattr(session, "turnsEngaged", 0) or 0),
                )
            except Exception:
                pass
            # Keep counters synced for callback payload
            session.totalMessagesExchanged = int(getattr(session, "turnIndex", 0) or 0)

            # Mark lifecycle and enqueue callback
            session.state = "READY_TO_REPORT"
            
            # ✅ Deterministic Final Report & Persistence
            try:
                # 1) Generate reportId and freeze report
                seq = int(getattr(session, "reportSequence", 0) or 0) + 1
                session.reportSequence = seq
                session.reportId = f"{session.sessionId}:{seq}"
                
                # 2) Build final report
                final_payload = build_final_payload(session)
                session.finalReport = final_payload
                session.finalizedAt = now_ms()
                session.state = "FINALIZED"
                
                # --- Objective 1: Update SLO metrics ---
                try:
                    metrics.increment_finalize_success()
                    if session.sessionFirstSeenAtMs and int(session.sessionFirstSeenAtMs) > 0:
                        metrics.record_finalize_latency(now_ms() - int(session.sessionFirstSeenAtMs))
                except Exception:
                    pass

                # --- Objective 3: Persist last callback payload for debug ---
                if settings.STORE_LAST_CALLBACK_PAYLOAD:
                    try:
                        get_redis().set(
                            f"session:{session.sessionId}:last_callback_payload",
                            json.dumps(final_payload),
                            ex=86400
                        )
                    except Exception:
                        pass
                
                # 3) Pass through the controller's reason so evaluator sees the specific gate
                enqueue_guvi_final_result(session, finalize_reason=finalize_reason)
                # callbackStatus is now set by hybrid dispatcher (sent/queued/failed)
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
