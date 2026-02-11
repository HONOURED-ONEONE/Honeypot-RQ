import time
from app.settings import settings


def _ioc_category_count(session) -> int:
    intel = session.extractedIntelligence
    categories = 0
    if intel.upiIds: categories += 1
    if intel.phishingLinks: categories += 1
    if intel.phoneNumbers: categories += 1
    if intel.bankAccounts: categories += 1
    # suspiciousKeywords not counted as IOC category
    return categories


def should_finalize(session) -> bool:
    """
    Decide whether to end engagement and trigger final callback.
    (Refinement 4: No-progress forcing / Max turns)
    """
    if session.state in ("READY_TO_REPORT", "REPORTED", "CLOSED"):
        return False

    # 1. SCAM DETECTED + MIN IOC CATEGORIES
    iocs_ok = _ioc_category_count(session) >= settings.FINALIZE_MIN_IOC_CATEGORIES
    if session.scamDetected and iocs_ok:
        return True

    # 2. MAX TURNS REACHED
    if session.totalMessagesExchanged >= settings.BF_MAX_TURNS * 2:
        return True

    # 3. NO PROGRESS THRESHOLD
    if session.bf_no_progress_count >= settings.BF_NO_PROGRESS_TURNS:
        return True

    # 4. REPEAT LIMIT REACHED
    if session.bf_repeat_count >= settings.BF_REPEAT_LIMIT + 1:
        return True

    # 5. STALENESS / INACTIVITY
    now = int(time.time())
    if session.lastUpdatedAtEpoch is not None:
        if (now - session.lastUpdatedAtEpoch) >= settings.INACTIVITY_TIMEOUT_SEC:
            return True

    return False
