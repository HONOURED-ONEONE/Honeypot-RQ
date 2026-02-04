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
    # Finalize when engagement is deep enough OR session is stale.
    # Criteria: minimum turns and minimum IOC categories.
    turns_ok = session.totalMessagesExchanged >= settings.FINALIZE_MIN_TURNS
    iocs_ok = _ioc_category_count(session) >= settings.FINALIZE_MIN_IOC_CATEGORIES

    # Staleness check (worker-safe): if last update older than inactivity timeout
    now = int(time.time())
    stale = False
    if session.lastUpdatedAtEpoch is not None:
        stale = (now - session.lastUpdatedAtEpoch) >= settings.INACTIVITY_TIMEOUT_SEC

    return (turns_ok and iocs_ok) or stale
