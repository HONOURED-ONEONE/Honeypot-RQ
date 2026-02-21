import pytest
from unittest.mock import MagicMock
from app.store.models import SessionState, Intelligence
from app.core.termination import decide_termination
from app.settings import settings

@pytest.fixture
def session():
    return SessionState(
        sessionId="test-session",
        scamDetected=True,
        turnsEngaged=0,
        bf_no_progress_count=0,
        bf_repeat_count=0,
        extractedIntelligence=Intelligence()
    )

def test_decide_termination_hard_cap(session):
    session.turnsEngaged = 10
    settings.BF_MAX_TURNS = 10
    reason = decide_termination(session=session)
    assert reason == "max_turns_reached"

def test_decide_termination_stagnation(session):
    session.bf_no_progress_count = 3
    settings.BF_NO_PROGRESS_TURNS = 3
    reason = decide_termination(session=session)
    assert reason == "no_progress_threshold"

def test_decide_termination_repeat(session):
    session.bf_repeat_count = 3  # BF_REPEAT_LIMIT (2) + 1
    settings.BF_REPEAT_LIMIT = 2
    reason = decide_termination(session=session)
    assert reason == "repeat_threshold"

def test_decide_termination_ioc_milestone(session):
    session.turnsEngaged = 8
    settings.CQ_MIN_TURNS = 8
    settings.FINALIZE_MIN_IOC_CATEGORIES = 1
    session.extractedIntelligence.phoneNumbers = ["+919876543210"]
    reason = decide_termination(session=session)
    assert reason == "ioc_milestone"

def test_decide_termination_ioc_milestone_gated_by_turns(session):
    session.turnsEngaged = 5
    settings.CQ_MIN_TURNS = 8
    settings.FINALIZE_MIN_IOC_CATEGORIES = 1
    session.extractedIntelligence.phoneNumbers = ["+919876543210"]
    reason = decide_termination(session=session)
    assert reason is None

def test_decide_termination_controller_force(session):
    session.turnsEngaged = 8
    settings.CQ_MIN_TURNS = 8
    controller_out = {"force_finalize": True, "reason": "controller_reason"}
    reason = decide_termination(session=session, controller_out=controller_out)
    assert reason == "controller_reason"

def test_decide_termination_controller_force_gated_by_turns(session):
    session.turnsEngaged = 5
    settings.CQ_MIN_TURNS = 8
    controller_out = {"force_finalize": True, "reason": "controller_reason"}
    reason = decide_termination(session=session, controller_out=controller_out)
    assert reason is None

def test_decide_termination_already_reported(session):
    session.state = "REPORTED"
    session.turnsEngaged = 10
    reason = decide_termination(session=session)
    assert reason is None
