
import pytest
from app.core.investigative_ladder import choose_ladder_target, LADDER_BY_SCAMTYPE

def test_ladder_order_bank_impersonation():
    # Order: ["phoneNumbers", "caseIds", "phishingLinks", "department", "bankAccounts"]
    intel = {}
    asked = {}
    turn = 10
    
    # 1. phoneNumbers
    target = choose_ladder_target(intel, "BANK_IMPERSONATION", asked, turn)
    assert target == "phoneNumbers"
    
    # 2. caseIds (simulate phoneNumbers present)
    intel["phoneNumbers"] = ["+919999999999"]
    target = choose_ladder_target(intel, "BANK_IMPERSONATION", asked, turn)
    assert target == "caseIds"

    # 3. phishingLinks (simulate caseIds present)
    intel["caseIds"] = ["CASE-123"]
    target = choose_ladder_target(intel, "BANK_IMPERSONATION", asked, turn)
    assert target == "phishingLinks"

def test_ladder_adaptive_avoidance():
    # Avoid keys newly extracted
    intel = {}
    asked = {}
    turn = 10
    avoid = ["phoneNumbers"]
    
    # Should skip phoneNumbers and go to caseIds
    target = choose_ladder_target(intel, "BANK_IMPERSONATION", asked, turn, avoid_keys=avoid)
    assert target == "caseIds"

def test_ladder_cooldown():
    # phoneNumbers asked recently
    intel = {}
    asked = {"phoneNumbers": 9} # Asked at turn 9
    turn = 10 # Current turn 10. Diff = 1 < 4 (cooldown)
    
    # Should skip phoneNumbers and go to caseIds
    target = choose_ladder_target(intel, "BANK_IMPERSONATION", asked, turn, cooldown_turns=4)
    assert target == "caseIds"

def test_ladder_fallback_relax_cooldown():
    # All blocked by cooldown or missing, but force relax if no other option
    # Actually, the logic is:
    # 1. Try strict (not blocked by cooldown)
    # 2. If nothing found, try relaxed (ignore cooldown if missing)
    
    intel = {}
    asked = {"phoneNumbers": 9}
    turn = 10
    # "phoneNumbers" is 1st preference, but on cooldown.
    # "caseIds" is 2nd preference.
    
    # If "caseIds" is NOT on cooldown, we pick it (Strict pass).
    target = choose_ladder_target(intel, "BANK_IMPERSONATION", asked, turn)
    assert target == "caseIds" 
    
    # Now suppose "caseIds" is ALSO on cooldown?
    asked["caseIds"] = 9
    # And "phishingLinks", "department", "bankAccounts" to force exhaustion
    asked["phishingLinks"] = 9
    asked["department"] = 9
    asked["bankAccounts"] = 9
    
    # Let's test the specific "Relax" logic.
    # Order: phoneNumbers, caseIds...
    # If phoneNumbers is missing but on cooldown, and caseIds is missing and on cooldown...
    # The Relax pass says: 
    # for k in plan.order: ... if not _has_vals(intel, k): return k
    # So it should return the first missing one, ignoring cooldown.
    
    target = choose_ladder_target(intel, "BANK_IMPERSONATION", asked, turn)
    assert target == "phoneNumbers" # It should cycle back to the first missing one.

def test_unknown_scam_type():
    target = choose_ladder_target({}, "UNKNOWN", {}, 10)
    assert target is None

