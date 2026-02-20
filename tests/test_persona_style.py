import pytest
from app.core.red_flags import choose_red_flag

def test_persona_style_rotation_normal():
    # Normal mode (no escalation)
    # 1. No history -> SKEPTICAL
    # Use "OTP" to trigger a match so we hit the rotation logic
    rf1 = choose_red_flag("OTP please", recent_styles=[], escalation=False)
    assert rf1.style == "SKEPTICAL"
    
    # 2. History ends with SKEPTICAL -> CONFUSION
    rf2 = choose_red_flag("OTP please", recent_styles=["SKEPTICAL"], escalation=False)
    assert rf2.style == "CONFUSION"
    
    # 3. History ends with CONFUSION -> SKEPTICAL
    rf3 = choose_red_flag("OTP please", recent_styles=["CONFUSION"], escalation=False)
    assert rf3.style == "SKEPTICAL"

def test_persona_style_rotation_escalation():
    # Escalation mode
    # 1. No history -> TECH_FRICTION
    rf1 = choose_red_flag("OTP please", recent_styles=[], escalation=True)
    assert rf1.style == "TECH_FRICTION"
    
    # 2. History ends with TECH_FRICTION -> DELAY
    rf2 = choose_red_flag("OTP please", recent_styles=["TECH_FRICTION"], escalation=True)
    assert rf2.style == "DELAY"
    
    # 3. History ends with DELAY -> TECH_FRICTION
    rf3 = choose_red_flag("OTP please", recent_styles=["DELAY"], escalation=True)
    assert rf3.style == "TECH_FRICTION"

def test_persona_style_cues():
    # Verify cues for specific styles and tags
    # OTP_REQUEST + CONFUSION
    rf = choose_red_flag("send me otp", recent_styles=["SKEPTICAL"], escalation=False) # -> CONFUSION
    assert rf.tag == "OTP_REQUEST"
    assert rf.style == "CONFUSION"
    assert rf.prefix in [
        "I’m not comfortable sharing an OTP on chat.",
        "I’m a bit unsure why an OTP is needed here.",
    ]

    # OTP_REQUEST + SKEPTICAL
    rf = choose_red_flag("send me otp", recent_styles=["CONFUSION"], escalation=False) # -> SKEPTICAL
    assert rf.style == "SKEPTICAL"
    assert rf.prefix in [
        "I don’t usually share OTPs over messages.",
        "An OTP request on chat makes me hesitant.",
    ]

    # THREAT + DELAY
    rf = choose_red_flag("block account now", recent_styles=["TECH_FRICTION"], escalation=True) # -> DELAY
    assert rf.tag == "THREAT_PRESSURE"
    assert rf.style == "DELAY"
    assert rf.prefix in [
        "I’ll need a moment before I can respond further.",
    ]
