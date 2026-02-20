from app.settings import settings
from app.core.state_machine import (
    BF_S0, BF_S1, BF_S2, BF_S3, BF_S4, BF_S5
)

# Intents

# Interaction Surface: State Acknowledgment
# Expected Artifact Yield: None
# Repeatability: Repeatable
# Relation: Precursor to INT_CHANNEL_FAIL or INT_ASK_* sequences
INT_ACK_CONCERN = "INT_ACK_CONCERN"

# Interaction Surface: Boundary Assertion
# Expected Artifact Yield: None
# Repeatability: Single-Use
# Relation: Unlocks INT_CHANNEL_FAIL; Suppresses sensitive data ingress
INT_REFUSE_SENSITIVE_ONCE = "INT_REFUSE_SENSITIVE_ONCE"

# Interaction Surface: Channel Inhibition / Controlled Failure
# Expected Artifact Yield: upiIds, bankAccounts
# Repeatability: Repeatable
# Relation: May trigger INT_ASK_ALT_VERIFICATION
INT_CHANNEL_FAIL = "INT_CHANNEL_FAIL"

# Interaction Surface: Domain Verification
# Expected Artifact Yield: phishingLinks
# Repeatability: Repeatable
# Relation: Unlocks domain analysis subsystems
INT_ASK_OFFICIAL_WEBSITE = "INT_ASK_OFFICIAL_WEBSITE"

# Interaction Surface: Authority Verification
# Expected Artifact Yield: phoneNumbers
# Repeatability: Repeatable
# Relation: Cross-references carrier registry
INT_ASK_OFFICIAL_HELPLINE = "INT_ASK_OFFICIAL_HELPLINE"

# Interaction Surface: Process Verification
# Expected Artifact Yield: identifiers (reference codes)
# Repeatability: Single-Use per session segment
# Relation: Validates process coherence
INT_ASK_TICKET_REF = "INT_ASK_TICKET_REF"

# Interaction Surface: Entity Verification
# Expected Artifact Yield: organizations
# Repeatability: Single-Use
# Relation: Maps to organizational hierarchy
INT_ASK_DEPARTMENT_BRANCH = "INT_ASK_DEPARTMENT_BRANCH"

# Interaction Surface: Alternative Channel Negotiation
# Expected Artifact Yield: phoneNumbers, upiIds
# Repeatability: Repeatable
# Relation: Fallback for INT_CHANNEL_FAIL
INT_ASK_ALT_VERIFICATION = "INT_ASK_ALT_VERIFICATION"

# Interaction Surface: Persistent Failure State
# Expected Artifact Yield: bankAccounts
# Repeatability: Repeatable
# Relation: Escalation of INT_CHANNEL_FAIL
INT_SECONDARY_FAIL = "INT_SECONDARY_FAIL"

# Interaction Surface: Session Finalization
# Expected Artifact Yield: None
# Repeatability: Single-Use
# Relation: Terminates active session context
INT_CLOSE_AND_VERIFY_SELF = "INT_CLOSE_AND_VERIFY_SELF"


# Intent Groupings

# Intents capable of extracting primary registry artifacts
HIGH_YIELD_ARTIFACT_INTENTS = {
    INT_CHANNEL_FAIL,
    INT_ASK_OFFICIAL_WEBSITE,
    INT_ASK_OFFICIAL_HELPLINE,
    INT_ASK_ALT_VERIFICATION,
    INT_SECONDARY_FAIL
}

# Intents enforcing security boundaries without data yield
SINGLE_USE_BOUNDARY_INTENTS = {
    INT_REFUSE_SENSITIVE_ONCE,
    INT_CLOSE_AND_VERIFY_SELF
}

# Intents representing non-functional transactional states
SECONDARY_FAILURE_INTENTS = {
    INT_SECONDARY_FAIL,
    INT_CHANNEL_FAIL
}

# Intents marking session termination
CLOSING_INTENTS = {
    INT_CLOSE_AND_VERIFY_SELF
}

# How many previous turns to consider before we allow repeating ALT_VERIFICATION
# Increasing to 2 helps avoid visible loops in short evaluator runs.
_ALT_COOLDOWN_WINDOW = int(getattr(settings, "ALT_COOLDOWN_WINDOW", 2))

# Group B: semantic cooldown & OTP pressure (read from settings, sane defaults)
_ALT_SEMANTIC_WINDOW = int(getattr(settings, "ALT_SEMANTIC_WINDOW", 5))
_ALT_MAX_USES_IN_WINDOW = int(getattr(settings, "ALT_MAX_USES_IN_WINDOW", 1))
_OTP_PRESSURE_WINDOW = int(getattr(settings, "OTP_PRESSURE_WINDOW", 4))
_OTP_PRESSURE_THRESHOLD = int(getattr(settings, "OTP_PRESSURE_THRESHOLD", 2))
