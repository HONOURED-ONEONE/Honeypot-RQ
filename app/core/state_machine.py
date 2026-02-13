# Minimal state constants (kept for clarity)

# Interaction Surface: Initial Contact / Handshake
# Expected Artifact Yield: None (Data ingress only)
INIT = "INIT"

# Interaction Surface: Passive Observation
# Expected Artifact Yield: Textual patterns, intent classification
MONITORING = "MONITORING"

# Interaction Surface: Active Verification Sequence
# Expected Artifact Yield: Registry Artifacts (upiIds, phoneNumbers, phishingLinks)
ENGAGED = "ENGAGED"

# Interaction Surface: Finalization / Artifact Serialization
# Expected Artifact Yield: None (State freezing)
READY_TO_REPORT = "READY_TO_REPORT"

# Interaction Surface: Post-Processing / Callback Dispatch
REPORTED = "REPORTED"

# Interaction Surface: Terminal State
CLOSED = "CLOSED"


# Broken-Flow States (Intent-Driven Engineering Surfaces)

# Interaction Surface: Context Initialization & Safety Check
# Registry dependency: None
BF_S0 = "BF_S0"

# Interaction Surface: Authority Displacement / Initial Inquiry
# Registry dependency: phoneNumbers, phishingLinks
BF_S1 = "BF_S1"

# Interaction Surface: Process Verification / Deep Engagement
# Registry dependency: upiIds, bankAccounts, identifiers
BF_S2 = "BF_S2"

# Interaction Surface: Channel Negotiation / Alternative Path
# Registry dependency: phoneNumbers, upiIds
BF_S3 = "BF_S3"

# Interaction Surface: Controlled Failure / Persistent Boundary
# Registry dependency: bankAccounts
BF_S4 = "BF_S4"

# Interaction Surface: Session Termination / Artifact Validation
# Registry dependency: All accrued artifacts
BF_S5 = "BF_S5"