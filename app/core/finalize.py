from typing import Optional
from app.core.termination import decide_termination

def should_finalize(session) -> Optional[str]:
    """
    Decide whether to end engagement and trigger final callback.

    INVARIANT: Finalization is DETRIMINISTIC and REGISTRY-GATED.
    - No sentiment analysis or conversation length heuristics.
    - Driven SOLELY by:
      1) Artifact Registry state (IOC counts)
      2) Controller counters (No-progress / Repeat limits)

    Returns the reason string if finalization is required, else None.
    """
    # Delegate to unified policy to prevent control-loop divergence.
    return decide_termination(session=session, controller_out=None)
