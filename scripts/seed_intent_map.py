"""
Seed the runtime Intent-Map in Redis so the controller can pass tactic-specific
instructions (FI/GB) to the responder, restricted to ONE targeted artifact.
This script is idempotent and safe to run in local/dev/CI.
"""
import json
import os
from redis import Redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
KEY = os.getenv("REGISTRY_INTENT_MAP_KEY", "registry:intent_map")

INTENT_MAP = {
    # phoneNumbers → ask helpline (FI tone)
    "phoneNumbers": {
        "intent": "INT_ASK_OFFICIAL_HELPLINE",
        "instruction": (
            "[STYLE:FEIGNED] The page keeps timing out on my phone and I feel safer calling. "
            "Could you share the official desk or your direct number so I can confirm? "
            "Ask only for the phone number."
        )
    },
    # phishingLinks → ask mirror/short link (FI tone)
    "phishingLinks": {
        "intent": "INT_ASK_OFFICIAL_WEBSITE",
        "instruction": (
            "[STYLE:FEIGNED] The site isn’t loading here. "
            "Do you have an official mirror or a short link I can open to check? "
            "Ask only for the link."
        )
    },
    # upiIds → ask alternate UPI (GB tone)
    "upiIds": {
        "intent": "INT_ASK_ALT_VERIFICATION",
        "instruction": (
            "[STYLE:GREED] My accountant is setting up a larger transfer, but the first attempt showed a block. "
            "Could you share a different UPI ID so I can try a small test first? "
            "Ask only for the UPI ID."
        )
    },
    # bankAccounts → ask alternate bank account (GB tone)
    "bankAccounts": {
        "intent": "INT_CHANNEL_FAIL",
        "instruction": (
            "[STYLE:GREED] The beneficiary shows maintenance on my side. "
            "Could you provide an alternate bank account so I can try a small test transfer before the high-value wire? "
            "Ask only for the bank account."
        )
    }
}

def main():
    r = Redis.from_url(REDIS_URL, decode_responses=True)
    # Optional: basic validation
    for k, v in INTENT_MAP.items():
        assert isinstance(v, dict) and "intent" in v and "instruction" in v, f"bad entry: {k}"
    r.set(KEY, json.dumps(INTENT_MAP))
    print(f"OK: wrote {KEY} into {REDIS_URL}")

if __name__ == "__main__":
    main()
