# Lightweight keyword signals used to compute suspiciousKeywords.

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "account blocked",
    "account will be blocked",
    "kyc",
    "suspended",
    "upi",
    "refund",
    "cashback",
    "prize",
    "offer expires",
    "click link",
    "immediately",
    "otp",
    "pin",
    "password",
    "bank account",
    "ticket",
    "reference",
    "ref",
    "complaint",
    "branch",
    "department",
    "employee id",
]


def extract_keywords(text: str):
    t = text.lower()
    hits = []
    for k in SUSPICIOUS_KEYWORDS:
        if k in t:
            hits.append(k)
    return hits
