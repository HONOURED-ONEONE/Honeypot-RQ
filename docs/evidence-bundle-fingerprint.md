# Evidence Bundle & Deterministic Fingerprint

## Purpose
Ensures consistent, reproducible, and contract-compliant reporting.

## Canonicalization
- **Phone Numbers**: E.164 (e.g. `+919876543210`) for Indian mobiles.
- **URLs**: Scheme+host normalized, query params sorted (if applicable), trailing punctuation removed.
- **UPI IDs**: `handle@psp` normalized to lowercase.
- **Emails**: Lowercase, RFC5322-safe subset.

## Validation
- **Invalid Artifacts**: Captured separately if malformed but likely scammy (e.g. partial UPI).
- **Strict Schema**: `HoneypotResponse` schema validation via `pydantic`.
- **List Guarantees**: Artifact lists are always present (even if empty).

## Fingerprint
- **Algorithm**: `sha256` (configurable).
- **Canonical Hash**: Hash of the `canonical` JSON string (sorted keys, compact).
- **Location**: `extractedIntelligence._meta.payloadFingerprint`.

## Contract Version
- `1.1`: Includes new ID categories (caseIds, policyNumbers, orderNumbers).
- Included in `_meta.contractVersion` and `X-Report-Version`.
