# Security, Privacy & Retention

## PII Minimization
- **Redaction**: Enabled by default (`ENABLE_PII_REDACTION`).
- **Logs**: Sensitive fields (`text`, `message`, `reply`) replaced with `[REDACTED:Nchars]`.
- **Evidence**: Field-level encryption (future roadmap, currently using Redis ACLs).

## Data Retention
- **Operational Logs**: `LOG_RETENTION_DAYS` (default 180).
- **Evidence**: `EVIDENCE_RETENTION_DAYS` (default 365, unless legal hold active).
- **Implementation**: Currently manual pruning or cloud-provider lifecycle policies (e.g. Cloud Logging / Cloud Storage TTL).

## Access Control
- **Admin API**: Protected by API Key (RBAC/ABAC foundation).
- **Public API**: Rate-limited (upstream), authentication optional via `API_KEY`.
- **Network**: Redis guarded by password/ACL; internal worker communication isolated.
