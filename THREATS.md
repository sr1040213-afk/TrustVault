# TrustVault threat model

|Threat|Application control|Residual risk|
|-|-|-|
|IDOR / guessed IDs|Server-side permission checks; unauthorized detail/download concealed as 404|Expand fuzz tests and independent penetration test|
|Revoked URL reuse|Active grant checked against DB each request|Already-downloaded copies cannot be recalled|
|Viewer mutation|Viewer upload blocked; edit requires Owner or Edit grant|Test every future mutation endpoint|
|Stored-file tampering|SHA-256 before download; mismatch audited and returns 409|Protect host, DB and backups|
|Fake extension|Allowlist and conservative signature/UTF-8/ZIP checks|Not malware scanning; add AV/CDR|
|Audit-row modification|HMAC recomputation and previous-event verification|DB plus HMAC key compromise; externally anchor chain heads|
|CSRF|Flask-WTF tokens|Test all state-changing routes|
|Session theft|HttpOnly, SameSite=Lax; Secure configurable|HTTPS, rotation, MFA|
|Oversized upload|10 MiB request cap|Proxy limits and quotas|
|Admin snooping|Admin does not bypass document authorization|Dual-control break-glass process if required|
|Credential guessing|Werkzeug password hashing|Rate limiting and MFA|
|Concurrent audit writes|Sequential chain logic|Multi-worker writes need DB serialization|

Each event MAC covers actor, document, action, outcome, detail, UTC timestamp and previous MAC. Keep the HMAC key outside the database. Basic file signatures do not guarantee benign content. Documents are soft-deleted; physical blob cleanup/retention policy remain deployment work.

Not included: malware scanner, DLP, MFA, rate limiter, email verification, password reset, external immutable audit anchor, concurrency-safe audit serialization or independent security certification.

\## Verified automated security scenarios



The local pytest suite includes tests for:



\- Cross-user document access and download denial.

\- Viewer and Admin upload restrictions.

\- Read/Edit grant enforcement.

\- Immediate access denial after permission revocation.

\- Prevention of self-assigned privileged roles.

\- Inactive-user login and existing-session revocation.

\- CSRF protection and security response headers.

\- SHA-256 detection of modified stored files.

\- Rejection of fake PDF uploads.

\- HMAC audit-chain tampering detection.

\- Unauthorized admin access and document deletion restrictions.

\- User activity-history authentication and cross-user isolation.



\## Accepted risks



The application does not claim protection against a compromised host, database, or HMAC key. Malware scanning, MFA, rate limiting, external immutable audit anchoring, and concurrency-safe audit serialization remain deployment risks.
