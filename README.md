# TrustVault — Secure Document Sharing \& Audit Platform

Flask portfolio application for document-level authorization, private file storage, integrity checks and HMAC-chained audit events.

## Implemented

* Owner, Viewer and Admin roles; Admin role provisioning in the console.
* Document Read/Edit grants; owner sharing; immediate per-request revocation checks.
* Private file storage outside static; extension allowlist and basic PDF/image/TXT/Office-container checks.
* SHA-256 at upload and before download; tampered object returns HTTP 409 and is audited.
* HMAC-SHA256 audit event recomputation and previous-event linkage verification.
* CSRF protection, 10 MiB request limit, safer session-cookie defaults and baseline security headers.
* Admin monitoring without automatic access to document contents.
* Added tests for authorization, revocation, HMAC tampering, modified stored files and fake PDF uploads.

## Windows setup

```powershell
py -3.11 -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

Open http://127.0.0.1:5000. Keep the terminal open. Set independent random `SECRET\_KEY` and `AUDIT\_HMAC\_KEY` values in `.env`; never commit `.env`. Set `COOKIE\_SECURE=1` only behind HTTPS.

## Roles

\## Roles

Registration creates Viewer accounts by default. Users cannot self-assign Owner or Admin roles. For a fresh local demo, follow `docs/ADMIN\_BOOTSTRAP.md` to provision the first admin. Admins can manage user roles and activate/deactivate accounts.

## Tests



Run `python -m pytest -q` after installing requirements and activating the virtual environment. The authorization and security test suite has passed locally during development. Re-run the suite after any code changes.

## Production caveat

Not security-certified or ready for confidential production data without review. Remaining controls: production migrations, HTTPS deployment, rate limiting, MFA, account verification/recovery, malware scanning/CDR, concurrency-safe audit writes, external audit anchoring, monitoring, backups, retention/deletion policy and independent penetration testing.

## Existing database

New HMAC canonicalization differs from the starter archive. Use a fresh demo DB or perform a reviewed migration. Old starter audit events will not verify with the new verifier. Never silently discard production audit history.
