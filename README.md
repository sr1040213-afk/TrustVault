# TrustVault - Secure Document Sharing and Audit Platform

Flask portfolio application for document-level authorization, private file storage, integrity checks and HMAC-chained audit events.

## Implemented

- Owner, Viewer and Admin roles; initial Admin and Owner role provisioning.
- Document Read/Edit grants; owner sharing; immediate per-request revocation checks.
- Private file storage outside static; extension allow list and basic PDF/image/TXT/Office-container checks.
- SHA-256 at upload and before download; tampered object returns HTTP 409 and is audited.
- HMAC-SHA256 audit event recomputation and previous-event linkage verification.
- CSRF protection, 10 MiB request limit, safer session-cookie defaults and baseline security headers.
- Admin monitoring without automatic access to document contents.
- Tests for authorization, revocation, HMAC tampering, modified stored files and fake PDF uploads.

## Windows Setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python -m flask --app run.py db upgrade
python run.py
```

Open http://127.0.0.1:5000. Keep the terminal open.

Set independent random `SECRET_KEY`, `AUDIT_HMAC_KEY` and `BOOTSTRAP_SECRET` values in `.env`. Never commit `.env` or publish these secrets. Set `COOKIE_SECURE=1` only behind HTTPS.

## Roles

Registration creates Viewer accounts by default. Users cannot self-assign Owner or Admin roles.

### Initial Admin and Owner Setup

1. Register two separate accounts through the application: one for Admin and another for Owner.
2. Configure a strong `BOOTSTRAP_SECRET` environment variable.
3. Open `/bootstrap-roles` in the browser.
4. Enter the bootstrap secret, the registered Admin email and the registered Owner email.
5. Submit the form. Both accounts must exist and be active.
6. After successful setup, log in using the passwords created during registration.

**Important:**
- Initial role setup is available only once, before an Admin account exists.
- If `BOOTSTRAP_SECRET` is not configured, the setup page returns HTTP 404.
- An incorrect bootstrap secret returns HTTP 403.
- Never expose the bootstrap secret or account passwords publicly.
- After initial setup, Admins can manage user roles and activate/deactivate accounts through the Admin Dashboard.

## Tests

Run:

```powershell
python -m pytest -q
```

Run after installing requirements and activating the virtual environment. The authorization and security test suite has passed locally during development. Re-run the suite after any code changes.

## Production Caveat

Not security-certified or ready for confidential production data without review.

Remaining controls include production migrations, HTTPS deployment, rate limiting, MFA, account verification/recovery, malware scanning/CDR, concurrency-safe audit writes, external audit anchoring, monitoring, backups, retention/deletion policy and independent penetration testing.

## Existing Database

New HMAC canonicalization differs from the starter archive. Use a fresh demo DB or perform a reviewed migration. Old starter audit events will not verify with the new verifier. Never silently discard production audit history.