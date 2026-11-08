# Deployment checklist

1. Install pinned requirements.
2. Use PostgreSQL and reviewed migrations; `create_all()` is not a migration tool.
3. Generate independent random `SECRET_KEY` and `AUDIT_HMAC_KEY`; keep them in a secrets manager.
4. Use HTTPS; set `COOKIE_SECURE=1`, `FLASK_DEBUG=0`.
5. Use a production WSGI server. Serialize audit writes before multi-worker scaling.
6. Store private objects on a restricted persistent volume.
7. Add malware scanning/CDR, rate limiting, MFA, verification/recovery, quotas, monitoring and backups.
8. Define retention, physical deletion and incident response.
9. Run pytest, dependency scanning, SAST/DAST and independent penetration testing.
10. Externally anchor audit chain heads.
11. Fresh DB or reviewed migration required for new HMAC format.
