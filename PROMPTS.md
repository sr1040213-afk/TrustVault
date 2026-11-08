# AI assistance and engineering log

## 2026-11-06 — Initial code audit

* Reviewed Flask routes, SQLAlchemy models, security helpers, templates and authorization tests.
* Identified linkage-only audit verification, missing download-time hash check, extension-only upload validation, missing role-management UI and limited tests.

## 2026-11-06 — Hardening changes

* Added canonical UTC HMAC recomputation and previous-event linkage checks.
* Added conservative content-signature checks and download-time SHA-256 verification.
* Added Admin role-management endpoint/UI, Edit-grant metadata form visibility, baseline HTTP security headers and safer session-cookie defaults.
* Added tests for audit tampering, modified stored files and fake PDF upload.
* Build verification: `compileall` succeeded. Pytest could not start because Flask is not installed in the build environment (`ModuleNotFoundError: flask`). Install requirements and run `pytest -q` locally.
* Subsequent local verification: After activating the project virtual environment, the full local pytest suite passed.

Keep this log accurate. Never commit secrets or customer documents. Do not claim code was tested unless it was run.

## 2026-11-08 — Authorization and access-control verification

* **What was requested:** Review and test role-based document access, sharing permissions, revocation and protection against unauthorized URL access.
* **Tool output:** Local pytest authorization tests verified cross-user access restrictions, Viewer/Admin upload restrictions, Read/Edit grants and immediate revocation.
* **Issue identified:** Authorization behavior needed explicit route-level tests, including attempts to access another user's documents.
* **What was done instead:** Added and ran automated tests for unauthorized document access, permission enforcement, sharing and revocation. The local test suite passed.
* **Fixing commit:** Add the actual GitHub commit URL after committing and pushing the relevant changes.



## 2026-11-08 — Audit integrity and denied-attempt verification

* **What was requested:** Verify that audit events are tamper-evident and unauthorized actions are recorded.
* **Tool output:** The audit HMAC tampering test verified that modifying an audit event causes chain verification to fail. Tests also checked selected denied operations.
* **Issue identified:** Audit integrity and denied-operation recording needed explicit verification rather than relying only on the audit implementation.
* **What was done instead:** Added and ran audit tampering and denied-operation tests, then verified the local test suite.
* **Fixing commit:** Add the actual GitHub commit URL after committing and pushing the relevant changes.



## 2026-11-08 — Activity history and documentation verification

* **What was requested:** Verify user activity history, search access boundaries and project documentation against the implemented routes.
* **Tool output:** Local tests verified authenticated activity history and cross-user activity isolation. README, API.md and THREATS.md were reviewed and updated.
* **Issue identified:** Documentation contained outdated role information and omitted some implemented routes and verified security scenarios.
* **What was done instead:** Corrected the Viewer-by-default registration description, updated route permissions and documented verified threat scenarios.
* **Fixing commit:** Add the actual GitHub commit URL after committing and pushing the relevant changes.
