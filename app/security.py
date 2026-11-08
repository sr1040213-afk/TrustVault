import hashlib, hmac, json, mimetypes
from datetime import datetime, timezone
from flask import current_app
from flask_login import current_user
from .extensions import db
from .models import Grant, AuditEvent
from flask import has_request_context

ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "pptx", "txt", "png", "jpg", "jpeg"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

def allowed_file(filename):
    return bool(filename and "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS)

def sha256_file(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()

def validate_file_content(filename, stream):
    """Conservative signature checks; ZIP-based Office files must be valid ZIP containers."""
    ext = filename.rsplit(".", 1)[-1].lower()
    head = stream.read(16)
    stream.seek(0)
    if ext == "pdf": return head.startswith(b"%PDF-")
    if ext in {"jpg", "jpeg"}: return head.startswith(b"\xff\xd8\xff")
    if ext == "png": return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in {"docx", "xlsx", "pptx"}:
        try:
            import zipfile
            with zipfile.ZipFile(stream) as z:
                names = set(z.namelist())
                required = {"[Content_Types].xml", "_rels/.rels"}
                return required.issubset(names) and any(n.startswith("word/") if ext == "docx" else n.startswith("xl/") if ext == "xlsx" else n.startswith("ppt/") for n in names)
        except (zipfile.BadZipFile, OSError): return False
        finally: stream.seek(0)
    if ext == "txt":
        try:
            stream.read().decode("utf-8")
            return True
        except UnicodeDecodeError: return False
        finally: stream.seek(0)
    return False

def can_access(document, user, permission="read"):
    if not user or not getattr(user, "is_authenticated", False) or not user.is_active or document.deleted_at is not None:
        return False
    if document.owner_id == user.id: return True
    grant = Grant.query.filter_by(document_id=document.id, user_id=user.id, revoked_at=None).first()
    if not grant: return False
    return grant.permission == "edit" if permission == "edit" else grant.permission in {"read", "edit"}

def _utc_iso(value):
    if value.tzinfo is None: value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()

def _audit_payload(actor_id, document_id, action, outcome, detail, created_at, previous):
    return {"actor_id": actor_id, "document_id": document_id, "action": action,
            "outcome": outcome, "detail": detail, "created_at": _utc_iso(created_at),
            "previous_mac": previous}

def _mac(payload):
    message = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(current_app.config["AUDIT_HMAC_KEY"], message, hashlib.sha256).hexdigest()

def append_audit(action, outcome="success", document_id=None, detail=""):
    last = AuditEvent.query.order_by(AuditEvent.id.desc()).first()
    previous = last.event_mac if last else "0" * 64
    now = datetime.now(timezone.utc)

    actor_id = None

    if has_request_context():
        user = current_user
        if user is not None and user.is_authenticated:
            actor_id = user.id

    detail = detail[:500]

    payload = _audit_payload(
        actor_id, document_id, action, outcome, detail, now, previous
    )

    event = AuditEvent(
        actor_id=actor_id,
        document_id=document_id,
        action=action,
        outcome=outcome,
        detail=detail,
        created_at=now,
        previous_mac=previous,
        event_mac=_mac(payload)
    )

    db.session.add(event)
    return event

def verify_audit_chain():
    previous = "0" * 64
    for event in AuditEvent.query.order_by(AuditEvent.id.asc()).all():
        if not hmac.compare_digest(event.previous_mac, previous): return False
        payload = _audit_payload(event.actor_id, event.document_id, event.action, event.outcome,
                                 event.detail, event.created_at, event.previous_mac)
        expected = _mac(payload)
        if not hmac.compare_digest(event.event_mac, expected): return False
        previous = event.event_mac
    return True
