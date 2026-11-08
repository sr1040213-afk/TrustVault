
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import CheckConstraint, UniqueConstraint
from .extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "role IN ('admin', 'owner', 'viewer')",
            name="ck_user_role"
        ),
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.active


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(80), nullable=False, default="General")
    original_name = db.Column(db.String(255), nullable=False)
    storage_name = db.Column(db.String(80), unique=True, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    deleted_at = db.Column(db.DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("length(sha256) = 64", name="ck_document_sha256_length"),
        CheckConstraint("size >= 0", name="ck_document_size_nonnegative"),
    )

    owner = db.relationship("User", foreign_keys=[owner_id])


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    permission = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_document_user_grant"),
        CheckConstraint(
            "permission IN ('read', 'edit')",
            name="ck_grant_permission"
        ),
    )

    user = db.relationship("User")
    document = db.relationship("Document")


class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"))
    action = db.Column(db.String(60), nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    detail = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    previous_mac = db.Column(db.String(64), nullable=False)
    event_mac = db.Column(db.String(64), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "outcome IN ('success', 'denied', 'error', 'integrity_failure')",
            name="ck_audit_outcome"
        ),
        CheckConstraint(
            "length(previous_mac) = 64",
            name="ck_audit_previous_mac_length"
        ),
        CheckConstraint(
            "length(event_mac) = 64",
            name="ck_audit_event_mac_length"
        ),
    )

    actor = db.relationship("User")
    document = db.relationship("Document")
