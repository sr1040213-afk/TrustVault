"""create initial schema

Revision ID: 20261105_00
Revises:
Create Date: 2026-11-08
"""

from alembic import op
import sqlalchemy as sa


revision = "20261105_00"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # 1. Users
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_user_email", "user", ["email"], unique=True)

    # 2. Documents
    op.create_table(
        "document",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column("title", sa.String(180), nullable=False),
        sa.Column("category", sa.String(80), nullable=False),
        sa.Column("original_name", sa.String(255), nullable=False),
        sa.Column("storage_name", sa.String(80), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("mime_type", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("storage_name"),
    )
    op.create_index("ix_document_owner_id", "document", ["owner_id"])

    # 3. Grants
    op.create_table(
        "grant",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "document_id",
            sa.Integer(),
            sa.ForeignKey("document.id"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id"),
            nullable=False,
        ),
        sa.Column("permission", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "document_id",
            "user_id",
            name="uq_document_user_grant",
        ),
    )
    op.create_index("ix_grant_document_id", "grant", ["document_id"])
    op.create_index("ix_grant_user_id", "grant", ["user_id"])

    # 4. Audit events
    op.create_table(
        "audit_event",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=True),
        sa.Column(
            "document_id",
            sa.Integer(),
            sa.ForeignKey("document.id"),
            nullable=True,
        ),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("detail", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_mac", sa.String(64), nullable=False),
        sa.Column("event_mac", sa.String(64), nullable=False),
    )


def downgrade():
    op.drop_table("audit_event")

    op.drop_index("ix_grant_user_id", table_name="grant")
    op.drop_index("ix_grant_document_id", table_name="grant")
    op.drop_table("grant")

    op.drop_index("ix_document_owner_id", table_name="document")
    op.drop_table("document")

    op.drop_index("ix_user_email", table_name="user")
    op.drop_table("user")