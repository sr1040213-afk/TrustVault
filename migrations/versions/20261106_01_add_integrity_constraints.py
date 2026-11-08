
from alembic import op

revision = "20261106_01"
down_revision = "20261105_00"
branch_labels = None
depends_on = None


def upgrade():
    op.create_check_constraint(
        "ck_user_role",
        "user",
        "role IN ('admin', 'owner', 'viewer')"
    )

    op.create_check_constraint(
        "ck_document_sha256_length",
        "document",
        "length(sha256) = 64"
    )

    op.create_check_constraint(
        "ck_document_size_nonnegative",
        "document",
        "size >= 0"
    )

    op.create_check_constraint(
        "ck_grant_permission",
        "grant",
        "permission IN ('read', 'edit')"
    )

    op.create_check_constraint(
        "ck_audit_outcome",
        "audit_event",
        "outcome IN ('success', 'denied', 'error', 'integrity_failure')"
    )

    op.create_check_constraint(
        "ck_audit_previous_mac_length",
        "audit_event",
        "length(previous_mac) = 64"
    )

    op.create_check_constraint(
        "ck_audit_event_mac_length",
        "audit_event",
        "length(event_mac) = 64"
    )


def downgrade():
    op.drop_constraint(
        "ck_audit_event_mac_length", "audit_event", type_="check"
    )
    op.drop_constraint(
        "ck_audit_previous_mac_length", "audit_event", type_="check"
    )
    op.drop_constraint(
        "ck_audit_outcome", "audit_event", type_="check"
    )
    op.drop_constraint(
        "ck_grant_permission", "grant", type_="check"
    )
    op.drop_constraint(
        "ck_document_size_nonnegative", "document", type_="check"
    )
    op.drop_constraint(
        "ck_document_sha256_length", "document", type_="check"
    )
    op.drop_constraint(
        "ck_user_role", "user", type_="check"
    )
