from alembic import op

revision = "20261106_01"
down_revision = "20261105_00"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("user", recreate="always") as batch:
        batch.create_check_constraint(
            "ck_user_role",
            "role IN ('admin', 'owner', 'viewer')"
        )

    with op.batch_alter_table("document", recreate="always") as batch:
        batch.create_check_constraint(
            "ck_document_sha256_length",
            "length(sha256) = 64"
        )
        batch.create_check_constraint(
            "ck_document_size_nonnegative",
            "size >= 0"
        )

    with op.batch_alter_table("grant", recreate="always") as batch:
        batch.create_check_constraint(
            "ck_grant_permission",
            "permission IN ('read', 'edit')"
        )

    with op.batch_alter_table("audit_event", recreate="always") as batch:
        batch.create_check_constraint(
            "ck_audit_outcome",
            "outcome IN ('success', 'denied', 'error', 'integrity_failure')"
        )
        batch.create_check_constraint(
            "ck_audit_previous_mac_length",
            "length(previous_mac) = 64"
        )
        batch.create_check_constraint(
            "ck_audit_event_mac_length",
            "length(event_mac) = 64"
        )


def downgrade():
    with op.batch_alter_table("audit_event", recreate="always") as batch:
        batch.drop_constraint("ck_audit_event_mac_length", type_="check")
        batch.drop_constraint("ck_audit_previous_mac_length", type_="check")
        batch.drop_constraint("ck_audit_outcome", type_="check")

    with op.batch_alter_table("grant", recreate="always") as batch:
        batch.drop_constraint("ck_grant_permission", type_="check")

    with op.batch_alter_table("document", recreate="always") as batch:
        batch.drop_constraint("ck_document_size_nonnegative", type_="check")
        batch.drop_constraint("ck_document_sha256_length", type_="check")

    with op.batch_alter_table("user", recreate="always") as batch:
        batch.drop_constraint("ck_user_role", type_="check")
