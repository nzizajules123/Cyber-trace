"""Add organizations, users, RBAC memberships, sessions, password resets, system audit logs, and case notes."""

from alembic import op
import sqlalchemy as sa

revision = "20261124_05"
down_revision = "20261123_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("slug", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("allow_registration", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("deployment_mode", sa.String(length=16), server_default="LOCAL", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_organizations_uuid", "organizations", ["uuid"], unique=True)
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=160), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("mfa_secret", sa.String(length=64), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_uuid", "users", ["uuid"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=32), server_default="INVESTIGATOR", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_org_membership_org_user"),
    )
    op.create_index("ix_org_memberships_org_id", "organization_memberships", ["organization_id"], unique=False)
    op.create_index("ix_org_memberships_user_id", "organization_memberships", ["user_id"], unique=False)

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_sessions_token_hash", "user_sessions", ["token_hash"], unique=True)
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"], unique=False)
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"], unique=False)

    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_password_reset_tokens_token_hash", "password_reset_tokens", ["token_hash"], unique=True)

    op.create_table(
        "system_audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("actor_email", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_system_audit_logs_org_id", "system_audit_logs", ["organization_id"], unique=False)
    op.create_index("ix_system_audit_logs_action", "system_audit_logs", ["action"], unique=False)
    op.create_index("ix_system_audit_logs_created_at", "system_audit_logs", ["created_at"], unique=False)

    op.create_table(
        "case_notes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("author_id", sa.Integer(), nullable=True),
        sa.Column("author_name", sa.String(length=160), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_case_notes_case_id", "case_notes", ["case_id"], unique=False)

    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("cases") as batch:
            batch.add_column(sa.Column("organization_id", sa.Integer(), nullable=True))
            batch.add_column(sa.Column("sync_uuid", sa.String(length=36), nullable=True))
            batch.add_column(sa.Column("sync_version", sa.Integer(), server_default="1", nullable=False))
    else:
        op.add_column("cases", sa.Column("organization_id", sa.Integer(), nullable=True))
        op.add_column("cases", sa.Column("sync_uuid", sa.String(length=36), nullable=True))
        op.add_column("cases", sa.Column("sync_version", sa.Integer(), server_default="1", nullable=False))
        op.create_foreign_key(
            "fk_cases_organization_id", "cases", "organizations", ["organization_id"], ["id"], ondelete="SET NULL"
        )
    op.create_index("ix_cases_organization_id", "cases", ["organization_id"], unique=False)
    op.create_index("ix_cases_sync_uuid", "cases", ["sync_uuid"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_cases_sync_uuid", table_name="cases")
    op.drop_index("ix_cases_organization_id", table_name="cases")
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("cases") as batch:
            batch.drop_column("sync_version")
            batch.drop_column("sync_uuid")
            batch.drop_column("organization_id")
    else:
        op.drop_constraint("fk_cases_organization_id", "cases", type_="foreignkey")
        op.drop_column("cases", "sync_version")
        op.drop_column("cases", "sync_uuid")
        op.drop_column("cases", "organization_id")

    op.drop_table("case_notes")
    op.drop_table("system_audit_logs")
    op.drop_table("password_reset_tokens")
    op.drop_table("user_sessions")
    op.drop_table("organization_memberships")
    op.drop_table("users")
    op.drop_table("organizations")
