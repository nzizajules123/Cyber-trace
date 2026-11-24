"""Add ai_conversations and ai_messages tables for AI Investigation Assistant."""

from alembic import op
import sqlalchemy as sa

revision = "20261124_06"
down_revision = "20261124_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_conversations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("conversation_code", sa.String(length=32), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("is_archived", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_conversations_code", "ai_conversations", ["conversation_code"], unique=True)
    op.create_index("ix_ai_conversations_org_id", "ai_conversations", ["organization_id"], unique=False)
    op.create_index("ix_ai_conversations_user_id", "ai_conversations", ["user_id"], unique=False)
    op.create_index("ix_ai_conversations_case_id", "ai_conversations", ["case_id"], unique=False)
    op.create_index("ix_ai_conversations_is_archived", "ai_conversations", ["is_archived"], unique=False)
    op.create_index(
        "ix_ai_conversations_org_user_active",
        "ai_conversations",
        ["organization_id", "user_id", "is_archived"],
        unique=False,
    )

    op.create_table(
        "ai_messages",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("conversation_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("mode", sa.String(length=32), server_default="deterministic", nullable=False),
        sa.Column("provider", sa.String(length=64), server_default="deterministic", nullable=False),
        sa.Column("model_name", sa.String(length=120), server_default="local-deterministic", nullable=False),
        sa.Column("external_data_transmitted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("citations_json", sa.JSON(), nullable=False),
        sa.Column("sections_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["conversation_id"], ["ai_conversations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_messages_conversation_id", "ai_messages", ["conversation_id"], unique=False)
    op.create_index("ix_ai_messages_created_at", "ai_messages", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_table("ai_messages")
    op.drop_table("ai_conversations")
