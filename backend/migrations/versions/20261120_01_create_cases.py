"""Create the case management table."""

from alembic import op
import sqlalchemy as sa

revision = "20261120_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("assigned_investigator", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="Open", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.current_timestamp(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.current_timestamp(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('Open', 'In Progress', 'Under Review', 'Closed')",
            name="ck_cases_status",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cases_title", "cases", ["title"], unique=False)
    op.create_index("ix_cases_status", "cases", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_cases_status", table_name="cases")
    op.drop_index("ix_cases_title", table_name="cases")
    op.drop_table("cases")
