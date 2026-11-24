"""Add commercial case fields and case audit history."""

from datetime import datetime

from alembic import op
from alembic import context
import sqlalchemy as sa

revision = "20261120_02"
down_revision = "20261120_01"
branch_labels = None
depends_on = None


def _backfill_case_numbers(connection: sa.Connection) -> None:
    if context.is_offline_mode():
        if connection.dialect.name == "mysql":
            op.execute(
                "UPDATE cases "
                "SET case_number = CONCAT('CT-', YEAR(created_at), '-', LPAD(id, 4, '0')) "
                "WHERE case_number IS NULL"
            )
        else:
            op.execute(
                "UPDATE cases "
                "SET case_number = 'CT-' || strftime('%Y', created_at) || '-' || printf('%04d', id) "
                "WHERE case_number IS NULL"
            )
        return

    rows = connection.execute(
        sa.text("SELECT id, created_at FROM cases WHERE case_number IS NULL")
    ).all()
    for row in rows:
        created_at = row.created_at
        if isinstance(created_at, datetime):
            year = created_at.year
        elif isinstance(created_at, str) and len(created_at) >= 4 and created_at[:4].isdigit():
            year = int(created_at[:4])
        else:
            year = datetime.now().year
        connection.execute(
            sa.text("UPDATE cases SET case_number = :number WHERE id = :id"),
            {"number": f"CT-{year}-{row.id:04d}", "id": row.id},
        )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("cases") as batch:
            batch.drop_constraint("ck_cases_status", type_="check")
            batch.add_column(sa.Column("case_number", sa.String(length=32), nullable=True))
            batch.add_column(
                sa.Column(
                    "severity",
                    sa.String(length=16),
                    server_default="MEDIUM",
                    nullable=False,
                )
            )
            batch.add_column(sa.Column("assigned_to", sa.String(length=160), nullable=True))
            batch.add_column(sa.Column("reporter_name", sa.String(length=160), nullable=True))
            batch.add_column(
                sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False)
            )
    else:
        op.drop_constraint("ck_cases_status", "cases", type_="check")
        op.add_column("cases", sa.Column("case_number", sa.String(length=32), nullable=True))
        op.add_column(
            "cases",
            sa.Column("severity", sa.String(length=16), server_default="MEDIUM", nullable=False),
        )
        op.add_column("cases", sa.Column("assigned_to", sa.String(length=160), nullable=True))
        op.add_column("cases", sa.Column("reporter_name", sa.String(length=160), nullable=True))
        op.add_column(
            "cases",
            sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        )

    connection = op.get_bind()
    _backfill_case_numbers(connection)
    op.execute(
        "UPDATE cases SET assigned_to = assigned_investigator "
        "WHERE assigned_investigator IS NOT NULL AND assigned_to IS NULL"
    )
    op.execute(
        "UPDATE cases SET status = CASE status "
        "WHEN 'Open' THEN 'OPEN' "
        "WHEN 'In Progress' THEN 'IN_PROGRESS' "
        "WHEN 'Under Review' THEN 'IN_PROGRESS' "
        "WHEN 'Closed' THEN 'CLOSED' "
        "ELSE 'OPEN' END"
    )

    if connection.dialect.name == "sqlite":
        with op.batch_alter_table("cases") as batch:
            batch.alter_column(
                "case_number",
                existing_type=sa.String(length=32),
                nullable=False,
            )
            batch.drop_column("assigned_investigator")
            batch.create_check_constraint(
                "ck_cases_status",
                "status IN ('OPEN', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED')",
            )
            batch.create_check_constraint(
                "ck_cases_severity",
                "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            )
    else:
        op.alter_column(
            "cases",
            "case_number",
            existing_type=sa.String(length=32),
            nullable=False,
        )
        op.drop_column("cases", "assigned_investigator")
        op.create_check_constraint(
            "ck_cases_status",
            "cases",
            "status IN ('OPEN', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED')",
        )
        op.create_check_constraint(
            "ck_cases_severity",
            "cases",
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
        )

    op.create_index("ix_cases_case_number", "cases", ["case_number"], unique=True)
    op.create_index("ix_cases_severity", "cases", ["severity"], unique=False)
    op.create_index("ix_cases_is_deleted", "cases", ["is_deleted"], unique=False)
    op.create_index(
        "ix_cases_active_status_severity",
        "cases",
        ["is_deleted", "status", "severity"],
        unique=False,
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=160), nullable=False),
        sa.Column("changes_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.current_timestamp(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_case_id", "audit_logs", ["case_id"], unique=False)
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"], unique=False)
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_case_id", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_cases_active_status_severity", table_name="cases")
    op.drop_index("ix_cases_is_deleted", table_name="cases")
    op.drop_index("ix_cases_severity", table_name="cases")
    op.drop_index("ix_cases_case_number", table_name="cases")

    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("cases") as batch:
            batch.drop_constraint("ck_cases_status", type_="check")
            batch.drop_constraint("ck_cases_severity", type_="check")
            batch.add_column(sa.Column("assigned_investigator", sa.String(length=160), nullable=True))
    else:
        op.drop_constraint("ck_cases_status", "cases", type_="check")
        op.drop_constraint("ck_cases_severity", "cases", type_="check")
        op.add_column("cases", sa.Column("assigned_investigator", sa.String(length=160), nullable=True))

    connection = op.get_bind()
    op.execute(
        "UPDATE cases SET assigned_investigator = assigned_to "
        "WHERE assigned_to IS NOT NULL"
    )
    op.execute(
        "UPDATE cases SET status = CASE status "
        "WHEN 'OPEN' THEN 'Open' "
        "WHEN 'IN_PROGRESS' THEN 'In Progress' "
        "WHEN 'ESCALATED' THEN 'In Progress' "
        "WHEN 'RESOLVED' THEN 'Closed' "
        "WHEN 'CLOSED' THEN 'Closed' "
        "ELSE 'Open' END"
    )

    if connection.dialect.name == "sqlite":
        with op.batch_alter_table("cases") as batch:
            batch.drop_column("case_number")
            batch.drop_column("severity")
            batch.drop_column("assigned_to")
            batch.drop_column("reporter_name")
            batch.drop_column("is_deleted")
            batch.create_check_constraint(
                "ck_cases_status",
                "status IN ('Open', 'In Progress', 'Under Review', 'Closed')",
            )
    else:
        op.drop_column("cases", "case_number")
        op.drop_column("cases", "severity")
        op.drop_column("cases", "assigned_to")
        op.drop_column("cases", "reporter_name")
        op.drop_column("cases", "is_deleted")
        op.create_check_constraint(
            "ck_cases_status",
            "cases",
            "status IN ('Open', 'In Progress', 'Under Review', 'Closed')",
        )
