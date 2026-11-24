"""Add evidence vault, integrity verification, custody ledger, forensic events, and findings."""

from alembic import op
import sqlalchemy as sa

revision = "20261123_03"
down_revision = "20261120_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_items",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("evidence_code", sa.String(length=32), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("stored_path", sa.String(length=512), nullable=False),
        sa.Column("mime_type", sa.String(length=120), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("sha512", sa.String(length=128), nullable=False),
        sa.Column("md5", sa.String(length=32), nullable=False),
        sa.Column("evidence_type", sa.String(length=32), server_default="LOG_FILE", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="INGESTED", nullable=False),
        sa.Column("acquisition_source", sa.String(length=200), nullable=True),
        sa.Column("collected_by", sa.String(length=160), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_items_evidence_code", "evidence_items", ["evidence_code"], unique=True)
    op.create_index("ix_evidence_items_case_id", "evidence_items", ["case_id"], unique=False)
    op.create_index("ix_evidence_items_sha256", "evidence_items", ["sha256"], unique=False)
    op.create_index("ix_evidence_items_is_deleted", "evidence_items", ["is_deleted"], unique=False)
    op.create_index("ix_evidence_case_active", "evidence_items", ["case_id", "is_deleted"], unique=False)

    op.create_table(
        "evidence_verifications",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("expected_hash", sa.String(length=128), nullable=False),
        sa.Column("computed_hash", sa.String(length=128), nullable=True),
        sa.Column("comparison_performed", sa.Boolean(), nullable=False),
        sa.Column("sha256_matches", sa.Boolean(), nullable=False),
        sa.Column("verified_by", sa.String(length=160), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_verifications_evidence_id", "evidence_verifications", ["evidence_id"], unique=False)
    op.create_index("ix_evidence_verifications_verified_at", "evidence_verifications", ["verified_at"], unique=False)

    op.create_table(
        "custody_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("actor", sa.String(length=160), nullable=False),
        sa.Column("from_custodian", sa.String(length=160), nullable=True),
        sa.Column("to_custodian", sa.String(length=160), nullable=True),
        sa.Column("location", sa.String(length=200), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_custody_events_evidence_id", "custody_events", ["evidence_id"], unique=False)
    op.create_index("ix_custody_events_action", "custody_events", ["action"], unique=False)
    op.create_index("ix_custody_events_entry_hash", "custody_events", ["entry_hash"], unique=False)
    op.create_index("ix_custody_events_occurred_at", "custody_events", ["occurred_at"], unique=False)

    op.create_table(
        "forensic_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("username", sa.String(length=160), nullable=True),
        sa.Column("action", sa.String(length=160), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("raw_line", sa.Text(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("extracted_iocs_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_forensic_events_case_id", "forensic_events", ["case_id"], unique=False)
    op.create_index("ix_forensic_events_evidence_id", "forensic_events", ["evidence_id"], unique=False)
    op.create_index("ix_forensic_events_occurred_at", "forensic_events", ["occurred_at"], unique=False)
    op.create_index("ix_forensic_events_event_type", "forensic_events", ["event_type"], unique=False)
    op.create_index("ix_forensic_events_source_ip", "forensic_events", ["source_ip"], unique=False)
    op.create_index("ix_forensic_events_username", "forensic_events", ["username"], unique=False)
    op.create_index("ix_forensic_events_case_time", "forensic_events", ["case_id", "occurred_at"], unique=False)

    op.create_table(
        "forensic_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="MEDIUM", nullable=False),
        sa.Column("confidence", sa.String(length=16), server_default="MEDIUM", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="REQUIRES_REVIEW", nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("indicators_json", sa.JSON(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewer_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.current_timestamp(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_forensic_findings_case_id", "forensic_findings", ["case_id"], unique=False)
    op.create_index("ix_forensic_findings_evidence_id", "forensic_findings", ["evidence_id"], unique=False)
    op.create_index("ix_forensic_findings_rule_id", "forensic_findings", ["rule_id"], unique=False)
    op.create_index("ix_forensic_findings_status", "forensic_findings", ["status"], unique=False)
    op.create_index("ix_forensic_findings_case_status", "forensic_findings", ["case_id", "status"], unique=False)


def downgrade() -> None:
    op.drop_table("forensic_findings")
    op.drop_table("forensic_events")
    op.drop_table("custody_events")
    op.drop_table("evidence_verifications")
    op.drop_table("evidence_items")
