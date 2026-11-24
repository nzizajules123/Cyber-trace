"""Add url_investigations table for Digital Footprint website research."""

from alembic import op
import sqlalchemy as sa

revision = "20261123_04"
down_revision = "20261123_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "url_investigations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("investigation_code", sa.String(length=32), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("final_url", sa.String(length=2048), nullable=True),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("submitted_by", sa.String(length=160), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("page_title", sa.String(length=512), nullable=True),
        sa.Column("snapshot_sha256", sa.String(length=64), nullable=True),
        sa.Column("evidence_code", sa.String(length=32), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("dns_info_json", sa.JSON(), nullable=False),
        sa.Column("tls_info_json", sa.JSON(), nullable=False),
        sa.Column("http_info_json", sa.JSON(), nullable=False),
        sa.Column("security_headers_json", sa.JSON(), nullable=False),
        sa.Column("artifacts_json", sa.JSON(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.current_timestamp(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_url_investigations_code", "url_investigations", ["investigation_code"], unique=True)
    op.create_index("ix_url_investigations_case_id", "url_investigations", ["case_id"], unique=False)
    op.create_index("ix_url_investigations_domain", "url_investigations", ["domain"], unique=False)
    op.create_index("ix_url_investigations_created_at", "url_investigations", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_table("url_investigations")
