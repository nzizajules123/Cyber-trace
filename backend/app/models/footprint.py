from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class UrlInvestigation(Base):
    __tablename__ = "url_investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_code: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    final_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    submitted_by: Mapped[str] = mapped_column(String(160), nullable=False, default="system")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="COMPLETED")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    page_title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    snapshot_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dns_info_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    tls_info_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    http_info_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    security_headers_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    artifacts_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.current_timestamp(),
        index=True,
    )

    case: Mapped["Case"] = relationship()
