from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.case import CaseSeverity


class FindingConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingStatus(str, Enum):
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATED = "MITIGATED"


class ForensicEvent(Base):
    __tablename__ = "forensic_events"
    __table_args__ = (
        Index("ix_forensic_events_case_time", "case_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="Other")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    action: Mapped[str | None] = mapped_column(String(160), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    raw_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extracted_iocs_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.current_timestamp(),
    )

    case: Mapped["Case"] = relationship()
    evidence: Mapped["EvidenceItem"] = relationship()


class ForensicFinding(Base):
    __tablename__ = "forensic_findings"
    __table_args__ = (
        Index("ix_forensic_findings_case_status", "case_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence_items.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[CaseSeverity] = mapped_column(
        SqlEnum(
            CaseSeverity,
            name="ck_finding_severity",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_type: [item.value for item in enum_type],
            length=16,
        ),
        nullable=False,
        default=CaseSeverity.MEDIUM,
        server_default=CaseSeverity.MEDIUM.value,
    )
    confidence: Mapped[FindingConfidence] = mapped_column(
        SqlEnum(
            FindingConfidence,
            name="ck_finding_confidence",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_type: [item.value for item in enum_type],
            length=16,
        ),
        nullable=False,
        default=FindingConfidence.MEDIUM,
        server_default=FindingConfidence.MEDIUM.value,
    )
    status: Mapped[FindingStatus] = mapped_column(
        SqlEnum(
            FindingStatus,
            name="ck_finding_status",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_type: [item.value for item in enum_type],
            length=32,
        ),
        nullable=False,
        default=FindingStatus.REQUIRES_REVIEW,
        server_default=FindingStatus.REQUIRES_REVIEW.value,
        index=True,
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    indicators_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewer_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.current_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=func.current_timestamp(),
    )

    case: Mapped["Case"] = relationship()
    evidence: Mapped["EvidenceItem | None"] = relationship()
