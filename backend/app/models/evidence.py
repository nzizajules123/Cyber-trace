from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class EvidenceType(str, Enum):
    LOG_FILE = "LOG_FILE"
    DISK_IMAGE = "DISK_IMAGE"
    MEMORY_DUMP = "MEMORY_DUMP"
    NETWORK_CAPTURE = "NETWORK_CAPTURE"
    DOCUMENT = "DOCUMENT"
    OTHER = "OTHER"


class EvidenceStatus(str, Enum):
    INGESTED = "INGESTED"
    ANALYZED = "ANALYZED"
    SEALED = "SEALED"
    ARCHIVED = "ARCHIVED"


class CustodyAction(str, Enum):
    COLLECTED = "COLLECTED"
    TRANSFERRED = "TRANSFERRED"
    ANALYZED = "ANALYZED"
    VERIFIED = "VERIFIED"
    EXPORTED = "EXPORTED"
    SEALED = "SEALED"


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    __table_args__ = (
        Index("ix_evidence_case_active", "case_id", "is_deleted"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_code: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(512), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(120), nullable=False, default="application/octet-stream")
    file_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_type: Mapped[EvidenceType] = mapped_column(
        SqlEnum(
            EvidenceType,
            name="ck_evidence_type",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_type: [item.value for item in enum_type],
            length=32,
        ),
        nullable=False,
        default=EvidenceType.LOG_FILE,
        server_default=EvidenceType.LOG_FILE.value,
    )
    status: Mapped[EvidenceStatus] = mapped_column(
        SqlEnum(
            EvidenceStatus,
            name="ck_evidence_status",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_type: [item.value for item in enum_type],
            length=32,
        ),
        nullable=False,
        default=EvidenceStatus.INGESTED,
        server_default=EvidenceStatus.INGESTED.value,
    )
    acquisition_source: Mapped[str | None] = mapped_column(String(200), nullable=True)
    collected_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0", index=True)
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
    verifications: Mapped[list["EvidenceVerification"]] = relationship(
        back_populates="evidence",
        cascade="all, delete-orphan",
        order_by="EvidenceVerification.verified_at, EvidenceVerification.id",
    )
    custody_events: Mapped[list["CustodyEvent"]] = relationship(
        back_populates="evidence",
        cascade="all, delete-orphan",
        order_by="CustodyEvent.occurred_at, CustodyEvent.id",
    )


class EvidenceVerification(Base):
    __tablename__ = "evidence_verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="SHA-256")
    expected_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    computed_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    comparison_performed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sha256_matches: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified_by: Mapped[str] = mapped_column(String(160), nullable=False, default="system")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.current_timestamp(),
        index=True,
    )

    evidence: Mapped["EvidenceItem"] = relationship(back_populates="verifications")


class CustodyEvent(Base):
    __tablename__ = "custody_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[CustodyAction] = mapped_column(
        SqlEnum(
            CustodyAction,
            name="ck_custody_action",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_type: [item.value for item in enum_type],
            length=32,
        ),
        nullable=False,
        index=True,
    )
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    from_custodian: Mapped[str | None] = mapped_column(String(160), nullable=True)
    to_custodian: Mapped[str | None] = mapped_column(String(160), nullable=True)
    location: Mapped[str | None] = mapped_column(String(200), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.current_timestamp(),
        index=True,
    )

    evidence: Mapped["EvidenceItem"] = relationship(back_populates="custody_events")
