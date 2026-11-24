from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CaseSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Case(Base):
    __tablename__ = "cases"
    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED')",
            name="ck_cases_status",
        ),
        CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_cases_severity",
        ),
        Index("ix_cases_active_status_severity", "is_deleted", "status", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[CaseStatus] = mapped_column(
        SqlEnum(
            CaseStatus,
            name="ck_cases_status",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_type: [item.value for item in enum_type],
            length=32,
        ),
        nullable=False,
        default=CaseStatus.OPEN,
        server_default=CaseStatus.OPEN.value,
        index=True,
    )
    severity: Mapped[CaseSeverity] = mapped_column(
        SqlEnum(
            CaseSeverity,
            name="ck_cases_severity",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda enum_type: [item.value for item in enum_type],
            length=16,
        ),
        nullable=False,
        default=CaseSeverity.MEDIUM,
        server_default=CaseSeverity.MEDIUM.value,
        index=True,
    )
    assigned_to: Mapped[str | None] = mapped_column(String(160), nullable=True)
    reporter_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
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

    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="AuditLog.created_at, AuditLog.id",
    )
