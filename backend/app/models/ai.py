from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AiConversation(Base):
    __tablename__ = "ai_conversations"
    __table_args__ = (
        Index("ix_ai_conversations_org_user_active", "organization_id", "user_id", "is_archived"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_code: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    is_archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0", index=True)
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
    messages: Mapped[list["AiMessage"]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="AiMessage.created_at, AiMessage.id",
    )


class AiMessage(Base):
    __tablename__ = "ai_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[int] = mapped_column(
        ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="deterministic")
    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="deterministic")
    model_name: Mapped[str] = mapped_column(String(120), nullable=False, default="local-deterministic")
    external_data_transmitted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    citations_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    sections_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.current_timestamp(),
        index=True,
    )

    conversation: Mapped["AiConversation"] = relationship(back_populates="messages")
