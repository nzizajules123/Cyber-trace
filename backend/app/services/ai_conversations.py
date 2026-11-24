from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.api.deps import AuthContext
from app.integrations.ai_assistant import answer_case_question
from app.models.ai import AiConversation, AiMessage
from app.schemas.ai import (
    AiConversationCreate,
    AiConversationDetailResponse,
    AiConversationSummaryResponse,
    AiMessageExchangeResponse,
    AiMessageResponse,
)
from app.services.auth import record_system_audit
from app.services.cases import get_case_by_id


def _serialize_message(msg: AiMessage) -> AiMessageResponse:
    return AiMessageResponse(
        id=msg.id,
        conversation_id=msg.conversation_id,
        role=msg.role,
        content=msg.content,
        mode=msg.mode,
        provider=msg.provider,
        model_name=msg.model_name,
        external_data_transmitted=msg.external_data_transmitted,
        citations=msg.citations_json or [],
        sections=msg.sections_json or {},
        created_at=msg.created_at,
    )


def _serialize_summary(conv: AiConversation) -> AiConversationSummaryResponse:
    return AiConversationSummaryResponse(
        id=conv.id,
        conversation_code=conv.conversation_code,
        case_id=conv.case_id,
        case_number=conv.case.case_number,
        case_title=conv.case.title,
        title=conv.title,
        message_count=len(conv.messages),
        created_at=conv.created_at,
        updated_at=conv.updated_at,
    )


def _serialize_detail(conv: AiConversation) -> AiConversationDetailResponse:
    base = _serialize_summary(conv)
    return AiConversationDetailResponse(
        **base.model_dump(),
        messages=[_serialize_message(m) for m in conv.messages],
    )


def _get_owned_conversation(
    db: Session,
    conversation_ref: str | int,
    *,
    auth: AuthContext,
) -> AiConversation:
    stmt = (
        select(AiConversation)
        .options(selectinload(AiConversation.case), selectinload(AiConversation.messages))
        .where(
            AiConversation.organization_id == auth.organization.id,
            AiConversation.user_id == auth.user.id,
            AiConversation.is_archived.is_(False),
        )
    )
    if isinstance(conversation_ref, int):
        conv = db.scalar(stmt.where(AiConversation.id == conversation_ref))
    else:
        ident = conversation_ref.strip()
        if ident.isdecimal():
            conv = db.scalar(stmt.where(AiConversation.id == int(ident)))
        else:
            conv = db.scalar(stmt.where(AiConversation.conversation_code == ident.upper()))
    if conv is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI conversation not found.")
    return conv


def create_conversation(
    db: Session,
    data: AiConversationCreate,
    *,
    auth: AuthContext,
) -> AiConversationDetailResponse:
    case = get_case_by_id(db, data.case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized case not found.")

    now = datetime.now(timezone.utc)
    conv = AiConversation(
        conversation_code=f"AI-{now.year}-{uuid4().hex[:8].upper()}",
        organization_id=auth.organization.id,
        user_id=auth.user.id,
        case_id=case.id,
        title=(data.title or "").strip() or f"{case.case_number} Investigation Session",
        is_archived=False,
        created_at=now,
        updated_at=now,
    )
    try:
        db.add(conv)
        record_system_audit(
            db,
            action="AI_CONVERSATION_CREATED",
            resource_type="ai_conversation",
            actor_email=auth.user.email,
            organization_id=auth.organization.id,
            user_id=auth.user.id,
            resource_id=conv.conversation_code,
            details={"caseNumber": case.case_number},
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise

    loaded = _get_owned_conversation(db, conv.id, auth=auth)
    return _serialize_detail(loaded)


def list_conversations(
    db: Session,
    *,
    auth: AuthContext,
    case_ref: str | None = None,
) -> list[AiConversationSummaryResponse]:
    stmt = (
        select(AiConversation)
        .options(selectinload(AiConversation.case), selectinload(AiConversation.messages))
        .where(
            AiConversation.organization_id == auth.organization.id,
            AiConversation.user_id == auth.user.id,
            AiConversation.is_archived.is_(False),
        )
    )
    if case_ref:
        case = get_case_by_id(db, case_ref, organization_id=auth.organization.id)
        if case is None:
            return []
        stmt = stmt.where(AiConversation.case_id == case.id)

    rows = db.scalars(stmt.order_by(AiConversation.updated_at.desc(), AiConversation.id.desc())).all()
    return [_serialize_summary(row) for row in rows]


def get_conversation_detail(
    db: Session,
    conversation_ref: str,
    *,
    auth: AuthContext,
) -> AiConversationDetailResponse:
    conv = _get_owned_conversation(db, conversation_ref, auth=auth)
    return _serialize_detail(conv)


def send_conversation_message(
    db: Session,
    conversation_ref: str,
    content: str,
    *,
    auth: AuthContext,
) -> AiMessageExchangeResponse:
    conv = _get_owned_conversation(db, conversation_ref, auth=auth)
    case = get_case_by_id(db, conv.case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked case is no longer available.")

    answer = answer_case_question(
        db,
        case=case,
        organization_id=auth.organization.id,
        question=content.strip(),
    )

    now = datetime.now(timezone.utc)
    user_msg = AiMessage(
        conversation_id=conv.id,
        role="user",
        content=content.strip(),
        mode=answer["mode"],
        provider=answer["provider"],
        model_name=answer["model"],
        external_data_transmitted=False,
        citations_json=[],
        sections_json={},
        created_at=now,
    )
    assistant_msg = AiMessage(
        conversation_id=conv.id,
        role="assistant",
        content=answer["content"],
        mode=answer["mode"],
        provider=answer["provider"],
        model_name=answer["model"],
        external_data_transmitted=bool(answer["external_data_transmitted"]),
        citations_json=answer["citations"],
        sections_json=answer["sections"],
        created_at=now,
    )
    conv.updated_at = now
    try:
        db.add(user_msg)
        db.add(assistant_msg)
        db.commit()
        db.refresh(user_msg)
        db.refresh(assistant_msg)
    except SQLAlchemyError:
        db.rollback()
        raise

    return AiMessageExchangeResponse(
        conversation_code=conv.conversation_code,
        user_message=_serialize_message(user_msg),
        assistant_message=_serialize_message(assistant_msg),
    )


def delete_conversation(
    db: Session,
    conversation_ref: str,
    *,
    auth: AuthContext,
) -> None:
    conv = _get_owned_conversation(db, conversation_ref, auth=auth)
    conv.is_archived = True
    conv.updated_at = datetime.now(timezone.utc)
    record_system_audit(
        db,
        action="AI_CONVERSATION_ARCHIVED",
        resource_type="ai_conversation",
        actor_email=auth.user.email,
        organization_id=auth.organization.id,
        user_id=auth.user.id,
        resource_id=conv.conversation_code,
    )
    db.commit()
