from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_current_auth
from app.db.session import get_db
from app.integrations.ai_assistant import resolve_ai_runtime_config
from app.schemas.ai import (
    AiConversationCreate,
    AiConversationDetailResponse,
    AiConversationListResponse,
    AiMessageCreate,
    AiMessageExchangeResponse,
    AiStatusResponse,
)
from app.services.ai_conversations import (
    create_conversation,
    delete_conversation,
    get_conversation_detail,
    list_conversations,
    send_conversation_message,
)

router = APIRouter(prefix="/ai", tags=["ai-assistant"])


@router.get("/status", response_model=AiStatusResponse)
def read_ai_status(auth: AuthContext = Depends(get_current_auth)) -> AiStatusResponse:
    del auth
    cfg = resolve_ai_runtime_config()
    return AiStatusResponse(
        mode=cfg["mode"],
        provider=cfg["provider"],
        model=cfg["model"],
        external_data_allowed=cfg["external_data_allowed"],
        is_generative_llm=cfg["is_generative_llm"],
        disclaimer=cfg["disclaimer"],
    )


@router.post("/conversations", response_model=AiConversationDetailResponse, status_code=status.HTTP_201_CREATED)
def create_ai_conversation(
    data: AiConversationCreate,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> AiConversationDetailResponse:
    return create_conversation(db, data, auth=auth)


@router.get("/conversations", response_model=AiConversationListResponse)
def read_ai_conversations(
    case_id: str | None = Query(default=None, alias="caseId"),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> AiConversationListResponse:
    items = list_conversations(db, auth=auth, case_ref=case_id)
    return AiConversationListResponse(items=items, total=len(items))


@router.get("/conversations/{conversation_id}", response_model=AiConversationDetailResponse)
def read_ai_conversation(
    conversation_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> AiConversationDetailResponse:
    return get_conversation_detail(db, conversation_id, auth=auth)


@router.post("/conversations/{conversation_id}/messages", response_model=AiMessageExchangeResponse, status_code=status.HTTP_201_CREATED)
def post_ai_message(
    conversation_id: str,
    data: AiMessageCreate,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> AiMessageExchangeResponse:
    return send_conversation_message(db, conversation_id, data.content, auth=auth)


@router.delete("/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
def archive_ai_conversation(
    conversation_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> Response:
    delete_conversation(db, conversation_id, auth=auth)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
