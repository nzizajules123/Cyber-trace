from datetime import datetime
from typing import Any

from pydantic import ConfigDict, Field

from app.schemas.case import StrictSchema, to_camel


class AiStatusResponse(StrictSchema):
    mode: str
    provider: str
    model: str
    external_data_allowed: bool
    is_generative_llm: bool
    disclaimer: str


class AiConversationCreate(StrictSchema):
    case_id: str = Field(min_length=1, max_length=64)
    title: str | None = Field(default=None, max_length=200)


class AiMessageCreate(StrictSchema):
    content: str = Field(min_length=1, max_length=4000)


class AiCitation(StrictSchema):
    kind: str
    ref: str
    label: str


class AiMessageResponse(StrictSchema):
    id: int
    conversation_id: int
    role: str
    content: str
    mode: str
    provider: str
    model_name: str
    external_data_transmitted: bool
    citations: list[dict[str, Any]] = Field(default_factory=list)
    sections: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class AiConversationSummaryResponse(StrictSchema):
    id: int
    conversation_code: str
    case_id: int
    case_number: str
    case_title: str
    title: str
    message_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class AiConversationDetailResponse(AiConversationSummaryResponse):
    messages: list[AiMessageResponse] = Field(default_factory=list)


class AiConversationListResponse(StrictSchema):
    items: list[AiConversationSummaryResponse]
    total: int = Field(ge=0)


class AiMessageExchangeResponse(StrictSchema):
    conversation_code: str
    user_message: AiMessageResponse
    assistant_message: AiMessageResponse
