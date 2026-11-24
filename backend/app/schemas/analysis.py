from datetime import datetime
from typing import Any

from pydantic import ConfigDict, Field

from app.models.analysis import FindingConfidence, FindingStatus
from app.models.case import CaseSeverity
from app.schemas.case import StrictSchema, to_camel


class ExtractedIocItem(StrictSchema):
    type: str
    value: str
    count: int = Field(default=1, ge=1)


class ForensicEventResponse(StrictSchema):
    id: int
    case_id: int
    case_number: str | None = None
    evidence_id: int
    evidence_code: str | None = None
    source_filename: str | None = None
    occurred_at: datetime
    event_type: str
    category: str
    source_ip: str | None
    username: str | None
    action: str | None
    description: str
    line_number: int | None
    extracted_iocs: list[dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
    )


class ForensicFindingResponse(StrictSchema):
    id: int
    case_id: int
    case_number: str | None = None
    evidence_id: int | None
    evidence_code: str | None = None
    rule_id: str
    title: str
    severity: CaseSeverity
    confidence: FindingConfidence
    status: FindingStatus
    summary: str
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    event_count: int
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    reviewer_notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
    )


class FindingCreateRequest(StrictSchema):
    case_id: str = Field(min_length=1, max_length=64)
    evidence_id: str | None = Field(default=None, max_length=64)
    title: str = Field(min_length=3, max_length=200)
    severity: CaseSeverity = Field(default=CaseSeverity.MEDIUM, strict=False)
    confidence: FindingConfidence = Field(default=FindingConfidence.MEDIUM, strict=False)
    summary: str = Field(min_length=5, max_length=5000)
    reviewer_notes: str | None = Field(default=None, max_length=4000)


class FindingReviewUpdate(StrictSchema):
    status: FindingStatus = Field(strict=False)
    reviewer_notes: str | None = Field(default=None, max_length=4000)


class AiAssistRequest(StrictSchema):
    case_id: str = Field(min_length=1, max_length=64)
    question: str | None = Field(default=None, max_length=1000)


class AnalysisRunResponse(StrictSchema):
    evidence_code: str
    case_number: str
    detected_format: str
    events_parsed: int
    unique_iocs: int
    findings_generated: int
    iocs: list[ExtractedIocItem]
    findings: list[ForensicFindingResponse]


class EventListResponse(StrictSchema):
    items: list[ForensicEventResponse]
    total: int = Field(ge=0)


class FindingListResponse(StrictSchema):
    items: list[ForensicFindingResponse]
    total: int = Field(ge=0)


class IocSummaryResponse(StrictSchema):
    total_unique: int = Field(ge=0)
    items: list[ExtractedIocItem]


class TimelineEntryResponse(StrictSchema):
    id: str
    occurred_at: datetime
    source_kind: str
    record_type: str
    event_type: str
    title: str
    description: str
    case_number: str
    source_ref: str
    severity: str | None = None
    status: str | None = None


class TimelineResponse(StrictSchema):
    total: int = Field(ge=0)
    items: list[TimelineEntryResponse]
