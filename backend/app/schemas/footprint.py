from datetime import datetime
from typing import Any

from pydantic import ConfigDict, Field

from app.schemas.case import StrictSchema, to_camel


class UrlResearchRequest(StrictSchema):
    url: str = Field(min_length=4, max_length=2048)
    case_id: str = Field(min_length=1, max_length=64)
    submitted_by: str | None = Field(default=None, max_length=160)
    seal_as_evidence: bool = Field(default=True)
    notes: str | None = Field(default=None, max_length=4000)


class UrlInvestigationResponse(StrictSchema):
    id: int
    investigation_code: str
    case_id: int
    case_number: str | None = None
    target_url: str
    final_url: str | None
    domain: str
    submitted_by: str
    status: str
    risk_score: int
    risk_level: str
    http_status: int | None
    page_title: str | None
    snapshot_sha256: str | None
    evidence_code: str | None
    findings_count: int
    dns_info: dict[str, Any] = Field(default_factory=dict)
    tls_info: dict[str, Any] = Field(default_factory=dict)
    http_info: dict[str, Any] = Field(default_factory=dict)
    security_headers: dict[str, Any] = Field(default_factory=dict)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    notes: str | None
    created_at: datetime

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
    )


class UrlInvestigationListResponse(StrictSchema):
    items: list[UrlInvestigationResponse]
    total: int = Field(ge=0)
