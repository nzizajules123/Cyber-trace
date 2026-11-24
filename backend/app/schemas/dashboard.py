from datetime import datetime

from pydantic import Field

from app.schemas.case import CaseResponse, StrictSchema


class MetricValueResponse(StrictSchema):
    value: int = Field(ge=0)


class DashboardMetricsResponse(StrictSchema):
    active_investigations: MetricValueResponse
    evidence_items: MetricValueResponse
    events_analyzed: MetricValueResponse
    findings_requiring_review: MetricValueResponse


class EvidenceVerificationCheckResponse(StrictSchema):
    evidence_item_id: str
    comparison_performed: bool
    algorithm: str
    sha256_matches: bool


class EvidenceIntegrityResponse(StrictSchema):
    total_items: int = Field(ge=0)
    verification_checks: list[EvidenceVerificationCheckResponse]


class ActivityEventResponse(StrictSchema):
    id: str
    occurred_at: datetime
    event_type: str
    record_type: str
    description: str
    source_evidence: str
    case_id: str
    analysis_status: str


class CountPointResponse(StrictSchema):
    label: str
    count: int = Field(ge=0)


class DashboardAnalyticsResponse(StrictSchema):
    event_volume: list[CountPointResponse]
    authentication_distribution: list[CountPointResponse]
    evidence_collection_trend: list[CountPointResponse]


class DashboardOverviewResponse(StrictSchema):
    current_user: dict[str, str] | None = None
    current_case_id: str | None = None
    notifications: list[dict[str, str]] = Field(default_factory=list)
    metrics: DashboardMetricsResponse
    cases: list[CaseResponse]
    evidence_integrity: EvidenceIntegrityResponse
    activity_events: list[ActivityEventResponse]
    analytics: DashboardAnalyticsResponse
    updated_at: datetime
