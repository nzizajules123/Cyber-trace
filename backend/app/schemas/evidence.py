from datetime import datetime

from pydantic import ConfigDict, Field

from app.models.evidence import CustodyAction, EvidenceStatus, EvidenceType
from app.schemas.case import StrictSchema, to_camel


class CustodyEventCreate(StrictSchema):
    action: CustodyAction = Field(strict=False)
    actor: str = Field(min_length=1, max_length=160)
    from_custodian: str | None = Field(default=None, max_length=160)
    to_custodian: str | None = Field(default=None, max_length=160)
    location: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=4000)


class CustodyEventResponse(StrictSchema):
    id: int
    evidence_id: int
    evidence_code: str | None = None
    case_number: str | None = None
    action: CustodyAction
    actor: str
    from_custodian: str | None
    to_custodian: str | None
    location: str | None
    notes: str | None
    previous_hash: str | None
    entry_hash: str
    occurred_at: datetime

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        from_attributes=True,
    )


class EvidenceVerificationResponse(StrictSchema):
    id: int
    evidence_id: int
    evidence_code: str | None = None
    algorithm: str
    expected_hash: str
    computed_hash: str | None
    comparison_performed: bool
    sha256_matches: bool
    verified_by: str
    notes: str | None
    verified_at: datetime

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        from_attributes=True,
    )


class EvidenceItemResponse(StrictSchema):
    id: int
    evidence_code: str
    case_id: int
    case_number: str | None = None
    original_filename: str
    mime_type: str
    file_size: int
    sha256: str
    sha512: str
    md5: str
    evidence_type: EvidenceType
    status: EvidenceStatus
    acquisition_source: str | None
    collected_by: str | None
    description: str | None
    latest_verification: EvidenceVerificationResponse | None = None
    custody_chain_valid: bool = True
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        from_attributes=True,
    )


class EvidenceDetailResponse(EvidenceItemResponse):
    verifications: list[EvidenceVerificationResponse] = Field(default_factory=list)
    custody_events: list[CustodyEventResponse] = Field(default_factory=list)


class EvidenceListResponse(StrictSchema):
    items: list[EvidenceItemResponse]
    total: int = Field(ge=0)


class IntegritySummaryResponse(StrictSchema):
    total_items: int = Field(ge=0)
    verified_count: int = Field(ge=0)
    mismatch_count: int = Field(ge=0)
    pending_count: int = Field(ge=0)
    items: list[EvidenceItemResponse]


class CustodyLedgerResponse(StrictSchema):
    total_events: int = Field(ge=0)
    all_chains_valid: bool
    broken_evidence_codes: list[str] = Field(default_factory=list)
    events: list[CustodyEventResponse]
