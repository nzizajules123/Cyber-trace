from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.case import CaseSeverity, CaseStatus


def to_camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class StrictSchema(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        strict=True,
        str_strip_whitespace=True,
    )


class CaseCreate(StrictSchema):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    status: CaseStatus = Field(default=CaseStatus.OPEN, strict=False)
    severity: CaseSeverity = Field(default=CaseSeverity.MEDIUM, strict=False)
    assigned_to: str | None = Field(default=None, max_length=160)
    reporter_name: str | None = Field(default=None, max_length=160)

    @field_validator("title")
    @classmethod
    def require_title(cls, value: str) -> str:
        if not value:
            raise ValueError("A case title is required.")
        return value

    @field_validator("description", "assigned_to", "reporter_name")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        return value or None


class CaseUpdate(StrictSchema):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    status: CaseStatus | None = Field(default=None, strict=False)
    severity: CaseSeverity | None = Field(default=None, strict=False)
    assigned_to: str | None = Field(default=None, max_length=160)
    reporter_name: str | None = Field(default=None, max_length=160)

    @field_validator("title")
    @classmethod
    def require_nonempty_title(cls, value: str | None) -> str | None:
        if value == "":
            raise ValueError("A case title cannot be blank.")
        return value

    @field_validator("description", "assigned_to", "reporter_name")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        return value or None

    @model_validator(mode="after")
    def require_changes(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("At least one case field must be provided.")
        for field in ("title", "status", "severity"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field.replace('_', ' ').capitalize()} cannot be null.")
        return self


class CaseResponse(StrictSchema):
    id: int
    case_number: str
    title: str
    description: str | None
    status: CaseStatus
    severity: CaseSeverity
    assigned_to: str | None
    reporter_name: str | None
    is_deleted: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        from_attributes=True,
    )


class AuditLogResponse(StrictSchema):
    id: int
    case_id: int
    action: str
    actor: str
    changes_json: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        from_attributes=True,
    )


class CaseDetailResponse(CaseResponse):
    audit_history: list[AuditLogResponse] = Field(validation_alias="audit_logs")


class PaginatedCaseListResponse(StrictSchema):
    items: list[CaseResponse]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    size: int = Field(ge=1)


class CaseMetricsResponse(StrictSchema):
    total_cases: int = Field(ge=0)
    open_cases: int = Field(ge=0)
    critical_cases: int = Field(ge=0)
    resolved_cases: int = Field(ge=0)
