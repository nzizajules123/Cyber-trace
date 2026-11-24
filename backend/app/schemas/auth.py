from datetime import datetime
from typing import Any

from pydantic import ConfigDict, Field

from app.models.auth import OrgRole
from app.schemas.case import StrictSchema, to_camel


class UserPublicResponse(StrictSchema):
    id: int
    uuid: str
    email: str
    full_name: str
    is_active: bool
    mfa_enabled: bool
    last_login_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid", from_attributes=True)


class OrganizationResponse(StrictSchema):
    id: int
    uuid: str
    name: str
    slug: str
    description: str | None
    allow_registration: bool
    deployment_mode: str
    created_at: datetime

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid", from_attributes=True)


class AuthSessionResponse(StrictSchema):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: UserPublicResponse
    organization: OrganizationResponse
    role: OrgRole


class AuthMeResponse(StrictSchema):
    user: UserPublicResponse
    organization: OrganizationResponse
    role: OrgRole
    deployment_mode: str
    ai_enabled: bool


class RegisterRequest(StrictSchema):
    email: str = Field(min_length=5, max_length=255)
    full_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=8, max_length=128)
    organization_name: str | None = Field(default=None, max_length=160)
    organization_slug: str | None = Field(default=None, max_length=120)


class LoginRequest(StrictSchema):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=1, max_length=128)
    totp_code: str | None = Field(default=None, max_length=10)


class ProfileUpdateRequest(StrictSchema):
    full_name: str | None = Field(default=None, min_length=2, max_length=160)


class PasswordRecoveryRequest(StrictSchema):
    email: str = Field(min_length=5, max_length=255)


class PasswordRecoveryConfirmRequest(StrictSchema):
    token: str = Field(min_length=16, max_length=255)
    new_password: str = Field(min_length=8, max_length=128)


class MfaSetupResponse(StrictSchema):
    secret: str
    otpauth_uri: str


class MfaVerifyRequest(StrictSchema):
    code: str = Field(min_length=6, max_length=10)


class OrganizationCreateRequest(StrictSchema):
    name: str = Field(min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    allow_registration: bool = True


class OrganizationUpdateRequest(StrictSchema):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    allow_registration: bool | None = None


class InvestigatorCreateRequest(StrictSchema):
    email: str = Field(min_length=5, max_length=255)
    full_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=8, max_length=128)
    role: OrgRole = Field(default=OrgRole.INVESTIGATOR, strict=False)


class InvestigatorUpdateRequest(StrictSchema):
    role: OrgRole | None = Field(default=None, strict=False)
    is_active: bool | None = None


class InvestigatorMemberResponse(StrictSchema):
    membership_id: int
    user_id: int
    email: str
    full_name: str
    role: OrgRole
    is_active: bool
    mfa_enabled: bool
    last_login_at: datetime | None
    created_at: datetime


class SystemAuditLogResponse(StrictSchema):
    id: int
    organization_id: int | None
    actor_email: str
    action: str
    resource_type: str
    resource_id: str | None
    ip_address: str | None
    details_json: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid", from_attributes=True)


class CaseNoteCreateRequest(StrictSchema):
    content: str = Field(min_length=1, max_length=10000)


class CaseNoteResponse(StrictSchema):
    id: int
    case_id: int
    author_name: str
    content: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid", from_attributes=True)
