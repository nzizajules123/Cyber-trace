from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import ADMIN_ROLES, SESSION_COOKIE_NAME, AuthContext, get_current_auth, require_roles
from app.core.config import get_settings
from app.core.security import auth_rate_limiter
from app.db.session import get_db
from app.models.auth import Organization, OrganizationMembership, SystemAuditLog
from app.schemas.auth import (
    AuthMeResponse,
    AuthSessionResponse,
    InvestigatorCreateRequest,
    InvestigatorMemberResponse,
    InvestigatorUpdateRequest,
    LoginRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    OrganizationCreateRequest,
    OrganizationResponse,
    OrganizationUpdateRequest,
    PasswordRecoveryConfirmRequest,
    PasswordRecoveryRequest,
    ProfileUpdateRequest,
    RegisterRequest,
    SystemAuditLogResponse,
    UserPublicResponse,
)
from app.services.auth import (
    add_org_investigator,
    authenticate_user,
    confirm_password_recovery,
    create_organization_for_user,
    enable_user_mfa,
    list_org_investigators,
    record_system_audit,
    register_user,
    request_password_recovery,
    setup_user_mfa,
    update_org_investigator,
    update_organization,
)

auth_router = APIRouter(prefix="/auth", tags=["authentication"])
org_router = APIRouter(prefix="/organizations", tags=["organizations"])
investigators_router = APIRouter(prefix="/investigators", tags=["investigators"])
audit_router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(request: Request, scope: str) -> None:
    if not get_settings().rate_limit_enabled:
        return
    if not auth_rate_limiter.allow(f"{scope}:{_client_ip(request)}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Please wait a minute and try again.",
        )


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_ttl_hours * 3600,
    )


@auth_router.post("/register", response_model=AuthSessionResponse, status_code=status.HTTP_201_CREATED)
def register(
    data: RegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> AuthSessionResponse:
    _enforce_rate_limit(request, "register")
    session_resp = register_user(
        db,
        data,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _set_session_cookie(response, session_resp.access_token)
    return session_resp


@auth_router.post("/login", response_model=AuthSessionResponse)
def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> AuthSessionResponse:
    _enforce_rate_limit(request, "login")
    session_resp = authenticate_user(
        db,
        data,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    _set_session_cookie(response, session_resp.access_token)
    return session_resp


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> Response:
    auth.session.revoked_at = datetime.now(timezone.utc)
    record_system_audit(
        db,
        action="AUTH_LOGOUT",
        resource_type="session",
        actor_email=auth.user.email,
        organization_id=auth.organization.id,
        user_id=auth.user.id,
        ip_address=_client_ip(request),
    )
    db.commit()
    response.delete_cookie(SESSION_COOKIE_NAME)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@auth_router.get("/me", response_model=AuthMeResponse)
def read_me(auth: AuthContext = Depends(get_current_auth)) -> AuthMeResponse:
    settings = get_settings()
    return AuthMeResponse(
        user=UserPublicResponse.model_validate(auth.user),
        organization=OrganizationResponse.model_validate(auth.organization),
        role=auth.role,
        deployment_mode=settings.deployment_mode,
        ai_enabled=True,
    )


@auth_router.patch("/me", response_model=UserPublicResponse)
def update_profile(
    data: ProfileUpdateRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> UserPublicResponse:
    if data.full_name is not None:
        auth.user.full_name = data.full_name.strip()
        auth.user.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(auth.user)
    return UserPublicResponse.model_validate(auth.user)


@auth_router.post("/password-recovery/request")
def request_recovery(
    data: PasswordRecoveryRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    _enforce_rate_limit(request, "recovery")
    raw_token = request_password_recovery(db, data.email, ip_address=_client_ip(request))
    # Never confirm whether an account exists in production; in LOCAL mode expose recovery token for offline labs
    payload: dict[str, str | None] = {
        "message": "If an active account exists for that email, a password recovery token has been issued."
    }
    if get_settings().deployment_mode.upper() == "LOCAL" and raw_token:
        payload["localRecoveryToken"] = raw_token
    return payload


@auth_router.post("/password-recovery/confirm")
def confirm_recovery(
    data: PasswordRecoveryConfirmRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    _enforce_rate_limit(request, "recovery_confirm")
    confirm_password_recovery(db, data.token, data.new_password, ip_address=_client_ip(request))
    return {"message": "Password updated successfully. Please sign in with your new password."}


@auth_router.post("/mfa/setup", response_model=MfaSetupResponse)
def mfa_setup(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> MfaSetupResponse:
    secret, uri = setup_user_mfa(db, auth.user)
    return MfaSetupResponse(secret=secret, otpauth_uri=uri)


@auth_router.post("/mfa/enable")
def mfa_enable(
    data: MfaVerifyRequest,
    request: Request,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    enable_user_mfa(
        db,
        auth.user,
        data.code,
        org_id=auth.organization.id,
        ip_address=_client_ip(request),
    )
    return {"mfaEnabled": True}


# --- Organization Management ---


@org_router.get("/current", response_model=OrganizationResponse)
def read_current_organization(auth: AuthContext = Depends(get_current_auth)) -> OrganizationResponse:
    return OrganizationResponse.model_validate(auth.organization)


@org_router.patch("/current", response_model=OrganizationResponse)
def patch_current_organization(
    data: OrganizationUpdateRequest,
    request: Request,
    auth: AuthContext = Depends(require_roles(*ADMIN_ROLES)),
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    updated = update_organization(db, auth.organization, data, actor=auth.user, ip_address=_client_ip(request))
    return OrganizationResponse.model_validate(updated)


@org_router.get("", response_model=list[OrganizationResponse])
def list_my_organizations(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> list[OrganizationResponse]:
    orgs = db.scalars(
        select(Organization)
        .join(OrganizationMembership, OrganizationMembership.organization_id == Organization.id)
        .where(
            OrganizationMembership.user_id == auth.user.id,
            OrganizationMembership.is_active.is_(True),
        )
    ).all()
    return [OrganizationResponse.model_validate(o) for o in orgs]


@org_router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_org(
    data: OrganizationCreateRequest,
    request: Request,
    auth: AuthContext = Depends(require_roles(*ADMIN_ROLES)),
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    org = create_organization_for_user(db, auth.user, data, ip_address=_client_ip(request))
    return OrganizationResponse.model_validate(org)


# --- Investigators Management ---


@investigators_router.get("", response_model=list[InvestigatorMemberResponse])
def read_investigators(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> list[InvestigatorMemberResponse]:
    return list_org_investigators(db, auth.organization.id)


@investigators_router.post("", response_model=InvestigatorMemberResponse, status_code=status.HTTP_201_CREATED)
def create_investigator(
    data: InvestigatorCreateRequest,
    request: Request,
    auth: AuthContext = Depends(require_roles(*ADMIN_ROLES)),
    db: Session = Depends(get_db),
) -> InvestigatorMemberResponse:
    return add_org_investigator(db, auth.organization.id, data, actor=auth.user, ip_address=_client_ip(request))


@investigators_router.patch("/{membership_id}", response_model=InvestigatorMemberResponse)
def patch_investigator(
    membership_id: int,
    data: InvestigatorUpdateRequest,
    request: Request,
    auth: AuthContext = Depends(require_roles(*ADMIN_ROLES)),
    db: Session = Depends(get_db),
) -> InvestigatorMemberResponse:
    return update_org_investigator(
        db, auth.organization.id, membership_id, data, actor=auth.user, ip_address=_client_ip(request)
    )


# --- System Audit Logs ---


@audit_router.get("", response_model=list[SystemAuditLogResponse])
def read_system_audit_logs(
    action: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> list[SystemAuditLogResponse]:
    stmt = select(SystemAuditLog).where(SystemAuditLog.organization_id == auth.organization.id)
    if action:
        stmt = stmt.where(SystemAuditLog.action == action)
    rows = db.scalars(stmt.order_by(SystemAuditLog.created_at.desc(), SystemAuditLog.id.desc()).limit(limit)).all()
    return [SystemAuditLogResponse.model_validate(row) for row in rows]
