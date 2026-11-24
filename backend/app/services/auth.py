import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.security import (
    generate_session_token,
    generate_totp_secret,
    hash_password,
    hash_token,
    verify_password,
    verify_totp_code,
)
from app.models.auth import (
    Organization,
    OrganizationMembership,
    OrgRole,
    PasswordResetToken,
    SystemAuditLog,
    User,
    UserSession,
)
from app.models.case import Case
from app.schemas.auth import (
    AuthSessionResponse,
    InvestigatorCreateRequest,
    InvestigatorMemberResponse,
    InvestigatorUpdateRequest,
    LoginRequest,
    OrganizationCreateRequest,
    OrganizationResponse,
    OrganizationUpdateRequest,
    RegisterRequest,
    UserPublicResponse,
)

SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(value: str) -> str:
    slug = SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return slug[:80] or "organization"


def record_system_audit(
    db: Session,
    *,
    action: str,
    resource_type: str,
    actor_email: str = "system",
    organization_id: int | None = None,
    user_id: int | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        SystemAuditLog(
            organization_id=organization_id,
            user_id=user_id,
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            details_json=details or {},
        )
    )


def _create_session_response(
    db: Session,
    *,
    user: User,
    org: Organization,
    role: OrgRole,
    ip_address: str | None,
    user_agent: str | None,
) -> AuthSessionResponse:
    now = datetime.now(timezone.utc)
    raw_token = generate_session_token()
    expires_at = now + timedelta(hours=get_settings().session_ttl_hours)
    session_row = UserSession(
        user_id=user.id,
        organization_id=org.id,
        token_hash=hash_token(raw_token),
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:250] or None,
        created_at=now,
    )
    user.last_login_at = now
    db.add(session_row)
    db.commit()
    db.refresh(user)
    return AuthSessionResponse(
        access_token=raw_token,
        expires_at=expires_at,
        user=UserPublicResponse.model_validate(user),
        organization=OrganizationResponse.model_validate(org),
        role=role,
    )


def register_user(
    db: Session,
    data: RegisterRequest,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuthSessionResponse:
    email = data.email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Enter a valid email address.")

    if db.scalar(select(User).where(User.email == email)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists.")

    total_users = db.scalar(select(func.count(User.id))) or 0
    is_first_user = total_users == 0

    org: Organization | None = None
    assigned_role = OrgRole.INVESTIGATOR

    if data.organization_slug:
        org = db.scalar(select(Organization).where(Organization.slug == data.organization_slug.strip().lower()))
        if org is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")
        if not org.allow_registration:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Self-registration is disabled for this organization.",
            )
    else:
        org_name = (data.organization_name or "").strip() or "CyberTrace Forensics Lab"
        base_slug = _slugify(org_name)
        slug = base_slug
        suffix = 1
        while db.scalar(select(Organization).where(Organization.slug == slug)) is not None:
            suffix += 1
            slug = f"{base_slug}-{suffix}"
        org = Organization(
            name=org_name,
            slug=slug,
            allow_registration=True,
            deployment_mode=get_settings().deployment_mode,
        )
        db.add(org)
        db.flush()
        assigned_role = OrgRole.SYSTEM_ADMIN if is_first_user else OrgRole.ORG_ADMIN

    user = User(
        email=email,
        full_name=data.full_name.strip(),
        password_hash=hash_password(data.password),
        is_active=True,
    )
    db.add(user)
    db.flush()

    membership = OrganizationMembership(
        organization_id=org.id,
        user_id=user.id,
        role=assigned_role,
        is_active=True,
    )
    db.add(membership)

    # Preserve any legacy pre-auth cases by assigning them to the initial organization
    if is_first_user:
        legacy_cases = db.scalars(select(Case).where(Case.organization_id.is_(None))).all()
        for legacy in legacy_cases:
            legacy.organization_id = org.id

    record_system_audit(
        db,
        action="AUTH_REGISTER",
        resource_type="user",
        actor_email=email,
        organization_id=org.id,
        user_id=user.id,
        resource_id=user.uuid,
        ip_address=ip_address,
        details={"role": assigned_role.value, "organizationSlug": org.slug},
    )
    return _create_session_response(
        db,
        user=user,
        org=org,
        role=assigned_role,
        ip_address=ip_address,
        user_agent=user_agent,
    )


def authenticate_user(
    db: Session,
    data: LoginRequest,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuthSessionResponse:
    email = data.email.strip().lower()
    user = db.scalar(
        select(User)
        .options(selectinload(User.memberships).selectinload(OrganizationMembership.organization))
        .where(User.email == email)
    )
    if user is None or not verify_password(user.password_hash, data.password):
        record_system_audit(
            db,
            action="AUTH_LOGIN_FAILED",
            resource_type="session",
            actor_email=email,
            ip_address=ip_address,
            details={"reason": "invalid_credentials"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account has been deactivated.")

    if user.mfa_enabled and user.mfa_secret:
        if not data.totp_code or not verify_totp_code(user.mfa_secret, data.totp_code):
            record_system_audit(
                db,
                action="AUTH_MFA_FAILED",
                resource_type="session",
                actor_email=email,
                user_id=user.id,
                ip_address=ip_address,
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid 6-digit MFA code is required.",
            )

    active_membership = next((m for m in user.memberships if m.is_active), None)
    if active_membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active organization membership found for this account.",
        )

    record_system_audit(
        db,
        action="AUTH_LOGIN",
        resource_type="session",
        actor_email=user.email,
        organization_id=active_membership.organization_id,
        user_id=user.id,
        ip_address=ip_address,
        details={"role": active_membership.role.value},
    )
    return _create_session_response(
        db,
        user=user,
        org=active_membership.organization,
        role=active_membership.role,
        ip_address=ip_address,
        user_agent=user_agent,
    )


def request_password_recovery(
    db: Session,
    email: str,
    *,
    ip_address: str | None = None,
) -> str | None:
    normalized = email.strip().lower()
    user = db.scalar(select(User).where(User.email == normalized, User.is_active.is_(True)))
    if user is None:
        return None
    raw_token = generate_session_token()
    now = datetime.now(timezone.utc)
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=now + timedelta(minutes=30),
            created_at=now,
        )
    )
    record_system_audit(
        db,
        action="AUTH_PASSWORD_RECOVERY_REQUESTED",
        resource_type="user",
        actor_email=user.email,
        user_id=user.id,
        ip_address=ip_address,
    )
    db.commit()
    return raw_token


def confirm_password_recovery(
    db: Session,
    token: str,
    new_password: str,
    *,
    ip_address: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    row = db.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == hash_token(token.strip()),
            PasswordResetToken.used_at.is_(None),
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired recovery token.")
    exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if exp < now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired recovery token.")

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account is unavailable.")

    user.password_hash = hash_password(new_password)
    row.used_at = now
    # Revoke all existing sessions on password reset
    sessions = db.scalars(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
    ).all()
    for sess in sessions:
        sess.revoked_at = now

    record_system_audit(
        db,
        action="AUTH_PASSWORD_RESET",
        resource_type="user",
        actor_email=user.email,
        user_id=user.id,
        ip_address=ip_address,
    )
    db.commit()


def setup_user_mfa(db: Session, user: User) -> tuple[str, str]:
    secret = generate_totp_secret()
    user.mfa_secret = secret
    user.mfa_enabled = False
    db.commit()
    uri = f"otpauth://totp/CyberTrace:{user.email}?secret={secret}&issuer=CyberTrace"
    return secret, uri


def enable_user_mfa(db: Session, user: User, code: str, *, org_id: int, ip_address: str | None) -> None:
    if not user.mfa_secret or not verify_totp_code(user.mfa_secret, code):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid 6-digit MFA code.")
    user.mfa_enabled = True
    record_system_audit(
        db,
        action="AUTH_MFA_ENABLED",
        resource_type="user",
        actor_email=user.email,
        organization_id=org_id,
        user_id=user.id,
        ip_address=ip_address,
    )
    db.commit()


def create_organization_for_user(
    db: Session,
    user: User,
    data: OrganizationCreateRequest,
    *,
    ip_address: str | None = None,
) -> Organization:
    base_slug = _slugify(data.name)
    slug = base_slug
    idx = 1
    while db.scalar(select(Organization).where(Organization.slug == slug)) is not None:
        idx += 1
        slug = f"{base_slug}-{idx}"
    org = Organization(
        name=data.name.strip(),
        slug=slug,
        description=data.description,
        allow_registration=data.allow_registration,
        deployment_mode=get_settings().deployment_mode,
    )
    db.add(org)
    db.flush()
    db.add(
        OrganizationMembership(
            organization_id=org.id,
            user_id=user.id,
            role=OrgRole.ORG_ADMIN,
            is_active=True,
        )
    )
    record_system_audit(
        db,
        action="ORG_CREATED",
        resource_type="organization",
        actor_email=user.email,
        organization_id=org.id,
        user_id=user.id,
        resource_id=org.slug,
        ip_address=ip_address,
    )
    db.commit()
    db.refresh(org)
    return org


def update_organization(
    db: Session,
    org: Organization,
    data: OrganizationUpdateRequest,
    *,
    actor: User,
    ip_address: str | None = None,
) -> Organization:
    if data.name is not None:
        org.name = data.name.strip()
    if data.description is not None:
        org.description = data.description
    if data.allow_registration is not None:
        org.allow_registration = data.allow_registration
    org.updated_at = datetime.now(timezone.utc)
    record_system_audit(
        db,
        action="ORG_UPDATED",
        resource_type="organization",
        actor_email=actor.email,
        organization_id=org.id,
        user_id=actor.id,
        resource_id=org.slug,
        ip_address=ip_address,
    )
    db.commit()
    db.refresh(org)
    return org


def list_org_investigators(db: Session, org_id: int) -> list[InvestigatorMemberResponse]:
    rows = db.scalars(
        select(OrganizationMembership)
        .options(selectinload(OrganizationMembership.user))
        .where(OrganizationMembership.organization_id == org_id)
        .order_by(OrganizationMembership.created_at.asc())
    ).all()
    return [
        InvestigatorMemberResponse(
            membership_id=m.id,
            user_id=m.user.id,
            email=m.user.email,
            full_name=m.user.full_name,
            role=m.role,
            is_active=bool(m.is_active and m.user.is_active),
            mfa_enabled=m.user.mfa_enabled,
            last_login_at=m.user.last_login_at,
            created_at=m.created_at,
        )
        for m in rows
    ]


def add_org_investigator(
    db: Session,
    org_id: int,
    data: InvestigatorCreateRequest,
    *,
    actor: User,
    ip_address: str | None = None,
) -> InvestigatorMemberResponse:
    email = data.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            email=email,
            full_name=data.full_name.strip(),
            password_hash=hash_password(data.password),
            is_active=True,
        )
        db.add(user)
        db.flush()

    existing = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == user.id,
        )
    )
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User is already a member of this organization.")

    membership = OrganizationMembership(
        organization_id=org_id,
        user_id=user.id,
        role=data.role,
        is_active=True,
    )
    db.add(membership)
    record_system_audit(
        db,
        action="INVESTIGATOR_ADDED",
        resource_type="membership",
        actor_email=actor.email,
        organization_id=org_id,
        user_id=actor.id,
        resource_id=email,
        ip_address=ip_address,
        details={"role": data.role.value},
    )
    db.commit()
    db.refresh(membership)
    return InvestigatorMemberResponse(
        membership_id=membership.id,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=membership.role,
        is_active=bool(membership.is_active and user.is_active),
        mfa_enabled=user.mfa_enabled,
        last_login_at=user.last_login_at,
        created_at=membership.created_at,
    )


def update_org_investigator(
    db: Session,
    org_id: int,
    membership_id: int,
    data: InvestigatorUpdateRequest,
    *,
    actor: User,
    ip_address: str | None = None,
) -> InvestigatorMemberResponse:
    membership = db.scalar(
        select(OrganizationMembership)
        .options(selectinload(OrganizationMembership.user))
        .where(
            OrganizationMembership.id == membership_id,
            OrganizationMembership.organization_id == org_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigator membership not found.")

    if data.role is not None:
        membership.role = data.role
    if data.is_active is not None:
        membership.is_active = data.is_active
        if not data.is_active:
            # Revoke active sessions in this org
            sessions = db.scalars(
                select(UserSession).where(
                    UserSession.user_id == membership.user_id,
                    UserSession.organization_id == org_id,
                    UserSession.revoked_at.is_(None),
                )
            ).all()
            now = datetime.now(timezone.utc)
            for s in sessions:
                s.revoked_at = now

    record_system_audit(
        db,
        action="INVESTIGATOR_UPDATED",
        resource_type="membership",
        actor_email=actor.email,
        organization_id=org_id,
        user_id=actor.id,
        resource_id=membership.user.email,
        ip_address=ip_address,
        details={"role": membership.role.value, "isActive": membership.is_active},
    )
    db.commit()
    db.refresh(membership)
    return InvestigatorMemberResponse(
        membership_id=membership.id,
        user_id=membership.user.id,
        email=membership.user.email,
        full_name=membership.user.full_name,
        role=membership.role,
        is_active=bool(membership.is_active and membership.user.is_active),
        mfa_enabled=membership.user.mfa_enabled,
        last_login_at=membership.user.last_login_at,
        created_at=membership.created_at,
    )
