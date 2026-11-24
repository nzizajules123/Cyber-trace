from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.security import hash_token
from app.db.session import get_db
from app.models.auth import Organization, OrganizationMembership, OrgRole, User, UserSession

SESSION_COOKIE_NAME = "cybertrace_session"

ADMIN_ROLES = (OrgRole.SYSTEM_ADMIN, OrgRole.ORG_ADMIN)
WRITE_CASE_ROLES = (
    OrgRole.SYSTEM_ADMIN,
    OrgRole.ORG_ADMIN,
    OrgRole.LEAD_INVESTIGATOR,
    OrgRole.INVESTIGATOR,
)
WRITE_EVIDENCE_ROLES = (
    OrgRole.SYSTEM_ADMIN,
    OrgRole.ORG_ADMIN,
    OrgRole.LEAD_INVESTIGATOR,
    OrgRole.INVESTIGATOR,
    OrgRole.EVIDENCE_ANALYST,
)


@dataclass
class AuthContext:
    user: User
    organization: Organization
    membership: OrganizationMembership
    session: UserSession

    @property
    def actor_label(self) -> str:
        return f"{self.user.full_name} <{self.user.email}>"

    @property
    def role(self) -> OrgRole:
        return self.membership.role


def _extract_raw_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if token:
            return token
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        return cookie_token.strip()
    return None


def get_current_auth(
    request: Request,
    db: Session = Depends(get_db),
) -> AuthContext:
    raw_token = _extract_raw_token(request)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session_row = db.scalar(
        select(UserSession)
        .options(selectinload(UserSession.user), selectinload(UserSession.organization))
        .where(
            UserSession.token_hash == hash_token(raw_token),
            UserSession.revoked_at.is_(None),
        )
    )
    if session_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = datetime.now(timezone.utc)
    exp = (
        session_row.expires_at
        if session_row.expires_at.tzinfo
        else session_row.expires_at.replace(tzinfo=timezone.utc)
    )
    if exp < now or not session_row.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or account deactivated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == session_row.organization_id,
            OrganizationMembership.user_id == session_row.user_id,
            OrganizationMembership.is_active.is_(True),
        )
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization membership is inactive.",
        )

    return AuthContext(
        user=session_row.user,
        organization=session_row.organization,
        membership=membership,
        session=session_row,
    )


def require_roles(*allowed: OrgRole):
    def _checker(auth: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if auth.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this action.",
            )
        return auth

    return _checker
