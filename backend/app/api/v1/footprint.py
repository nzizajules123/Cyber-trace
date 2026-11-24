from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import WRITE_EVIDENCE_ROLES, AuthContext, get_current_auth, require_roles
from app.db.session import get_db
from app.models.case import Case
from app.models.footprint import UrlInvestigation
from app.schemas.footprint import (
    UrlInvestigationListResponse,
    UrlInvestigationResponse,
    UrlResearchRequest,
)
from app.services.url_research import (
    list_url_investigations,
    run_url_research,
    serialize_url_investigation,
)

router = APIRouter(prefix="/footprint", tags=["digital-footprint"])


@router.post("/research", response_model=UrlInvestigationResponse, status_code=status.HTTP_201_CREATED)
def research_website_url(
    data: UrlResearchRequest,
    auth: AuthContext = Depends(require_roles(*WRITE_EVIDENCE_ROLES)),
    db: Session = Depends(get_db),
) -> UrlInvestigationResponse:
    return run_url_research(
        db,
        data,
        organization_id=auth.organization.id,
        actor=auth.actor_label,
    )


@router.get("", response_model=UrlInvestigationListResponse)
def read_url_investigations(
    case_id: str | None = Query(default=None, alias="caseId"),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> UrlInvestigationListResponse:
    items = list_url_investigations(db, organization_id=auth.organization.id, case_ref=case_id)
    return UrlInvestigationListResponse(items=items, total=len(items))


@router.get("/{investigation_code}", response_model=UrlInvestigationResponse)
def read_url_investigation(
    investigation_code: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> UrlInvestigationResponse:
    row = db.scalar(
        select(UrlInvestigation)
        .join(Case, UrlInvestigation.case_id == Case.id)
        .options(selectinload(UrlInvestigation.case))
        .where(
            UrlInvestigation.investigation_code == investigation_code.strip().upper(),
            Case.organization_id == auth.organization.id,
            Case.is_deleted.is_(False),
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL investigation not found.")
    return serialize_url_investigation(row)
