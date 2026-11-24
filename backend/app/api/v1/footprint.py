from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.session import get_db
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
    db: Session = Depends(get_db),
) -> UrlInvestigationResponse:
    return run_url_research(db, data)


@router.get("", response_model=UrlInvestigationListResponse)
def read_url_investigations(
    case_id: str | None = Query(default=None, alias="caseId"),
    db: Session = Depends(get_db),
) -> UrlInvestigationListResponse:
    items = list_url_investigations(db, case_ref=case_id)
    return UrlInvestigationListResponse(items=items, total=len(items))


@router.get("/{investigation_code}", response_model=UrlInvestigationResponse)
def read_url_investigation(
    investigation_code: str,
    db: Session = Depends(get_db),
) -> UrlInvestigationResponse:
    row = db.scalar(
        select(UrlInvestigation)
        .options(selectinload(UrlInvestigation.case))
        .where(UrlInvestigation.investigation_code == investigation_code.strip().upper())
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="URL investigation not found.")
    return serialize_url_investigation(row)
