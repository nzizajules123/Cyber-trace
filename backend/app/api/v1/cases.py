from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps import WRITE_CASE_ROLES, AuthContext, get_current_auth, require_roles
from app.db.session import get_db
from app.models.case import CaseSeverity, CaseStatus
from app.schemas.auth import CaseNoteCreateRequest, CaseNoteResponse
from app.schemas.case import (
    CaseCreate,
    CaseDetailResponse,
    CaseMetricsResponse,
    CaseResponse,
    CaseUpdate,
    PaginatedCaseListResponse,
)
from app.services.cases import (
    add_case_note,
    create_case,
    get_case_by_id,
    get_case_metrics,
    list_case_notes,
    list_cases,
    soft_delete_case,
    update_case,
)

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("", response_model=PaginatedCaseListResponse)
def read_cases(
    q: str | None = Query(default=None, max_length=200),
    case_status: CaseStatus | None = Query(default=None, alias="status"),
    severity: CaseSeverity | None = None,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=100),
    skip: int | None = Query(default=None, ge=0),
    limit: int | None = Query(default=None, ge=1, le=100),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> PaginatedCaseListResponse:
    effective_size = limit if limit is not None else size
    effective_skip = skip if skip is not None else (page - 1) * effective_size
    cases, total = list_cases(
        db,
        organization_id=auth.organization.id,
        query=q,
        status_filter=case_status,
        severity_filter=severity,
        skip=effective_skip,
        limit=effective_size,
    )
    return PaginatedCaseListResponse(
        items=cases,
        total=total,
        page=effective_skip // effective_size + 1,
        size=effective_size,
    )


@router.get("/metrics", response_model=CaseMetricsResponse)
def read_case_metrics(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> CaseMetricsResponse:
    return CaseMetricsResponse(**get_case_metrics(db, organization_id=auth.organization.id))


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case_record(
    data: CaseCreate,
    auth: AuthContext = Depends(require_roles(*WRITE_CASE_ROLES)),
    db: Session = Depends(get_db),
) -> CaseResponse:
    return create_case(db, data, organization_id=auth.organization.id, actor=auth.actor_label)


@router.get("/{case_id}", response_model=CaseDetailResponse)
def read_case(
    case_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> CaseDetailResponse:
    case = get_case_by_id(db, case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return CaseDetailResponse.model_validate(case)


@router.patch("/{case_id}", response_model=CaseDetailResponse)
def update_case_record(
    case_id: str,
    data: CaseUpdate,
    auth: AuthContext = Depends(require_roles(*WRITE_CASE_ROLES)),
    db: Session = Depends(get_db),
) -> CaseDetailResponse:
    case = get_case_by_id(db, case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    updated = update_case(db, case, data, actor=auth.actor_label)
    return CaseDetailResponse.model_validate(updated)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_case_record(
    case_id: str,
    auth: AuthContext = Depends(require_roles(*WRITE_CASE_ROLES)),
    db: Session = Depends(get_db),
) -> Response:
    case = get_case_by_id(db, case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    soft_delete_case(db, case, actor=auth.actor_label)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{case_id}/notes", response_model=list[CaseNoteResponse])
def read_case_notes(
    case_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> list[CaseNoteResponse]:
    case = get_case_by_id(db, case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return [CaseNoteResponse.model_validate(n) for n in list_case_notes(db, case.id)]


@router.post("/{case_id}/notes", response_model=CaseNoteResponse, status_code=status.HTTP_201_CREATED)
def create_case_note(
    case_id: str,
    data: CaseNoteCreateRequest,
    auth: AuthContext = Depends(require_roles(*WRITE_CASE_ROLES)),
    db: Session = Depends(get_db),
) -> CaseNoteResponse:
    case = get_case_by_id(db, case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    note = add_case_note(
        db,
        case,
        content=data.content,
        author_id=auth.user.id,
        author_name=auth.actor_label,
    )
    return CaseNoteResponse.model_validate(note)
