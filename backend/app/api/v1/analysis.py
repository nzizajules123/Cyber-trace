from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import WRITE_EVIDENCE_ROLES, AuthContext, get_current_auth, require_roles
from app.db.session import get_db
from app.integrations.ai_assistant import generate_evidence_backed_assistance
from app.models.analysis import FindingStatus, ForensicFinding
from app.models.case import Case, CaseSeverity
from app.schemas.analysis import (
    AiAssistRequest,
    AnalysisRunResponse,
    EventListResponse,
    FindingCreateRequest,
    FindingListResponse,
    FindingReviewUpdate,
    ForensicFindingResponse,
    IocSummaryResponse,
    TimelineResponse,
)
from app.services.cases import get_case_by_id
from app.services.correlation import correlate_events
from app.services.evidence import get_evidence_by_id
from app.services.log_analyzer import (
    aggregate_iocs,
    analyze_evidence_file,
    build_unified_timeline,
    create_manual_finding,
    list_findings,
    list_forensic_events,
    review_finding,
    serialize_event,
    serialize_finding,
)

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("/evidence/{evidence_id}/analyze", response_model=AnalysisRunResponse)
def run_evidence_analysis(
    evidence_id: str,
    auth: AuthContext = Depends(require_roles(*WRITE_EVIDENCE_ROLES)),
    db: Session = Depends(get_db),
) -> AnalysisRunResponse:
    evidence = get_evidence_by_id(db, evidence_id, organization_id=auth.organization.id)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found.")
    return analyze_evidence_file(db, evidence, actor=auth.actor_label)


@router.get("/events", response_model=EventListResponse)
def read_forensic_events(
    case_id: str | None = Query(default=None, alias="caseId"),
    evidence_id: int | None = Query(default=None, alias="evidenceId"),
    event_type: str | None = Query(default=None, alias="eventType"),
    q: str | None = Query(default=None, max_length=200),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> EventListResponse:
    items = list_forensic_events(
        db,
        organization_id=auth.organization.id,
        case_ref=case_id,
        evidence_id=evidence_id,
        event_type=event_type,
        query=q,
    )
    serialized = [serialize_event(item) for item in items]
    return EventListResponse(items=serialized, total=len(serialized))


@router.get("/iocs", response_model=IocSummaryResponse)
def read_extracted_iocs(
    case_id: str | None = Query(default=None, alias="caseId"),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> IocSummaryResponse:
    items = aggregate_iocs(db, organization_id=auth.organization.id, case_ref=case_id)
    return IocSummaryResponse(total_unique=len(items), items=items)


@router.get("/correlations")
def read_event_correlations(
    case_id: str | None = Query(default=None, alias="caseId"),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> dict:
    items = correlate_events(db, organization_id=auth.organization.id, case_ref=case_id)
    return {"total": len(items), "items": items}


@router.get("/findings", response_model=FindingListResponse)
def read_findings(
    case_id: str | None = Query(default=None, alias="caseId"),
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    severity: CaseSeverity | None = None,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> FindingListResponse:
    items = list_findings(
        db,
        organization_id=auth.organization.id,
        case_ref=case_id,
        status_filter=finding_status,
        severity_filter=severity,
    )
    serialized = [serialize_finding(item) for item in items]
    return FindingListResponse(items=serialized, total=len(serialized))


@router.post("/findings", response_model=ForensicFindingResponse, status_code=status.HTTP_201_CREATED)
def create_finding(
    data: FindingCreateRequest,
    auth: AuthContext = Depends(require_roles(*WRITE_EVIDENCE_ROLES)),
    db: Session = Depends(get_db),
) -> ForensicFindingResponse:
    created = create_manual_finding(db, data, organization_id=auth.organization.id, actor=auth.actor_label)
    return serialize_finding(created)


@router.patch("/findings/{finding_id}", response_model=ForensicFindingResponse)
def update_finding_review(
    finding_id: int,
    data: FindingReviewUpdate,
    auth: AuthContext = Depends(require_roles(*WRITE_EVIDENCE_ROLES)),
    db: Session = Depends(get_db),
) -> ForensicFindingResponse:
    finding = db.scalar(
        select(ForensicFinding)
        .join(Case, ForensicFinding.case_id == Case.id)
        .options(selectinload(ForensicFinding.case), selectinload(ForensicFinding.evidence))
        .where(
            ForensicFinding.id == finding_id,
            Case.organization_id == auth.organization.id,
            Case.is_deleted.is_(False),
        )
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic finding not found.")
    updated = review_finding(db, finding, data, actor=auth.actor_label)
    return serialize_finding(updated)


@router.get("/timeline", response_model=TimelineResponse)
def read_case_timeline(
    case_id: str | None = Query(default=None, alias="caseId"),
    limit: int = Query(default=150, ge=1, le=500),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> TimelineResponse:
    items = build_unified_timeline(db, organization_id=auth.organization.id, case_ref=case_id, limit=limit)
    return TimelineResponse(total=len(items), items=items)


@router.post("/ai/assist")
def run_ai_investigation_assistant(
    data: AiAssistRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> dict:
    case = get_case_by_id(db, data.case_id, organization_id=auth.organization.id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return generate_evidence_backed_assistance(
        db,
        case=case,
        organization_id=auth.organization.id,
        question=data.question,
    )
