from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.session import get_db
from app.models.analysis import FindingStatus, ForensicFinding
from app.models.case import CaseSeverity
from app.schemas.analysis import (
    AnalysisRunResponse,
    EventListResponse,
    FindingListResponse,
    FindingReviewUpdate,
    ForensicFindingResponse,
    IocSummaryResponse,
    TimelineResponse,
)
from app.services.evidence import get_evidence_by_id
from app.services.log_analyzer import (
    aggregate_iocs,
    analyze_evidence_file,
    build_unified_timeline,
    list_findings,
    list_forensic_events,
    review_finding,
    serialize_event,
    serialize_finding,
)

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("/evidence/{evidence_id}/analyze", response_model=AnalysisRunResponse)
def run_evidence_analysis(evidence_id: str, db: Session = Depends(get_db)) -> AnalysisRunResponse:
    evidence = get_evidence_by_id(db, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found.")
    return analyze_evidence_file(db, evidence)


@router.get("/events", response_model=EventListResponse)
def read_forensic_events(
    case_id: str | None = Query(default=None, alias="caseId"),
    evidence_id: int | None = Query(default=None, alias="evidenceId"),
    event_type: str | None = Query(default=None, alias="eventType"),
    q: str | None = Query(default=None, max_length=200),
    db: Session = Depends(get_db),
) -> EventListResponse:
    items = list_forensic_events(
        db,
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
    db: Session = Depends(get_db),
) -> IocSummaryResponse:
    items = aggregate_iocs(db, case_ref=case_id)
    return IocSummaryResponse(total_unique=len(items), items=items)


@router.get("/findings", response_model=FindingListResponse)
def read_findings(
    case_id: str | None = Query(default=None, alias="caseId"),
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    severity: CaseSeverity | None = None,
    db: Session = Depends(get_db),
) -> FindingListResponse:
    items = list_findings(
        db,
        case_ref=case_id,
        status_filter=finding_status,
        severity_filter=severity,
    )
    serialized = [serialize_finding(item) for item in items]
    return FindingListResponse(items=serialized, total=len(serialized))


@router.patch("/findings/{finding_id}", response_model=ForensicFindingResponse)
def update_finding_review(
    finding_id: int,
    data: FindingReviewUpdate,
    db: Session = Depends(get_db),
) -> ForensicFindingResponse:
    finding = db.scalar(
        select(ForensicFinding)
        .options(selectinload(ForensicFinding.case), selectinload(ForensicFinding.evidence))
        .where(ForensicFinding.id == finding_id)
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic finding not found.")
    updated = review_finding(db, finding, data)
    return serialize_finding(updated)


@router.get("/timeline", response_model=TimelineResponse)
def read_case_timeline(
    case_id: str | None = Query(default=None, alias="caseId"),
    limit: int = Query(default=150, ge=1, le=500),
    db: Session = Depends(get_db),
) -> TimelineResponse:
    items = build_unified_timeline(db, case_ref=case_id, limit=limit)
    return TimelineResponse(total=len(items), items=items)
