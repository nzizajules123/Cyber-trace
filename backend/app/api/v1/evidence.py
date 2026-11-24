from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.evidence import EvidenceType
from app.schemas.evidence import (
    CustodyEventCreate,
    CustodyEventResponse,
    CustodyLedgerResponse,
    EvidenceDetailResponse,
    EvidenceItemResponse,
    EvidenceListResponse,
    EvidenceVerificationResponse,
    IntegritySummaryResponse,
)
from app.services.evidence import (
    get_custody_ledger,
    get_evidence_by_id,
    get_integrity_summary,
    ingest_evidence_file,
    list_evidence,
    record_custody_transfer,
    serialize_evidence_detail,
    serialize_evidence_item,
    verify_evidence_integrity,
)

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("", response_model=EvidenceListResponse)
def read_evidence_list(
    case_id: str | None = Query(default=None, alias="caseId"),
    evidence_type: EvidenceType | None = Query(default=None, alias="evidenceType"),
    q: str | None = Query(default=None, max_length=200),
    db: Session = Depends(get_db),
) -> EvidenceListResponse:
    items = list_evidence(db, case_ref=case_id, evidence_type=evidence_type, query=q)
    serialized = [serialize_evidence_item(item) for item in items]
    return EvidenceListResponse(items=serialized, total=len(serialized))


@router.get("/integrity/summary", response_model=IntegritySummaryResponse)
def read_integrity_summary(db: Session = Depends(get_db)) -> IntegritySummaryResponse:
    return get_integrity_summary(db)


@router.get("/custody/ledger", response_model=CustodyLedgerResponse)
def read_custody_ledger(
    evidence_id: str | None = Query(default=None, alias="evidenceId"),
    db: Session = Depends(get_db),
) -> CustodyLedgerResponse:
    return get_custody_ledger(db, evidence_ref=evidence_id)


@router.post("/upload", response_model=EvidenceItemResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    case_id: str = Form(..., alias="caseId"),
    evidence_type: EvidenceType = Form(default=EvidenceType.LOG_FILE, alias="evidenceType"),
    acquisition_source: str | None = Form(default=None, alias="acquisitionSource"),
    collected_by: str | None = Form(default=None, alias="collectedBy"),
    description: str | None = Form(default=None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> EvidenceItemResponse:
    item = await ingest_evidence_file(
        db,
        case_ref=case_id,
        upload=file,
        evidence_type=evidence_type,
        acquisition_source=acquisition_source,
        collected_by=collected_by,
        description=description,
    )
    return serialize_evidence_item(item)


@router.get("/{evidence_id}", response_model=EvidenceDetailResponse)
def read_evidence_detail(evidence_id: str, db: Session = Depends(get_db)) -> EvidenceDetailResponse:
    item = get_evidence_by_id(db, evidence_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found.")
    return serialize_evidence_detail(item)


@router.post("/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
def trigger_evidence_verification(
    evidence_id: str,
    verified_by: str | None = Query(default=None, alias="verifiedBy"),
    db: Session = Depends(get_db),
) -> EvidenceVerificationResponse:
    item = get_evidence_by_id(db, evidence_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found.")
    verification = verify_evidence_integrity(db, item, verified_by=verified_by)
    return EvidenceVerificationResponse(
        id=verification.id,
        evidence_id=verification.evidence_id,
        evidence_code=item.evidence_code,
        algorithm=verification.algorithm,
        expected_hash=verification.expected_hash,
        computed_hash=verification.computed_hash,
        comparison_performed=verification.comparison_performed,
        sha256_matches=verification.sha256_matches,
        verified_by=verification.verified_by,
        notes=verification.notes,
        verified_at=verification.verified_at,
    )


@router.post("/{evidence_id}/custody", response_model=CustodyEventResponse, status_code=status.HTTP_201_CREATED)
def add_custody_event(
    evidence_id: str,
    data: CustodyEventCreate,
    db: Session = Depends(get_db),
) -> CustodyEventResponse:
    item = get_evidence_by_id(db, evidence_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found.")
    event = record_custody_transfer(db, item, data)
    return CustodyEventResponse(
        id=event.id,
        evidence_id=event.evidence_id,
        evidence_code=item.evidence_code,
        case_number=item.case.case_number if item.case else None,
        action=event.action,
        actor=event.actor,
        from_custodian=event.from_custodian,
        to_custodian=event.to_custodian,
        location=event.location,
        notes=event.notes,
        previous_hash=event.previous_hash,
        entry_hash=event.entry_hash,
        occurred_at=event.occurred_at,
    )
