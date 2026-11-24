from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import WRITE_EVIDENCE_ROLES, AuthContext, get_current_auth, require_roles
from app.db.session import get_db
from app.models.evidence import CustodyAction, EvidenceType
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
from app.services.auth import record_system_audit
from app.services.evidence import (
    _sanitize_filename,
    append_custody_event,
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
from app.storage.local import get_evidence_storage

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("", response_model=EvidenceListResponse)
def read_evidence_list(
    case_id: str | None = Query(default=None, alias="caseId"),
    evidence_type: EvidenceType | None = Query(default=None, alias="evidenceType"),
    q: str | None = Query(default=None, max_length=200),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> EvidenceListResponse:
    items = list_evidence(
        db,
        organization_id=auth.organization.id,
        case_ref=case_id,
        evidence_type=evidence_type,
        query=q,
    )
    serialized = [serialize_evidence_item(item) for item in items]
    return EvidenceListResponse(items=serialized, total=len(serialized))


@router.get("/integrity/summary", response_model=IntegritySummaryResponse)
def read_integrity_summary(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> IntegritySummaryResponse:
    return get_integrity_summary(db, organization_id=auth.organization.id)


@router.get("/custody/ledger", response_model=CustodyLedgerResponse)
def read_custody_ledger(
    evidence_id: str | None = Query(default=None, alias="evidenceId"),
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> CustodyLedgerResponse:
    return get_custody_ledger(db, organization_id=auth.organization.id, evidence_ref=evidence_id)


@router.post("/upload", response_model=EvidenceItemResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    case_id: str = Form(..., alias="caseId"),
    evidence_type: EvidenceType = Form(default=EvidenceType.LOG_FILE, alias="evidenceType"),
    acquisition_source: str | None = Form(default=None, alias="acquisitionSource"),
    collected_by: str | None = Form(default=None, alias="collectedBy"),
    description: str | None = Form(default=None),
    file: UploadFile = File(...),
    auth: AuthContext = Depends(require_roles(*WRITE_EVIDENCE_ROLES)),
    db: Session = Depends(get_db),
) -> EvidenceItemResponse:
    item = await ingest_evidence_file(
        db,
        case_ref=case_id,
        upload=file,
        organization_id=auth.organization.id,
        evidence_type=evidence_type,
        acquisition_source=acquisition_source,
        collected_by=collected_by,
        description=description,
        actor=auth.actor_label,
    )
    return serialize_evidence_item(item)


@router.get("/{evidence_id}", response_model=EvidenceDetailResponse)
def read_evidence_detail(
    evidence_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> EvidenceDetailResponse:
    item = get_evidence_by_id(db, evidence_id, organization_id=auth.organization.id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found.")
    return serialize_evidence_detail(item)


@router.get("/{evidence_id}/download")
def download_evidence_file(
    evidence_id: str,
    request: Request,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> Response:
    item = get_evidence_by_id(db, evidence_id, organization_id=auth.organization.id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found.")
    storage = get_evidence_storage()
    try:
        data = storage.read_bytes(item.stored_path)
    except (FileNotFoundError, ValueError) as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file unavailable.") from err

    append_custody_event(
        db,
        item,
        action=CustodyAction.EXPORTED,
        actor=auth.actor_label,
        location="CyberTrace Evidence Vault",
        notes=f"Authorized download by {auth.user.email}.",
    )
    record_system_audit(
        db,
        action="EVIDENCE_DOWNLOADED",
        resource_type="evidence",
        actor_email=auth.user.email,
        organization_id=auth.organization.id,
        user_id=auth.user.id,
        resource_id=item.evidence_code,
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    safe_name = _sanitize_filename(item.original_filename)
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
def trigger_evidence_verification(
    evidence_id: str,
    verified_by: str | None = Query(default=None, alias="verifiedBy"),
    auth: AuthContext = Depends(require_roles(*WRITE_EVIDENCE_ROLES)),
    db: Session = Depends(get_db),
) -> EvidenceVerificationResponse:
    item = get_evidence_by_id(db, evidence_id, organization_id=auth.organization.id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found.")
    verification = verify_evidence_integrity(db, item, verified_by=verified_by or auth.actor_label)
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
    auth: AuthContext = Depends(require_roles(*WRITE_EVIDENCE_ROLES)),
    db: Session = Depends(get_db),
) -> CustodyEventResponse:
    item = get_evidence_by_id(db, evidence_id, organization_id=auth.organization.id)
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
