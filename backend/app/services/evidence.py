import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException, UploadFile, status
from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.models.audit import AuditLog
from app.models.case import Case
from app.models.evidence import (
    CustodyAction,
    CustodyEvent,
    EvidenceItem,
    EvidenceStatus,
    EvidenceType,
    EvidenceVerification,
)
from app.schemas.evidence import (
    CustodyEventCreate,
    CustodyEventResponse,
    CustodyLedgerResponse,
    EvidenceDetailResponse,
    EvidenceItemResponse,
    EvidenceVerificationResponse,
    IntegritySummaryResponse,
)
from app.services.cases import SYSTEM_ACTOR, get_case_by_id
from app.storage.local import get_evidence_storage

SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
MAX_EVIDENCE_BYTES = 50 * 1024 * 1024  # 50 MB


def _vault_root() -> Path:
    return get_evidence_storage().root


def _sanitize_filename(name: str) -> str:
    base = Path(name or "evidence.bin").name
    cleaned = SAFE_FILENAME_RE.sub("_", base).strip("._")
    return cleaned[:120] or "evidence.bin"


def compute_custody_hash(
    *,
    evidence_code: str,
    action: str,
    actor: str,
    from_custodian: str | None,
    to_custodian: str | None,
    location: str | None,
    notes: str | None,
    occurred_at: datetime,
    previous_hash: str | None,
) -> str:
    payload = {
        "evidenceCode": evidence_code,
        "action": action,
        "actor": actor,
        "fromCustodian": from_custodian,
        "toCustodian": to_custodian,
        "location": location,
        "notes": notes,
        "occurredAt": occurred_at.astimezone(timezone.utc).isoformat()
        if occurred_at.tzinfo
        else occurred_at.replace(tzinfo=timezone.utc).isoformat(),
        "previousHash": previous_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_custody_chain(evidence: EvidenceItem) -> bool:
    events = sorted(evidence.custody_events, key=lambda item: (item.occurred_at, item.id))
    expected_prev: str | None = None
    for event in events:
        if event.previous_hash != expected_prev:
            return False
        recomputed = compute_custody_hash(
            evidence_code=evidence.evidence_code,
            action=event.action.value if isinstance(event.action, CustodyAction) else str(event.action),
            actor=event.actor,
            from_custodian=event.from_custodian,
            to_custodian=event.to_custodian,
            location=event.location,
            notes=event.notes,
            occurred_at=event.occurred_at,
            previous_hash=event.previous_hash,
        )
        if recomputed != event.entry_hash:
            return False
        expected_prev = event.entry_hash
    return True


def append_custody_event(
    db: Session,
    evidence: EvidenceItem,
    *,
    action: CustodyAction,
    actor: str,
    from_custodian: str | None = None,
    to_custodian: str | None = None,
    location: str | None = None,
    notes: str | None = None,
) -> CustodyEvent:
    last_event = db.scalar(
        select(CustodyEvent)
        .where(CustodyEvent.evidence_id == evidence.id)
        .order_by(CustodyEvent.occurred_at.desc(), CustodyEvent.id.desc())
        .limit(1)
    )
    previous_hash = last_event.entry_hash if last_event else None
    occurred_at = datetime.now(timezone.utc)
    entry_hash = compute_custody_hash(
        evidence_code=evidence.evidence_code,
        action=action.value,
        actor=actor,
        from_custodian=from_custodian,
        to_custodian=to_custodian,
        location=location,
        notes=notes,
        occurred_at=occurred_at,
        previous_hash=previous_hash,
    )
    event = CustodyEvent(
        evidence_id=evidence.id,
        action=action,
        actor=actor,
        from_custodian=from_custodian,
        to_custodian=to_custodian,
        location=location,
        notes=notes,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        occurred_at=occurred_at,
    )
    db.add(event)
    return event


def _serialize_verification(
    verification: EvidenceVerification,
    evidence_code: str,
) -> EvidenceVerificationResponse:
    return EvidenceVerificationResponse(
        id=verification.id,
        evidence_id=verification.evidence_id,
        evidence_code=evidence_code,
        algorithm=verification.algorithm,
        expected_hash=verification.expected_hash,
        computed_hash=verification.computed_hash,
        comparison_performed=verification.comparison_performed,
        sha256_matches=verification.sha256_matches,
        verified_by=verification.verified_by,
        notes=verification.notes,
        verified_at=verification.verified_at,
    )


def _serialize_custody(
    event: CustodyEvent,
    *,
    evidence_code: str,
    case_number: str | None,
) -> CustodyEventResponse:
    return CustodyEventResponse(
        id=event.id,
        evidence_id=event.evidence_id,
        evidence_code=evidence_code,
        case_number=case_number,
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


def serialize_evidence_item(evidence: EvidenceItem) -> EvidenceItemResponse:
    latest = evidence.verifications[-1] if evidence.verifications else None
    return EvidenceItemResponse(
        id=evidence.id,
        evidence_code=evidence.evidence_code,
        case_id=evidence.case_id,
        case_number=evidence.case.case_number if evidence.case else None,
        original_filename=evidence.original_filename,
        mime_type=evidence.mime_type,
        file_size=evidence.file_size,
        sha256=evidence.sha256,
        sha512=evidence.sha512,
        md5=evidence.md5,
        evidence_type=evidence.evidence_type,
        status=evidence.status,
        acquisition_source=evidence.acquisition_source,
        collected_by=evidence.collected_by,
        description=evidence.description,
        latest_verification=_serialize_verification(latest, evidence.evidence_code) if latest else None,
        custody_chain_valid=verify_custody_chain(evidence),
        created_at=evidence.created_at,
        updated_at=evidence.updated_at,
    )


def serialize_evidence_detail(evidence: EvidenceItem) -> EvidenceDetailResponse:
    base = serialize_evidence_item(evidence)
    case_number = evidence.case.case_number if evidence.case else None
    return EvidenceDetailResponse(
        **base.model_dump(),
        verifications=[
            _serialize_verification(v, evidence.evidence_code) for v in evidence.verifications
        ],
        custody_events=[
            _serialize_custody(e, evidence_code=evidence.evidence_code, case_number=case_number)
            for e in evidence.custody_events
        ],
    )


def get_evidence_by_id(
    db: Session,
    evidence_id: int | str,
    *,
    organization_id: int | None = None,
) -> EvidenceItem | None:
    stmt = (
        select(EvidenceItem)
        .join(Case, EvidenceItem.case_id == Case.id)
        .options(
            selectinload(EvidenceItem.case),
            selectinload(EvidenceItem.verifications),
            selectinload(EvidenceItem.custody_events),
        )
        .where(EvidenceItem.is_deleted.is_(False), Case.is_deleted.is_(False))
    )
    if organization_id is not None:
        stmt = stmt.where(Case.organization_id == organization_id)
    if isinstance(evidence_id, int):
        return db.scalar(stmt.where(EvidenceItem.id == evidence_id))
    identifier = evidence_id.strip()
    if identifier.isdecimal():
        return db.scalar(stmt.where(EvidenceItem.id == int(identifier)))
    return db.scalar(stmt.where(EvidenceItem.evidence_code == identifier.upper()))


async def ingest_evidence_file(
    db: Session,
    *,
    case_ref: str,
    upload: UploadFile,
    organization_id: int | None = None,
    evidence_type: EvidenceType = EvidenceType.LOG_FILE,
    acquisition_source: str | None = None,
    collected_by: str | None = None,
    description: str | None = None,
    actor: str = SYSTEM_ACTOR,
) -> EvidenceItem:
    case = get_case_by_id(db, case_ref, organization_id=organization_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked case not found.")

    raw_bytes = await upload.read()
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Uploaded evidence file is empty.")
    if len(raw_bytes) > MAX_EVIDENCE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Evidence file exceeds the 50 MB limit.",
        )

    sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
    sha512_hex = hashlib.sha512(raw_bytes).hexdigest()
    md5_hex = hashlib.md5(raw_bytes).hexdigest()

    now = datetime.now(timezone.utc)
    evidence_code = f"EV-{now.year}-{uuid4().hex[:8].upper()}"
    safe_name = _sanitize_filename(upload.filename or "evidence.bin")
    storage = get_evidence_storage()
    stored_path = storage.save_bytes(f"{case.case_number}/{evidence_code}_{safe_name}", raw_bytes)

    collector = (collected_by or "").strip() or actor
    evidence = EvidenceItem(
        evidence_code=evidence_code,
        case_id=case.id,
        original_filename=upload.filename or safe_name,
        stored_path=stored_path,
        mime_type=upload.content_type or "application/octet-stream",
        file_size=len(raw_bytes),
        sha256=sha256_hex,
        sha512=sha512_hex,
        md5=md5_hex,
        evidence_type=evidence_type,
        status=EvidenceStatus.INGESTED,
        acquisition_source=(acquisition_source or "").strip() or None,
        collected_by=collector,
        description=(description or "").strip() or None,
        is_deleted=False,
        created_at=now,
        updated_at=now,
    )
    try:
        db.add(evidence)
        db.flush()

        db.add(
            EvidenceVerification(
                evidence_id=evidence.id,
                algorithm="SHA-256",
                expected_hash=sha256_hex,
                computed_hash=sha256_hex,
                comparison_performed=True,
                sha256_matches=True,
                verified_by=collector,
                notes="Initial cryptographic acquisition digest computed and sealed in vault.",
                verified_at=now,
            )
        )

        append_custody_event(
            db,
            evidence,
            action=CustodyAction.COLLECTED,
            actor=collector,
            to_custodian=collector,
            location=evidence.acquisition_source or "CyberTrace Evidence Vault",
            notes=f"Ingested {evidence.original_filename} ({evidence.file_size} bytes, SHA-256: {sha256_hex[:16]}…).",
        )

        db.add(
            AuditLog(
                case_id=case.id,
                action="EVIDENCE_INGESTED",
                actor=actor,
                changes_json={
                    "evidenceCode": {"old": None, "new": evidence_code},
                    "filename": {"old": None, "new": evidence.original_filename},
                    "sha256": {"old": None, "new": sha256_hex},
                },
            )
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        storage.delete(stored_path)
        raise

    loaded = get_evidence_by_id(db, evidence.id, organization_id=organization_id)
    assert loaded is not None
    return loaded


def list_evidence(
    db: Session,
    *,
    organization_id: int | None = None,
    case_ref: str | None = None,
    evidence_type: EvidenceType | None = None,
    query: str | None = None,
) -> list[EvidenceItem]:
    stmt = (
        select(EvidenceItem)
        .join(Case, EvidenceItem.case_id == Case.id)
        .options(
            selectinload(EvidenceItem.case),
            selectinload(EvidenceItem.verifications),
            selectinload(EvidenceItem.custody_events),
        )
        .where(EvidenceItem.is_deleted.is_(False), Case.is_deleted.is_(False))
    )
    if organization_id is not None:
        stmt = stmt.where(Case.organization_id == organization_id)
    if case_ref:
        case = get_case_by_id(db, case_ref, organization_id=organization_id)
        if case is None:
            return []
        stmt = stmt.where(EvidenceItem.case_id == case.id)
    if evidence_type is not None:
        stmt = stmt.where(EvidenceItem.evidence_type == evidence_type)
    term = (query or "").strip()
    if term:
        stmt = stmt.where(
            or_(
                EvidenceItem.original_filename.icontains(term, autoescape=True),
                EvidenceItem.evidence_code.icontains(term, autoescape=True),
                EvidenceItem.sha256.icontains(term, autoescape=True),
            )
        )
    return list(db.scalars(stmt.order_by(EvidenceItem.created_at.desc(), EvidenceItem.id.desc())).all())


def verify_evidence_integrity(
    db: Session,
    evidence: EvidenceItem,
    *,
    verified_by: str | None = None,
) -> EvidenceVerification:
    actor = (verified_by or "").strip() or SYSTEM_ACTOR
    storage = get_evidence_storage()
    now = datetime.now(timezone.utc)

    try:
        raw_bytes = storage.read_bytes(evidence.stored_path)
        computed_hash: str | None = hashlib.sha256(raw_bytes).hexdigest()
        matches = computed_hash == evidence.sha256
        notes = (
            "SHA-256 digest matches original acquisition hash."
            if matches
            else f"HASH MISMATCH DETECTED! Expected {evidence.sha256[:16]}…, got {computed_hash[:16]}…."
        )
    except (FileNotFoundError, ValueError):
        computed_hash = None
        matches = False
        notes = "Evidence file is missing or inaccessible in vault storage — integrity check failed."

    verification = EvidenceVerification(
        evidence_id=evidence.id,
        algorithm="SHA-256",
        expected_hash=evidence.sha256,
        computed_hash=computed_hash,
        comparison_performed=True,
        sha256_matches=matches,
        verified_by=actor,
        notes=notes,
        verified_at=now,
    )
    try:
        db.add(verification)
        append_custody_event(
            db,
            evidence,
            action=CustodyAction.VERIFIED,
            actor=actor,
            location="CyberTrace Evidence Vault",
            notes=notes,
        )
        db.commit()
        db.refresh(verification)
    except SQLAlchemyError:
        db.rollback()
        raise
    return verification


def record_custody_transfer(
    db: Session,
    evidence: EvidenceItem,
    data: CustodyEventCreate,
) -> CustodyEvent:
    try:
        event = append_custody_event(
            db,
            evidence,
            action=data.action,
            actor=data.actor,
            from_custodian=data.from_custodian,
            to_custodian=data.to_custodian,
            location=data.location,
            notes=data.notes,
        )
        if data.action == CustodyAction.SEALED:
            evidence.status = EvidenceStatus.SEALED
            evidence.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(event)
    except SQLAlchemyError:
        db.rollback()
        raise
    return event


def get_integrity_summary(db: Session, *, organization_id: int | None = None) -> IntegritySummaryResponse:
    items = list_evidence(db, organization_id=organization_id)
    serialized = [serialize_evidence_item(item) for item in items]
    verified = 0
    mismatched = 0
    pending = 0
    for item in serialized:
        latest = item.latest_verification
        if latest and latest.comparison_performed:
            if latest.sha256_matches:
                verified += 1
            else:
                mismatched += 1
        else:
            pending += 1
    return IntegritySummaryResponse(
        total_items=len(serialized),
        verified_count=verified,
        mismatch_count=mismatched,
        pending_count=pending,
        items=serialized,
    )


def get_custody_ledger(
    db: Session,
    *,
    organization_id: int | None = None,
    evidence_ref: str | None = None,
) -> CustodyLedgerResponse:
    items = list_evidence(db, organization_id=organization_id)
    if evidence_ref:
        target = get_evidence_by_id(db, evidence_ref, organization_id=organization_id)
        items = [target] if target else []

    broken_codes: list[str] = []
    all_events: list[CustodyEventResponse] = []
    for item in items:
        if not verify_custody_chain(item):
            broken_codes.append(item.evidence_code)
        case_number = item.case.case_number if item.case else None
        for ev in item.custody_events:
            all_events.append(
                _serialize_custody(ev, evidence_code=item.evidence_code, case_number=case_number)
            )

    all_events.sort(key=lambda e: (e.occurred_at, e.id), reverse=True)
    return CustodyLedgerResponse(
        total_events=len(all_events),
        all_chains_valid=len(broken_codes) == 0,
        broken_evidence_codes=broken_codes,
        events=all_events,
    )
