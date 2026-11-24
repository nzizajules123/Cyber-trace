from datetime import datetime, timezone
from enum import Enum as EnumType
from uuid import uuid4

from sqlalchemy import case as sql_case, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.auth import CaseNote
from app.models.case import Case, CaseSeverity, CaseStatus
from app.schemas.case import CaseCreate, CaseUpdate, to_camel

SYSTEM_ACTOR = "system"
ACTIVE_CASE_STATUSES = (CaseStatus.OPEN, CaseStatus.IN_PROGRESS, CaseStatus.ESCALATED)
RESOLVED_CASE_STATUSES = (CaseStatus.RESOLVED, CaseStatus.CLOSED)


def _case_filters(
    *,
    organization_id: int | None = None,
    query: str | None = None,
    status_filter: CaseStatus | None = None,
    severity_filter: CaseSeverity | None = None,
) -> list:
    filters = [Case.is_deleted.is_(False)]
    if organization_id is not None:
        filters.append(Case.organization_id == organization_id)
    if status_filter is not None:
        filters.append(Case.status == status_filter)
    if severity_filter is not None:
        filters.append(Case.severity == severity_filter)

    term = query.strip() if query else ""
    if term:
        filters.append(
            or_(
                Case.title.icontains(term, autoescape=True),
                Case.case_number.icontains(term, autoescape=True),
            )
        )
    return filters


def list_cases(
    db: Session,
    *,
    organization_id: int | None = None,
    query: str | None = None,
    status_filter: CaseStatus | None = None,
    severity_filter: CaseSeverity | None = None,
    skip: int = 0,
    limit: int = 50,
) -> tuple[list[Case], int]:
    filters = _case_filters(
        organization_id=organization_id,
        query=query,
        status_filter=status_filter,
        severity_filter=severity_filter,
    )
    total = db.scalar(select(func.count()).select_from(Case).where(*filters)) or 0
    records = db.scalars(
        select(Case)
        .where(*filters)
        .order_by(Case.updated_at.desc(), Case.id.desc())
        .offset(skip)
        .limit(limit)
    ).all()
    return list(records), total


def get_case_by_id(
    db: Session,
    case_id: int | str,
    *,
    organization_id: int | None = None,
) -> Case | None:
    org_filter = [Case.organization_id == organization_id] if organization_id is not None else []
    if isinstance(case_id, int):
        return db.scalar(
            select(Case).where(Case.id == case_id, Case.is_deleted.is_(False), *org_filter)
        )
    identifier = case_id.strip()
    if identifier.isdecimal():
        return get_case_by_id(db, int(identifier), organization_id=organization_id)
    return db.scalar(
        select(Case).where(
            Case.case_number == identifier.upper(),
            Case.is_deleted.is_(False),
            *org_filter,
        )
    )


def _record_mutation(
    db: Session,
    case: Case,
    *,
    action: str,
    changes: dict,
    actor: str = SYSTEM_ACTOR,
) -> Case:
    db.add(
        AuditLog(
            case_id=case.id,
            action=action,
            actor=actor,
            changes_json=changes,
        )
    )
    try:
        db.commit()
        db.refresh(case)
    except SQLAlchemyError:
        db.rollback()
        raise
    return case


def create_case(
    db: Session,
    data: CaseCreate,
    *,
    organization_id: int | None = None,
    actor: str = SYSTEM_ACTOR,
) -> Case:
    now = datetime.now(timezone.utc)
    case = Case(
        organization_id=organization_id,
        sync_uuid=str(uuid4()),
        sync_version=1,
        case_number=f"CT-{now.year}-{uuid4().hex[:8].upper()}",
        title=data.title,
        description=data.description,
        status=data.status,
        severity=data.severity,
        assigned_to=data.assigned_to,
        reporter_name=data.reporter_name,
        is_deleted=False,
        created_at=now,
        updated_at=now,
    )
    changes: dict[str, dict[str, object]] = {
        "caseNumber": {"old": None, "new": case.case_number},
        "title": {"old": None, "new": case.title},
        "status": {"old": None, "new": case.status.value},
        "severity": {"old": None, "new": case.severity.value},
    }
    if case.description is not None:
        changes["description"] = {"old": None, "new": case.description}
    if case.assigned_to is not None:
        changes["assignedTo"] = {"old": None, "new": case.assigned_to}
    if case.reporter_name is not None:
        changes["reporterName"] = {"old": None, "new": case.reporter_name}

    try:
        db.add(case)
        db.flush()
        _record_mutation(
            db,
            case,
            action="CASE_CREATED",
            changes=changes,
            actor=actor,
        )
    except SQLAlchemyError:
        db.rollback()
        raise
    return case


def update_case(
    db: Session,
    case: Case,
    data: CaseUpdate,
    *,
    actor: str = SYSTEM_ACTOR,
) -> Case:
    changes = {}
    updates = data.model_dump(exclude_unset=True)
    for field, new_value in updates.items():
        current_value = getattr(case, field)
        if current_value == new_value:
            continue
        old_serialized = current_value.value if isinstance(current_value, EnumType) else current_value
        new_serialized = new_value.value if isinstance(new_value, EnumType) else new_value
        changes[to_camel(field)] = {"old": old_serialized, "new": new_serialized}

    if not changes:
        return case

    status_changed = "status" in changes
    for field, new_value in updates.items():
        if to_camel(field) in changes:
            setattr(case, field, new_value)
    case.sync_version = (case.sync_version or 1) + 1
    case.updated_at = datetime.now(timezone.utc)
    try:
        return _record_mutation(
            db,
            case,
            action="CASE_STATUS_CHANGED" if status_changed else "CASE_UPDATED",
            changes=changes,
            actor=actor,
        )
    except SQLAlchemyError:
        db.rollback()
        raise


def soft_delete_case(db: Session, case: Case, *, actor: str = SYSTEM_ACTOR) -> Case:
    if case.is_deleted:
        return case
    case.is_deleted = True
    case.sync_version = (case.sync_version or 1) + 1
    case.updated_at = datetime.now(timezone.utc)
    try:
        return _record_mutation(
            db,
            case,
            action="CASE_DELETED",
            changes={"isDeleted": {"old": False, "new": True}},
            actor=actor,
        )
    except SQLAlchemyError:
        db.rollback()
        raise


def get_case_metrics(db: Session, *, organization_id: int | None = None) -> dict[str, int]:
    filters = [Case.is_deleted.is_(False)]
    if organization_id is not None:
        filters.append(Case.organization_id == organization_id)
    row = db.execute(
        select(
            func.count(Case.id).label("total_cases"),
            func.coalesce(
                func.sum(sql_case((Case.status.in_(ACTIVE_CASE_STATUSES), 1), else_=0)),
                0,
            ).label("open_cases"),
            func.coalesce(
                func.sum(sql_case((Case.severity == CaseSeverity.CRITICAL, 1), else_=0)),
                0,
            ).label("critical_cases"),
            func.coalesce(
                func.sum(sql_case((Case.status.in_(RESOLVED_CASE_STATUSES), 1), else_=0)),
                0,
            ).label("resolved_cases"),
        ).where(*filters)
    ).one()
    return {
        "total_cases": int(row.total_cases),
        "open_cases": int(row.open_cases),
        "critical_cases": int(row.critical_cases),
        "resolved_cases": int(row.resolved_cases),
    }


def list_case_notes(db: Session, case_id: int) -> list[CaseNote]:
    return list(
        db.scalars(
            select(CaseNote)
            .where(CaseNote.case_id == case_id)
            .order_by(CaseNote.created_at.desc(), CaseNote.id.desc())
        ).all()
    )


def add_case_note(
    db: Session,
    case: Case,
    *,
    content: str,
    author_id: int | None,
    author_name: str,
) -> CaseNote:
    note = CaseNote(
        case_id=case.id,
        author_id=author_id,
        author_name=author_name,
        content=content.strip(),
    )
    try:
        db.add(note)
        db.add(
            AuditLog(
                case_id=case.id,
                action="CASE_NOTE_ADDED",
                actor=author_name,
                changes_json={"notePreview": {"old": None, "new": content.strip()[:120]}},
            )
        )
        db.commit()
        db.refresh(note)
    except SQLAlchemyError:
        db.rollback()
        raise
    return note
