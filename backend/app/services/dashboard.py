from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.models.analysis import FindingStatus, ForensicEvent, ForensicFinding
from app.models.audit import AuditLog
from app.models.case import Case, CaseSeverity, CaseStatus
from app.models.evidence import EvidenceItem
from app.schemas.case import CaseResponse
from app.schemas.dashboard import (
    ActivityEventResponse,
    CountPointResponse,
    DashboardAnalyticsResponse,
    DashboardMetricsResponse,
    DashboardOverviewResponse,
    EvidenceIntegrityResponse,
    EvidenceVerificationCheckResponse,
    MetricValueResponse,
)
from app.services.cases import ACTIVE_CASE_STATUSES


def _format_audit_description(action: str, changes: dict, case_title: str) -> str:
    if action == "CASE_CREATED":
        return f"Case created: {case_title}."
    if action == "CASE_DELETED":
        return f"Case archived: {case_title}."
    if action == "EVIDENCE_INGESTED":
        code = (changes.get("evidenceCode") or {}).get("new") or "evidence"
        fname = (changes.get("filename") or {}).get("new") or "file"
        return f"Evidence {code} ingested ({fname})."
    if action == "EVIDENCE_ANALYZED":
        code = (changes.get("evidenceCode") or {}).get("new") or "evidence"
        parsed = (changes.get("eventsParsed") or {}).get("new") or 0
        return f"Automated analysis completed on {code} ({parsed} events parsed)."
    if action == "FINDING_REVIEWED":
        title = (changes.get("findingTitle") or {}).get("new") or "finding"
        new_st = (changes.get("status") or {}).get("new") or "updated"
        return f"Finding '{title}' marked {new_st}."
    if action == "URL_RESEARCH_COMPLETED":
        url = (changes.get("targetUrl") or {}).get("new") or "URL"
        level = (changes.get("riskLevel") or {}).get("new") or "LOW"
        return f"Digital footprint research completed for {url} (Risk: {level})."
    if action == "CASE_STATUS_CHANGED":
        status_change = changes.get("status")
        if isinstance(status_change, dict):
            old_val = status_change.get("old") or "—"
            new_val = status_change.get("new") or "—"
            return f"Case status changed from {old_val} to {new_val}."
        return "Case status updated."
    if changes:
        changed_fields = ", ".join(changes.keys())
        return f"Case updated ({changed_fields})."
    return "Case record updated."


def get_dashboard_overview(
    db: Session,
    *,
    organization_id: int | None = None,
    current_user: dict[str, str] | None = None,
) -> DashboardOverviewResponse:
    now = datetime.now(timezone.utc)
    org_filters = [Case.is_deleted.is_(False)]
    if organization_id is not None:
        org_filters.append(Case.organization_id == organization_id)

    active_count = (
        db.scalar(
            select(func.count(Case.id)).where(
                *org_filters,
                Case.status.in_(ACTIVE_CASE_STATUSES),
            )
        )
        or 0
    )
    review_cases_count = (
        db.scalar(
            select(func.count(Case.id)).where(
                *org_filters,
                Case.status.in_(ACTIVE_CASE_STATUSES),
                or_(
                    Case.status == CaseStatus.ESCALATED,
                    Case.severity == CaseSeverity.CRITICAL,
                ),
            )
        )
        or 0
    )
    pending_findings_count = (
        db.scalar(
            select(func.count(ForensicFinding.id))
            .join(Case, ForensicFinding.case_id == Case.id)
            .where(
                *org_filters,
                ForensicFinding.status == FindingStatus.REQUIRES_REVIEW,
            )
        )
        or 0
    )
    total_forensic_events = (
        db.scalar(
            select(func.count(ForensicEvent.id))
            .join(Case, ForensicEvent.case_id == Case.id)
            .where(*org_filters)
        )
        or 0
    )
    total_audit_events = (
        db.scalar(
            select(func.count(AuditLog.id))
            .join(Case, AuditLog.case_id == Case.id)
            .where(*org_filters)
        )
        or 0
    )

    recent_cases = list(
        db.scalars(
            select(Case)
            .where(*org_filters)
            .order_by(Case.updated_at.desc(), Case.id.desc())
            .limit(20)
        ).all()
    )

    evidence_items = list(
        db.scalars(
            select(EvidenceItem)
            .join(Case, EvidenceItem.case_id == Case.id)
            .options(selectinload(EvidenceItem.verifications))
            .where(EvidenceItem.is_deleted.is_(False), *org_filters)
            .order_by(EvidenceItem.created_at.desc())
        ).all()
    )
    verification_checks: list[EvidenceVerificationCheckResponse] = []
    evidence_day_counts: Counter[str] = Counter()
    for item in evidence_items:
        if item.created_at:
            evidence_day_counts[item.created_at.strftime("%b %d")] += 1
        if item.verifications:
            latest = item.verifications[-1]
            verification_checks.append(
                EvidenceVerificationCheckResponse(
                    evidence_item_id=item.evidence_code,
                    comparison_performed=latest.comparison_performed,
                    algorithm=latest.algorithm,
                    sha256_matches=latest.sha256_matches,
                )
            )

    activity_events: list[ActivityEventResponse] = []

    recent_findings = list(
        db.scalars(
            select(ForensicFinding)
            .join(Case, ForensicFinding.case_id == Case.id)
            .options(selectinload(ForensicFinding.case), selectinload(ForensicFinding.evidence))
            .where(*org_filters)
            .order_by(ForensicFinding.created_at.desc(), ForensicFinding.id.desc())
            .limit(10)
        ).all()
    )
    for finding in recent_findings:
        activity_events.append(
            ActivityEventResponse(
                id=f"finding-{finding.id}",
                occurred_at=finding.last_seen_at or finding.created_at,
                event_type="Authentication" if "BRUTE" in finding.rule_id or "CREDENTIAL" in finding.rule_id else "Application activity",
                record_type="Analytical finding",
                description=f"{finding.title} — {finding.summary}",
                source_evidence=finding.evidence.original_filename if finding.evidence else finding.rule_id,
                case_id=finding.case.case_number,
                analysis_status=finding.status.value.replace("_", " ").title(),
            )
        )

    recent_audit_rows = db.execute(
        select(AuditLog, Case.case_number, Case.title)
        .join(Case, AuditLog.case_id == Case.id)
        .where(*org_filters)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(15)
    ).all()
    for audit, case_number, title in recent_audit_rows:
        activity_events.append(
            ActivityEventResponse(
                id=f"audit-{audit.id}",
                occurred_at=audit.created_at,
                event_type="Investigation update",
                record_type="Recorded fact",
                description=_format_audit_description(audit.action, audit.changes_json or {}, title),
                source_evidence="Case record",
                case_id=case_number,
                analysis_status="Recorded",
            )
        )

    activity_events.sort(key=lambda e: e.occurred_at, reverse=True)
    activity_events = activity_events[:25]

    day_counts: Counter[str] = Counter()
    start_day = (now - timedelta(days=6)).date()
    start_dt = datetime(start_day.year, start_day.month, start_day.day, tzinfo=timezone.utc)
    for ts in db.scalars(
        select(AuditLog.created_at)
        .join(Case, AuditLog.case_id == Case.id)
        .where(*org_filters, AuditLog.created_at >= start_dt)
    ).all():
        if ts is not None:
            day_counts[ts.strftime("%Y-%m-%d")] += 1
    for ts in db.scalars(
        select(ForensicEvent.occurred_at)
        .join(Case, ForensicEvent.case_id == Case.id)
        .where(*org_filters, ForensicEvent.occurred_at >= start_dt)
    ).all():
        if ts is not None:
            day_counts[ts.strftime("%Y-%m-%d")] += 1

    event_volume = []
    for offset in range(6, -1, -1):
        day = (now - timedelta(days=offset)).date()
        event_volume.append(
            CountPointResponse(
                label=day.strftime("%b %d"),
                count=day_counts.get(day.strftime("%Y-%m-%d"), 0),
            )
        )

    auth_rows = db.execute(
        select(ForensicEvent.category, func.count(ForensicEvent.id))
        .join(Case, ForensicEvent.case_id == Case.id)
        .where(*org_filters, ForensicEvent.event_type == "Authentication")
        .group_by(ForensicEvent.category)
    ).all()
    auth_distribution = [
        CountPointResponse(label=cat, count=int(cnt))
        for cat, cnt in sorted(auth_rows, key=lambda row: row[1], reverse=True)
    ]

    evidence_trend: list[CountPointResponse] = []
    if evidence_items:
        for offset in range(5, -1, -1):
            label = (now - timedelta(days=offset)).strftime("%b %d")
            evidence_trend.append(
                CountPointResponse(label=label, count=evidence_day_counts.get(label, 0))
            )

    findings_metric = int(pending_findings_count) if pending_findings_count > 0 else int(review_cases_count)

    return DashboardOverviewResponse(
        current_user=current_user,
        current_case_id=recent_cases[0].case_number if recent_cases else None,
        notifications=[],
        metrics=DashboardMetricsResponse(
            active_investigations=MetricValueResponse(value=int(active_count)),
            evidence_items=MetricValueResponse(value=len(evidence_items)),
            events_analyzed=MetricValueResponse(value=int(total_forensic_events + total_audit_events)),
            findings_requiring_review=MetricValueResponse(value=findings_metric),
        ),
        cases=[CaseResponse.model_validate(item) for item in recent_cases],
        evidence_integrity=EvidenceIntegrityResponse(
            total_items=len(evidence_items),
            verification_checks=verification_checks,
        ),
        activity_events=activity_events,
        analytics=DashboardAnalyticsResponse(
            event_volume=event_volume,
            authentication_distribution=auth_distribution,
            evidence_collection_trend=evidence_trend,
        ),
        updated_at=now,
    )
