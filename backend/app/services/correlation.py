from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.analysis import ForensicEvent
from app.models.case import Case
from app.services.cases import get_case_by_id


def correlate_events(
    db: Session,
    *,
    organization_id: int,
    case_ref: str | None = None,
) -> list[dict[str, Any]]:
    """Correlate recorded forensic events by shared IP, shared username, or tight temporal bursts.
    Every correlation explicitly states why events were associated and never claims unproven causality.
    """
    stmt = (
        select(ForensicEvent)
        .join(Case, ForensicEvent.case_id == Case.id)
        .options(selectinload(ForensicEvent.case), selectinload(ForensicEvent.evidence))
        .where(Case.organization_id == organization_id, Case.is_deleted.is_(False))
    )
    if case_ref:
        case = get_case_by_id(db, case_ref, organization_id=organization_id)
        if case is None:
            return []
        stmt = stmt.where(ForensicEvent.case_id == case.id)

    events = list(
        db.scalars(stmt.order_by(ForensicEvent.occurred_at.asc(), ForensicEvent.id.asc()).limit(1000)).all()
    )
    if len(events) < 2:
        return []

    correlations: list[dict[str, Any]] = []

    # 1. Shared Source IP across multiple event types or evidence sources
    by_ip: dict[str, list[ForensicEvent]] = defaultdict(list)
    for ev in events:
        if ev.source_ip:
            by_ip[ev.source_ip].append(ev)

    for ip, group in by_ip.items():
        if len(group) < 2:
            continue
        ev_types = sorted({e.event_type for e in group})
        ev_codes = sorted({e.evidence.evidence_code for e in group if e.evidence})
        case_nums = sorted({e.case.case_number for e in group if e.case})
        span_sec = int((group[-1].occurred_at - group[0].occurred_at).total_seconds())
        confidence = "HIGH" if len(ev_codes) > 1 or len(ev_types) > 1 else "MEDIUM"
        correlations.append(
            {
                "id": f"corr-ip-{ip}",
                "correlationType": "SHARED_SOURCE_IP",
                "key": ip,
                "confidence": confidence,
                "eventCount": len(group),
                "caseNumbers": case_nums,
                "evidenceCodes": ev_codes,
                "eventIds": [e.id for e in group[:25]],
                "firstSeenAt": group[0].occurred_at.isoformat(),
                "lastSeenAt": group[-1].occurred_at.isoformat(),
                "explanation": (
                    f"{len(group)} recorded events share source IP {ip} across "
                    f"{len(ev_codes)} evidence item(s) ({', '.join(ev_types)}) over {span_sec}s. "
                    "Association indicates shared network origin; investigator verification is required to confirm attribution."
                ),
            }
        )

    # 2. Shared Username across multiple IPs or event categories
    by_user: dict[str, list[ForensicEvent]] = defaultdict(list)
    for ev in events:
        if ev.username:
            by_user[ev.username].append(ev)

    for user, group in by_user.items():
        if len(group) < 2:
            continue
        ips = sorted({e.source_ip for e in group if e.source_ip})
        categories = sorted({e.category for e in group})
        ev_codes = sorted({e.evidence.evidence_code for e in group if e.evidence})
        case_nums = sorted({e.case.case_number for e in group if e.case})
        has_priv = any("Privilege" in c for c in categories)
        has_fail_and_ok = "Unsuccessful" in categories and "Successful" in categories
        confidence = "HIGH" if (has_fail_and_ok or has_priv) else "MEDIUM"
        correlations.append(
            {
                "id": f"corr-user-{user}",
                "correlationType": "SHARED_ACCOUNT_ACTIVITY",
                "key": user,
                "confidence": confidence,
                "eventCount": len(group),
                "caseNumbers": case_nums,
                "evidenceCodes": ev_codes,
                "eventIds": [e.id for e in group[:25]],
                "firstSeenAt": group[0].occurred_at.isoformat(),
                "lastSeenAt": group[-1].occurred_at.isoformat(),
                "explanation": (
                    f"{len(group)} events reference account '{user}' with categories [{', '.join(categories)}]"
                    + (f" across {len(ips)} IP(s) ({', '.join(ips[:4])}). " if ips else ". ")
                    + "Sequence warrants investigator review to distinguish legitimate administration from account misuse."
                ),
            }
        )

    # 3. Temporal burst clusters (events within 5 minutes of each other across different types)
    window = timedelta(minutes=5)
    cluster: list[ForensicEvent] = [events[0]]
    cluster_idx = 0
    for ev in events[1:]:
        if ev.occurred_at - cluster[-1].occurred_at <= window:
            cluster.append(ev)
        else:
            if len(cluster) >= 4 and len({e.event_type for e in cluster}) >= 2:
                cluster_idx += 1
                correlations.append(
                    {
                        "id": f"corr-time-{cluster_idx}",
                        "correlationType": "TEMPORAL_PROXIMITY",
                        "key": cluster[0].occurred_at.strftime("%Y-%m-%d %H:%M UTC"),
                        "confidence": "LOW",
                        "eventCount": len(cluster),
                        "caseNumbers": sorted({e.case.case_number for e in cluster if e.case}),
                        "evidenceCodes": sorted({e.evidence.evidence_code for e in cluster if e.evidence}),
                        "eventIds": [e.id for e in cluster[:25]],
                        "firstSeenAt": cluster[0].occurred_at.isoformat(),
                        "lastSeenAt": cluster[-1].occurred_at.isoformat(),
                        "explanation": (
                            f"{len(cluster)} multi-type events ({', '.join(sorted({e.event_type for e in cluster}))}) "
                            "occurred within a 5-minute window. Temporal proximity alone does not prove causal linkage."
                        ),
                    }
                )
            cluster = [ev]
    if len(cluster) >= 4 and len({e.event_type for e in cluster}) >= 2:
        cluster_idx += 1
        correlations.append(
            {
                "id": f"corr-time-{cluster_idx}",
                "correlationType": "TEMPORAL_PROXIMITY",
                "key": cluster[0].occurred_at.strftime("%Y-%m-%d %H:%M UTC"),
                "confidence": "LOW",
                "eventCount": len(cluster),
                "caseNumbers": sorted({e.case.case_number for e in cluster if e.case}),
                "evidenceCodes": sorted({e.evidence.evidence_code for e in cluster if e.evidence}),
                "eventIds": [e.id for e in cluster[:25]],
                "firstSeenAt": cluster[0].occurred_at.isoformat(),
                "lastSeenAt": cluster[-1].occurred_at.isoformat(),
                "explanation": (
                    f"{len(cluster)} multi-type events ({', '.join(sorted({e.event_type for e in cluster}))}) "
                    "occurred within a 5-minute window. Temporal proximity alone does not prove causal linkage."
                ),
            }
        )

    correlations.sort(key=lambda c: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(c["confidence"], 3), -c["eventCount"]))
    return correlations
