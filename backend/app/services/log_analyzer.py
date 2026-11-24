import io
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import HTTPException, status
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.models.analysis import FindingConfidence, FindingStatus, ForensicEvent, ForensicFinding
from app.models.audit import AuditLog
from app.models.case import Case, CaseSeverity
from app.models.evidence import CustodyAction, EvidenceItem, EvidenceStatus
from app.schemas.analysis import (
    AnalysisRunResponse,
    ExtractedIocItem,
    FindingCreateRequest,
    FindingReviewUpdate,
    ForensicEventResponse,
    ForensicFindingResponse,
    TimelineEntryResponse,
)
from app.services.cases import SYSTEM_ACTOR, get_case_by_id
from app.services.evidence import append_custody_event, get_evidence_by_id
from app.storage.local import get_evidence_storage

# Regex patterns for IOC extraction
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Syslog / SSH / Web log parsers
SSH_FAIL_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
SSH_ACCEPT_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
SUDO_RE = re.compile(r"sudo:.*?(?P<user>[A-Za-z0-9_.-]+)\s*:.*?COMMAND=(?P<cmd>.+)", re.IGNORECASE)
APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>[^"\s]+)(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)
ISO_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
SYSLOG_TS_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\b")

WEB_ATTACK_PATTERNS = [
    ("SQL Injection", re.compile(r"(?:'\s*or\s*'1'='1|union\s+select|sleep\(|benchmark\(|--|%27%20or%20)", re.IGNORECASE)),
    ("Path Traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/etc/shadow)", re.IGNORECASE)),
    ("XSS Payload", re.compile(r"(?:<script|javascript:|onerror=|onload=|%3cscript)", re.IGNORECASE)),
    ("Sensitive File Probe", re.compile(r"(?:/\.env|/\.git|/wp-login\.php|/phpmyadmin|/admin/config)", re.IGNORECASE)),
]


def extract_iocs(text: str) -> list[dict[str, str]]:
    found: list[tuple[str, str]] = []
    for match in IPV4_RE.findall(text):
        found.append(("IPv4", match))
    for match in EMAIL_RE.findall(text):
        found.append(("Email", match.lower()))
    for match in URL_RE.findall(text):
        found.append(("URL", match.rstrip(".,;)")))
    for match in CVE_RE.findall(text):
        found.append(("CVE", match.upper()))
    for match in SHA256_RE.findall(text):
        found.append(("SHA-256", match.lower()))
    # Only tag MD5 if not part of a SHA-256
    sha_set = {val for kind, val in found if kind == "SHA-256"}
    for match in MD5_RE.findall(text):
        low = match.lower()
        if not any(low in s for s in sha_set):
            found.append(("MD5", low))

    unique = list(dict.fromkeys(found))
    return [{"type": kind, "value": val} for kind, val in unique]


def _parse_timestamp(raw: Any, fallback: datetime) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not raw or not isinstance(raw, str):
        return fallback
    text = raw.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
            if parsed.year == 1900:
                parsed = parsed.replace(year=fallback.year)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return fallback


def _classify_auth_category(text: str) -> str:
    low = text.lower()
    if any(tok in low for tok in ("mfa", "2fa", "otp", "challenge")):
        return "MFA challenge"
    if any(tok in low for tok in ("fail", "invalid", "denied", "reject", "unsuccessful", "401", "403")):
        return "Unsuccessful"
    if any(tok in low for tok in ("accept", "success", "granted", "logged in", "authenticated", "200")):
        return "Successful"
    return "Other"


def _parse_structured_record(record: dict[str, Any], line_no: int, fallback_ts: datetime) -> dict[str, Any]:
    raw_line = json.dumps(record, default=str)[:1000]
    ts_val = record.get("timestamp") or record.get("occurredAt") or record.get("time") or record.get("date")
    occurred_at = _parse_timestamp(ts_val, fallback_ts)

    source_ip = str(record.get("sourceIp") or record.get("source_ip") or record.get("ip") or record.get("client_ip") or "") or None
    username = str(record.get("username") or record.get("user") or record.get("actor") or record.get("account") or "") or None
    action = str(record.get("action") or record.get("event") or record.get("method") or "") or None
    message = str(record.get("message") or record.get("description") or record.get("detail") or raw_line)

    combined = f"{action or ''} {message} {record.get('status', '')} {record.get('outcome', '')}"
    low = combined.lower()
    if any(tok in low for tok in ("login", "auth", "signin", "sign-in", "password", "ssh", "mfa", "token")):
        event_type = "Authentication"
        category = _classify_auth_category(combined)
    elif any(tok in low for tok in ("file", "read", "write", "delete", "download", "chmod", "access")):
        event_type = "File access"
        category = "File operation"
    elif any(tok in low for tok in ("http", "get ", "post ", "url", "request", "404", "500")):
        event_type = "Web"
        category = str(record.get("status") or "HTTP")
    else:
        event_type = str(record.get("eventType") or record.get("event_type") or "Application activity")
        category = "Other"

    iocs = extract_iocs(raw_line)
    if not source_ip:
        ip_ioc = next((i["value"] for i in iocs if i["type"] == "IPv4"), None)
        source_ip = ip_ioc

    return {
        "occurred_at": occurred_at,
        "event_type": event_type,
        "category": category,
        "source_ip": source_ip,
        "username": username,
        "action": action,
        "description": message[:500],
        "raw_line": raw_line,
        "line_number": line_no,
        "extracted_iocs_json": iocs,
    }


def _parse_text_line(line: str, line_no: int, fallback_ts: datetime) -> dict[str, Any]:
    iocs = extract_iocs(line)
    occurred_at = fallback_ts

    iso_match = ISO_TS_RE.search(line)
    if iso_match:
        occurred_at = _parse_timestamp(iso_match.group(0), fallback_ts)
    else:
        sys_match = SYSLOG_TS_RE.match(line)
        if sys_match:
            occurred_at = _parse_timestamp(
                f"{sys_match.group('mon')} {sys_match.group('day')} {sys_match.group('hms')}",
                fallback_ts,
            )

    apache = APACHE_RE.match(line)
    if apache:
        status_code = apache.group("status")
        method = apache.group("method")
        path = apache.group("path")
        return {
            "occurred_at": _parse_timestamp(apache.group("time"), fallback_ts),
            "event_type": "Web",
            "category": f"HTTP {status_code}",
            "source_ip": apache.group("ip"),
            "username": None if apache.group("user") == "-" else apache.group("user"),
            "action": f"{method} {path}",
            "description": f"{method} {path} returned HTTP {status_code} from {apache.group('ip')}",
            "raw_line": line[:1000],
            "line_number": line_no,
            "extracted_iocs_json": iocs,
        }

    ssh_fail = SSH_FAIL_RE.search(line)
    if ssh_fail:
        return {
            "occurred_at": occurred_at,
            "event_type": "Authentication",
            "category": "Unsuccessful",
            "source_ip": ssh_fail.group("ip"),
            "username": ssh_fail.group("user"),
            "action": "SSH_LOGIN_FAILED",
            "description": f"Failed SSH login for '{ssh_fail.group('user')}' from {ssh_fail.group('ip')}",
            "raw_line": line[:1000],
            "line_number": line_no,
            "extracted_iocs_json": iocs,
        }

    ssh_ok = SSH_ACCEPT_RE.search(line)
    if ssh_ok:
        return {
            "occurred_at": occurred_at,
            "event_type": "Authentication",
            "category": "Successful",
            "source_ip": ssh_ok.group("ip"),
            "username": ssh_ok.group("user"),
            "action": "SSH_LOGIN_ACCEPTED",
            "description": f"Accepted SSH login for '{ssh_ok.group('user')}' from {ssh_ok.group('ip')}",
            "raw_line": line[:1000],
            "line_number": line_no,
            "extracted_iocs_json": iocs,
        }

    sudo = SUDO_RE.search(line)
    if sudo:
        return {
            "occurred_at": occurred_at,
            "event_type": "Application activity",
            "category": "Privilege escalation",
            "source_ip": next((i["value"] for i in iocs if i["type"] == "IPv4"), None),
            "username": sudo.group("user"),
            "action": "SUDO_COMMAND",
            "description": f"Privileged command executed by '{sudo.group('user')}': {sudo.group('cmd').strip()}",
            "raw_line": line[:1000],
            "line_number": line_no,
            "extracted_iocs_json": iocs,
        }

    ip_val = next((i["value"] for i in iocs if i["type"] == "IPv4"), None)
    low = line.lower()
    if any(tok in low for tok in ("auth", "login", "signin", "password", "mfa")):
        ev_type = "Authentication"
        cat = _classify_auth_category(line)
    elif any(tok in low for tok in ("file", "open", "read", "write", "delete")):
        ev_type = "File access"
        cat = "File operation"
    else:
        ev_type = "Application activity"
        cat = "Other"

    return {
        "occurred_at": occurred_at,
        "event_type": ev_type,
        "category": cat,
        "source_ip": ip_val,
        "username": None,
        "action": None,
        "description": line[:500],
        "raw_line": line[:1000],
        "line_number": line_no,
        "extracted_iocs_json": iocs,
    }


def _parse_evidence_content(filename: str, raw_text: str) -> tuple[str, list[dict[str, Any]]]:
    now = datetime.now(timezone.utc)
    suffix = Path(filename).suffix.lower()
    stripped = raw_text.strip()
    if not stripped:
        return "empty", []

    # 1. JSON array or JSONL
    if suffix in (".json", ".jsonl", ".ndjson") or stripped.startswith("{") or stripped.startswith("["):
        if stripped.startswith("["):
            try:
                loaded = json.loads(stripped)
                if isinstance(loaded, list):
                    return "json", [
                        _parse_structured_record(item, idx + 1, now)
                        for idx, item in enumerate(loaded[:2000])
                        if isinstance(item, dict)
                    ]
            except json.JSONDecodeError:
                pass
        parsed_jsonl = []
        for idx, line in enumerate(stripped.splitlines()[:2000], start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    parsed_jsonl.append(_parse_structured_record(obj, idx, now))
            except json.JSONDecodeError:
                parsed_jsonl = []
                break
        if parsed_jsonl:
            return "jsonl", parsed_jsonl

    # 2. CSV (parsed with pandas)
    if suffix == ".csv":
        try:
            df = pd.read_csv(io.StringIO(stripped), nrows=2000)
            records = df.fillna("").to_dict(orient="records")
            if records:
                return "csv", [
                    _parse_structured_record(rec, idx + 2, now) for idx, rec in enumerate(records)
                ]
        except Exception:
            pass

    # 3. Line-by-line syslog / web / generic log
    lines = [line.strip() for line in stripped.splitlines()[:2000] if line.strip()]
    parsed = [_parse_text_line(line, idx, now) for idx, line in enumerate(lines, start=1)]
    has_apache = any(p["event_type"] == "Web" for p in parsed)
    has_ssh = any((p["action"] or "").startswith("SSH_") for p in parsed)
    fmt = "web_access_log" if has_apache else ("syslog_auth" if has_ssh else "text_log")
    return fmt, parsed


def _run_detection_rules(
    case_id: int,
    evidence_id: int,
    events: list[dict[str, Any]],
) -> list[ForensicFinding]:
    findings: list[ForensicFinding] = []

    # Rule 1: Brute-force & Credential Compromise (per source IP)
    failed_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    success_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev["event_type"] == "Authentication" and ev["source_ip"]:
            if ev["category"] == "Unsuccessful":
                failed_by_ip[ev["source_ip"]].append(ev)
            elif ev["category"] == "Successful":
                success_by_ip[ev["source_ip"]].append(ev)

    for ip, fails in failed_by_ip.items():
        if len(fails) >= 5:
            successes = success_by_ip.get(ip, [])
            users = sorted({e["username"] for e in fails + successes if e["username"]})
            all_ev = fails + successes
            timestamps = [e["occurred_at"] for e in all_ev]
            compromised = len(successes) > 0
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    rule_id="RULE_CREDENTIAL_COMPROMISE" if compromised else "RULE_BRUTE_FORCE",
                    title=(
                        f"Suspected credential compromise after brute-force from {ip}"
                        if compromised
                        else f"Authentication brute-force burst from {ip}"
                    ),
                    severity=CaseSeverity.CRITICAL if compromised else CaseSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    status=FindingStatus.REQUIRES_REVIEW,
                    summary=(
                        f"Observed {len(fails)} failed authentication attempts from {ip} followed by "
                        f"{len(successes)} successful login(s) targeting {', '.join(users) or 'unknown account'}."
                        if compromised
                        else f"Observed {len(fails)} failed authentication attempts from {ip} "
                        f"targeting {', '.join(users) or 'unknown account'}."
                    ),
                    indicators_json=[
                        {"type": "IPv4", "value": ip},
                        *[{"type": "Account", "value": u} for u in users[:5]],
                    ],
                    event_count=len(all_ev),
                    first_seen_at=min(timestamps),
                    last_seen_at=max(timestamps),
                )
            )

    # Rule 2: Multi-IP account activity (possible credential sharing / impossible travel)
    ips_by_user: dict[str, set[str]] = defaultdict(set)
    events_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev["event_type"] == "Authentication" and ev["username"] and ev["source_ip"]:
            ips_by_user[ev["username"]].add(ev["source_ip"])
            events_by_user[ev["username"]].append(ev)

    for user, ips in ips_by_user.items():
        if len(ips) >= 3:
            user_events = events_by_user[user]
            timestamps = [e["occurred_at"] for e in user_events]
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    rule_id="RULE_MULTI_IP_ACCOUNT",
                    title=f"Account '{user}' observed across {len(ips)} distinct source IPs",
                    severity=CaseSeverity.HIGH,
                    confidence=FindingConfidence.MEDIUM,
                    status=FindingStatus.REQUIRES_REVIEW,
                    summary=f"Account '{user}' generated authentication events from {len(ips)} distinct IP addresses: {', '.join(sorted(ips)[:6])}.",
                    indicators_json=[
                        {"type": "Account", "value": user},
                        *[{"type": "IPv4", "value": ip} for ip in sorted(ips)[:6]],
                    ],
                    event_count=len(user_events),
                    first_seen_at=min(timestamps),
                    last_seen_at=max(timestamps),
                )
            )

    # Rule 3: Web attack payload signatures (SQLi, Path Traversal, XSS, Sensitive Probes)
    attack_hits: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        haystack = f"{ev.get('action') or ''} {ev.get('raw_line') or ''}"
        for label, pattern in WEB_ATTACK_PATTERNS:
            if pattern.search(haystack):
                attack_hits[label].append(ev)

    for label, hits in attack_hits.items():
        ips = sorted({e["source_ip"] for e in hits if e["source_ip"]})
        timestamps = [e["occurred_at"] for e in hits]
        findings.append(
            ForensicFinding(
                case_id=case_id,
                evidence_id=evidence_id,
                rule_id=f"RULE_WEB_{label.upper().replace(' ', '_')}",
                title=f"{label} pattern detected ({len(hits)} event{'s' if len(hits) != 1 else ''})",
                severity=CaseSeverity.HIGH if label in ("SQL Injection", "Path Traversal") else CaseSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                status=FindingStatus.REQUIRES_REVIEW,
                summary=f"Detected {len(hits)} log entries matching {label} indicators"
                + (f" from {', '.join(ips[:5])}." if ips else "."),
                indicators_json=[{"type": "IPv4", "value": ip} for ip in ips[:5]],
                event_count=len(hits),
                first_seen_at=min(timestamps),
                last_seen_at=max(timestamps),
            )
        )

    # Rule 4: High-volume HTTP 401/403/404 scanning
    web_4xx_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev["event_type"] == "Web" and ev["source_ip"] and ev["category"] in ("HTTP 401", "HTTP 403", "HTTP 404"):
            web_4xx_by_ip[ev["source_ip"]].append(ev)

    for ip, hits in web_4xx_by_ip.items():
        if len(hits) >= 8:
            timestamps = [e["occurred_at"] for e in hits]
            findings.append(
                ForensicFinding(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    rule_id="RULE_WEB_RECON_SCAN",
                    title=f"High-frequency HTTP 4xx reconnaissance from {ip}",
                    severity=CaseSeverity.MEDIUM,
                    confidence=FindingConfidence.MEDIUM,
                    status=FindingStatus.REQUIRES_REVIEW,
                    summary=f"Source IP {ip} triggered {len(hits)} HTTP 401/403/404 responses, consistent with automated scanning.",
                    indicators_json=[{"type": "IPv4", "value": ip}],
                    event_count=len(hits),
                    first_seen_at=min(timestamps),
                    last_seen_at=max(timestamps),
                )
            )

    # Rule 5: Privilege escalation commands
    priv_events = [e for e in events if e["category"] == "Privilege escalation" or e.get("action") == "SUDO_COMMAND"]
    if priv_events:
        users = sorted({e["username"] for e in priv_events if e["username"]})
        timestamps = [e["occurred_at"] for e in priv_events]
        findings.append(
            ForensicFinding(
                case_id=case_id,
                evidence_id=evidence_id,
                rule_id="RULE_PRIVILEGE_ESCALATION",
                title=f"Privileged command execution recorded ({len(priv_events)} event{'s' if len(priv_events) != 1 else ''})",
                severity=CaseSeverity.MEDIUM,
                confidence=FindingConfidence.MEDIUM,
                status=FindingStatus.REQUIRES_REVIEW,
                summary=f"Recorded {len(priv_events)} sudo/privileged command execution(s) by {', '.join(users) or 'unknown user'}.",
                indicators_json=[{"type": "Account", "value": u} for u in users[:5]],
                event_count=len(priv_events),
                first_seen_at=min(timestamps),
                last_seen_at=max(timestamps),
            )
        )

    return findings


def serialize_event(event: ForensicEvent) -> ForensicEventResponse:
    return ForensicEventResponse(
        id=event.id,
        case_id=event.case_id,
        case_number=event.case.case_number if event.case else None,
        evidence_id=event.evidence_id,
        evidence_code=event.evidence.evidence_code if event.evidence else None,
        source_filename=event.evidence.original_filename if event.evidence else None,
        occurred_at=event.occurred_at,
        event_type=event.event_type,
        category=event.category,
        source_ip=event.source_ip,
        username=event.username,
        action=event.action,
        description=event.description,
        line_number=event.line_number,
        extracted_iocs=event.extracted_iocs_json or [],
    )


def serialize_finding(finding: ForensicFinding) -> ForensicFindingResponse:
    return ForensicFindingResponse(
        id=finding.id,
        case_id=finding.case_id,
        case_number=finding.case.case_number if finding.case else None,
        evidence_id=finding.evidence_id,
        evidence_code=finding.evidence.evidence_code if finding.evidence else None,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        status=finding.status,
        summary=finding.summary,
        indicators=finding.indicators_json or [],
        event_count=finding.event_count,
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        reviewer_notes=finding.reviewer_notes,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


def analyze_evidence_file(
    db: Session,
    evidence: EvidenceItem,
    *,
    actor: str = SYSTEM_ACTOR,
) -> AnalysisRunResponse:
    storage = get_evidence_storage()
    try:
        raw_text = storage.read_bytes(evidence.stored_path).decode("utf-8", errors="replace")
    except (FileNotFoundError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file is missing from vault storage.",
        ) from err

    detected_format, parsed_events = _parse_evidence_content(evidence.original_filename, raw_text)
    if not parsed_events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="No parseable log records were found in this evidence file.",
        )

    new_findings = _run_detection_rules(evidence.case_id, evidence.id, parsed_events)
    ioc_counter: Counter[tuple[str, str]] = Counter()
    for ev in parsed_events:
        for ioc in ev["extracted_iocs_json"]:
            ioc_counter[(ioc["type"], ioc["value"])] += 1

    try:
        db.execute(delete(ForensicEvent).where(ForensicEvent.evidence_id == evidence.id))
        db.execute(delete(ForensicFinding).where(ForensicFinding.evidence_id == evidence.id))

        for ev in parsed_events:
            db.add(ForensicEvent(case_id=evidence.case_id, evidence_id=evidence.id, **ev))
        for finding in new_findings:
            db.add(finding)

        evidence.status = EvidenceStatus.ANALYZED
        evidence.updated_at = datetime.now(timezone.utc)

        append_custody_event(
            db,
            evidence,
            action=CustodyAction.ANALYZED,
            actor=actor,
            location="CyberTrace Analysis Engine",
            notes=f"Parsed {len(parsed_events)} events ({detected_format}), extracted {len(ioc_counter)} unique IOCs, generated {len(new_findings)} findings.",
        )
        db.add(
            AuditLog(
                case_id=evidence.case_id,
                action="EVIDENCE_ANALYZED",
                actor=actor,
                changes_json={
                    "evidenceCode": {"old": None, "new": evidence.evidence_code},
                    "eventsParsed": {"old": None, "new": len(parsed_events)},
                    "findingsGenerated": {"old": None, "new": len(new_findings)},
                },
            )
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise

    saved_findings = list(
        db.scalars(
            select(ForensicFinding)
            .options(selectinload(ForensicFinding.case), selectinload(ForensicFinding.evidence))
            .where(ForensicFinding.evidence_id == evidence.id)
            .order_by(ForensicFinding.id.asc())
        ).all()
    )
    iocs_list = [
        ExtractedIocItem(type=kind, value=val, count=cnt)
        for (kind, val), cnt in ioc_counter.most_common(100)
    ]
    return AnalysisRunResponse(
        evidence_code=evidence.evidence_code,
        case_number=evidence.case.case_number,
        detected_format=detected_format,
        events_parsed=len(parsed_events),
        unique_iocs=len(ioc_counter),
        findings_generated=len(saved_findings),
        iocs=iocs_list,
        findings=[serialize_finding(f) for f in saved_findings],
    )


def list_forensic_events(
    db: Session,
    *,
    organization_id: int | None = None,
    case_ref: str | None = None,
    evidence_id: int | None = None,
    event_type: str | None = None,
    query: str | None = None,
    limit: int = 200,
) -> list[ForensicEvent]:
    stmt = (
        select(ForensicEvent)
        .join(Case, ForensicEvent.case_id == Case.id)
        .options(selectinload(ForensicEvent.case), selectinload(ForensicEvent.evidence))
        .where(Case.is_deleted.is_(False))
    )
    if organization_id is not None:
        stmt = stmt.where(Case.organization_id == organization_id)
    if case_ref:
        case = get_case_by_id(db, case_ref, organization_id=organization_id)
        if case is None:
            return []
        stmt = stmt.where(ForensicEvent.case_id == case.id)
    if evidence_id is not None:
        stmt = stmt.where(ForensicEvent.evidence_id == evidence_id)
    if event_type:
        stmt = stmt.where(ForensicEvent.event_type == event_type)
    term = (query or "").strip()
    if term:
        stmt = stmt.where(
            or_(
                ForensicEvent.description.icontains(term, autoescape=True),
                ForensicEvent.source_ip.icontains(term, autoescape=True),
                ForensicEvent.username.icontains(term, autoescape=True),
            )
        )
    return list(
        db.scalars(
            stmt.order_by(ForensicEvent.occurred_at.desc(), ForensicEvent.id.desc()).limit(limit)
        ).all()
    )


def list_findings(
    db: Session,
    *,
    organization_id: int | None = None,
    case_ref: str | None = None,
    status_filter: FindingStatus | None = None,
    severity_filter: CaseSeverity | None = None,
) -> list[ForensicFinding]:
    stmt = (
        select(ForensicFinding)
        .join(Case, ForensicFinding.case_id == Case.id)
        .options(selectinload(ForensicFinding.case), selectinload(ForensicFinding.evidence))
        .where(Case.is_deleted.is_(False))
    )
    if organization_id is not None:
        stmt = stmt.where(Case.organization_id == organization_id)
    if case_ref:
        case = get_case_by_id(db, case_ref, organization_id=organization_id)
        if case is None:
            return []
        stmt = stmt.where(ForensicFinding.case_id == case.id)
    if status_filter is not None:
        stmt = stmt.where(ForensicFinding.status == status_filter)
    if severity_filter is not None:
        stmt = stmt.where(ForensicFinding.severity == severity_filter)
    return list(
        db.scalars(
            stmt.order_by(ForensicFinding.created_at.desc(), ForensicFinding.id.desc())
        ).all()
    )


def create_manual_finding(
    db: Session,
    data: FindingCreateRequest,
    *,
    organization_id: int,
    actor: str = SYSTEM_ACTOR,
) -> ForensicFinding:
    case = get_case_by_id(db, data.case_id, organization_id=organization_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked case not found.")
    evidence = None
    if data.evidence_id:
        evidence = get_evidence_by_id(db, data.evidence_id, organization_id=organization_id)
        if evidence is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked evidence item not found.")

    now = datetime.now(timezone.utc)
    finding = ForensicFinding(
        case_id=case.id,
        evidence_id=evidence.id if evidence else None,
        rule_id="INVESTIGATOR_MANUAL",
        title=data.title.strip(),
        severity=data.severity,
        confidence=data.confidence,
        status=FindingStatus.REQUIRES_REVIEW,
        summary=data.summary.strip(),
        indicators_json=[{"type": "Evidence", "value": evidence.evidence_code}] if evidence else [],
        event_count=1,
        first_seen_at=now,
        last_seen_at=now,
        reviewer_notes=data.reviewer_notes,
    )
    try:
        db.add(finding)
        db.add(
            AuditLog(
                case_id=case.id,
                action="FINDING_CREATED",
                actor=actor,
                changes_json={"findingTitle": {"old": None, "new": finding.title}},
            )
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise

    loaded = db.scalar(
        select(ForensicFinding)
        .options(selectinload(ForensicFinding.case), selectinload(ForensicFinding.evidence))
        .where(ForensicFinding.id == finding.id)
    )
    assert loaded is not None
    return loaded


def review_finding(
    db: Session,
    finding: ForensicFinding,
    data: FindingReviewUpdate,
    *,
    actor: str = SYSTEM_ACTOR,
) -> ForensicFinding:
    old_status = finding.status.value
    finding.status = data.status
    finding.reviewer_notes = data.reviewer_notes
    finding.updated_at = datetime.now(timezone.utc)
    try:
        db.add(
            AuditLog(
                case_id=finding.case_id,
                action="FINDING_REVIEWED",
                actor=actor,
                changes_json={
                    "findingTitle": {"old": None, "new": finding.title},
                    "status": {"old": old_status, "new": data.status.value},
                },
            )
        )
        db.commit()
        db.refresh(finding)
    except SQLAlchemyError:
        db.rollback()
        raise
    return finding


def aggregate_iocs(
    db: Session,
    *,
    organization_id: int | None = None,
    case_ref: str | None = None,
) -> list[ExtractedIocItem]:
    events = list_forensic_events(db, organization_id=organization_id, case_ref=case_ref, limit=2000)
    counter: Counter[tuple[str, str]] = Counter()
    for ev in events:
        for item in ev.extracted_iocs_json or []:
            if isinstance(item, dict) and item.get("type") and item.get("value"):
                counter[(str(item["type"]), str(item["value"]))] += 1
    return [
        ExtractedIocItem(type=kind, value=val, count=cnt)
        for (kind, val), cnt in counter.most_common(150)
    ]


def build_unified_timeline(
    db: Session,
    *,
    organization_id: int | None = None,
    case_ref: str | None = None,
    limit: int = 150,
) -> list[TimelineEntryResponse]:
    entries: list[TimelineEntryResponse] = []
    target_case = get_case_by_id(db, case_ref, organization_id=organization_id) if case_ref else None
    if case_ref and target_case is None:
        return []

    ev_stmt = (
        select(ForensicEvent)
        .join(Case, ForensicEvent.case_id == Case.id)
        .options(selectinload(ForensicEvent.case), selectinload(ForensicEvent.evidence))
        .where(Case.is_deleted.is_(False))
    )
    if organization_id is not None:
        ev_stmt = ev_stmt.where(Case.organization_id == organization_id)
    if target_case:
        ev_stmt = ev_stmt.where(ForensicEvent.case_id == target_case.id)
    for ev in db.scalars(ev_stmt.order_by(ForensicEvent.occurred_at.desc()).limit(limit)).all():
        entries.append(
            TimelineEntryResponse(
                id=f"event-{ev.id}",
                occurred_at=ev.occurred_at,
                source_kind="LOG_EVENT",
                record_type="Recorded fact",
                event_type=ev.event_type,
                title=ev.action or ev.category,
                description=ev.description,
                case_number=ev.case.case_number,
                source_ref=ev.evidence.original_filename if ev.evidence else "Log evidence",
                status=ev.category,
            )
        )

    find_stmt = (
        select(ForensicFinding)
        .join(Case, ForensicFinding.case_id == Case.id)
        .options(selectinload(ForensicFinding.case), selectinload(ForensicFinding.evidence))
        .where(Case.is_deleted.is_(False))
    )
    if organization_id is not None:
        find_stmt = find_stmt.where(Case.organization_id == organization_id)
    if target_case:
        find_stmt = find_stmt.where(ForensicFinding.case_id == target_case.id)
    for finding in db.scalars(find_stmt.order_by(ForensicFinding.created_at.desc()).limit(limit)).all():
        entries.append(
            TimelineEntryResponse(
                id=f"finding-{finding.id}",
                occurred_at=finding.last_seen_at or finding.created_at,
                source_kind="FINDING",
                record_type="Analytical finding",
                event_type="Detection Rule",
                title=finding.title,
                description=finding.summary,
                case_number=finding.case.case_number,
                source_ref=finding.evidence.evidence_code if finding.evidence else finding.rule_id,
                severity=finding.severity.value,
                status=finding.status.value,
            )
        )

    audit_stmt = (
        select(AuditLog, Case.case_number)
        .join(Case, AuditLog.case_id == Case.id)
        .where(Case.is_deleted.is_(False))
    )
    if organization_id is not None:
        audit_stmt = audit_stmt.where(Case.organization_id == organization_id)
    if target_case:
        audit_stmt = audit_stmt.where(AuditLog.case_id == target_case.id)
    for audit, cnum in db.execute(audit_stmt.order_by(AuditLog.created_at.desc()).limit(limit)).all():
        entries.append(
            TimelineEntryResponse(
                id=f"audit-{audit.id}",
                occurred_at=audit.created_at,
                source_kind="AUDIT",
                record_type="Recorded fact",
                event_type="Investigation update",
                title=audit.action.replace("_", " ").title(),
                description=f"Actor: {audit.actor} — {', '.join((audit.changes_json or {}).keys()) or 'case record updated'}",
                case_number=cnum,
                source_ref="Case Audit Log",
                status="Recorded",
            )
        )

    entries.sort(key=lambda item: item.occurred_at, reverse=True)
    return entries[:limit]
