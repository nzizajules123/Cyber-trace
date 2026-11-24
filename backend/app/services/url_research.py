import hashlib
import ipaddress
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse
from uuid import uuid4

import certifi
import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.models.analysis import FindingConfidence, FindingStatus, ForensicFinding
from app.models.audit import AuditLog
from app.models.case import CaseSeverity
from app.models.evidence import (
    CustodyAction,
    EvidenceItem,
    EvidenceStatus,
    EvidenceType,
    EvidenceVerification,
)
from app.models.footprint import UrlInvestigation
from app.schemas.footprint import UrlInvestigationResponse, UrlResearchRequest
from app.services.cases import SYSTEM_ACTOR, get_case_by_id
from app.services.evidence import _sanitize_filename, _vault_root, append_custody_event
from app.services.log_analyzer import extract_iocs

SECURITY_HEADER_NAMES = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

MAX_HTML_BYTES = 1_500_000  # 1.5 MB cap for HTML parsing
MAX_REDIRECTS = 5


class _ForensicHtmlParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self._in_title = False
        self.title_parts: list[str] = []
        self.meta_description: str | None = None
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "title":
            self._in_title = True
        elif t == "meta" and attr_map.get("name", "").lower() == "description":
            if attr_map.get("content") and not self.meta_description:
                self.meta_description = attr_map["content"].strip()[:400]
        elif t == "a" and attr_map.get("href"):
            href = attr_map["href"].strip()
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(urljoin(self.base_url, href))
        elif t == "script" and attr_map.get("src"):
            self.scripts.append(urljoin(self.base_url, attr_map["src"].strip()))
        elif t == "form":
            action = urljoin(self.base_url, attr_map.get("action", "").strip())
            self._current_form = {
                "action": action,
                "method": (attr_map.get("method") or "GET").upper(),
                "hasPasswordField": False,
            }
            self.forms.append(self._current_form)
        elif t == "input" and self._current_form is not None:
            if attr_map.get("type", "").lower() == "password":
                self._current_form["hasPasswordField"] = True

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self._in_title = False
        elif t == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def normalize_and_validate_url(raw_url: str) -> tuple[str, str, int | None]:
    candidate = raw_url.strip()
    if not re.match(r"^https?://", candidate, re.IGNORECASE):
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Only http:// and https:// URLs are supported for forensic research.",
        )
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname or "." not in hostname and hostname != "localhost":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Please provide a valid public website domain or URL.",
        )
    return candidate, hostname, parsed.port


def _is_forbidden_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def resolve_and_guard_dns(hostname: str) -> dict[str, Any]:
    if hostname in ("localhost", "127.0.0.1", "::1") or hostname.endswith(".local"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Private or loopback hosts cannot be researched (SSRF protection).",
        )
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"DNS resolution failed for '{hostname}': {err}",
        ) from err

    ipv4s: list[str] = []
    ipv6s: list[str] = []
    for family, _, _, _, sockaddr in infos:
        ip_str = sockaddr[0]
        if _is_forbidden_ip(ip_str):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Blocked target '{hostname}': resolves to a non-public/internal IP address ({ip_str}).",
            )
        if family == socket.AF_INET and ip_str not in ipv4s:
            ipv4s.append(ip_str)
        elif family == socket.AF_INET6 and ip_str not in ipv6s:
            ipv6s.append(ip_str)

    reverse_dns: dict[str, str] = {}
    for ip_str in ipv4s[:3]:
        try:
            ptr, _, _ = socket.gethostbyaddr(ip_str)
            reverse_dns[ip_str] = ptr
        except OSError:
            pass

    return {
        "hostname": hostname,
        "ipv4": ipv4s,
        "ipv6": ipv6s,
        "reverseDns": reverse_dns,
    }


def inspect_tls_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
    except ssl.SSLCertVerificationError as err:
        return {"available": True, "valid": False, "error": f"Certificate verification failed: {err.verify_message}"}
    except OSError as err:
        return {"available": False, "valid": False, "error": str(err)}

    subject = dict(item[0] for item in cert.get("subject", ()))
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    sans = [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    days_remaining: int | None = None
    expired = False
    if not_after:
        try:
            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (exp_dt - datetime.now(timezone.utc)).days
            expired = days_remaining < 0
        except ValueError:
            pass

    return {
        "available": True,
        "valid": not expired,
        "expired": expired,
        "subjectCn": subject.get("commonName"),
        "issuerOrg": issuer.get("organizationName"),
        "issuerCn": issuer.get("commonName"),
        "notBefore": not_before,
        "notAfter": not_after,
        "daysRemaining": days_remaining,
        "sans": sans[:20],
        "tlsVersion": tls_version,
        "cipher": cipher[0] if cipher else None,
    }


def fetch_url_safely(start_url: str) -> dict[str, Any]:
    redirect_chain: list[dict[str, Any]] = []
    current_url = start_url
    start_ts = time.perf_counter()

    with httpx.Client(
        timeout=httpx.Timeout(10.0, connect=6.0),
        follow_redirects=False,
        headers={
            "User-Agent": "CyberTrace-ForensicResearch/1.0 (+defensive-investigation)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    ) as client:
        response: httpx.Response | None = None
        for _ in range(MAX_REDIRECTS + 1):
            parsed = urlparse(current_url)
            if parsed.hostname:
                resolve_and_guard_dns(parsed.hostname.lower())
            try:
                response = client.get(current_url)
            except httpx.HTTPError as err:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Unable to fetch target URL: {err}",
                ) from err

            if response.is_redirect and response.headers.get("location"):
                next_url = urljoin(current_url, response.headers["location"])
                redirect_chain.append(
                    {"url": current_url, "statusCode": response.status_code, "location": next_url}
                )
                current_url = next_url
                continue
            break

    elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
    assert response is not None
    raw_body = response.content[:MAX_HTML_BYTES]
    body_text = raw_body.decode(response.encoding or "utf-8", errors="replace")
    snapshot_sha256 = hashlib.sha256(raw_body).hexdigest()

    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    security_headers = {
        name: {"present": name in headers_lower, "value": headers_lower.get(name)}
        for name in SECURITY_HEADER_NAMES
    }

    return {
        "finalUrl": str(response.url),
        "statusCode": response.status_code,
        "elapsedMs": elapsed_ms,
        "contentType": headers_lower.get("content-type", ""),
        "server": headers_lower.get("server"),
        "poweredBy": headers_lower.get("x-powered-by"),
        "redirectChain": redirect_chain,
        "securityHeaders": security_headers,
        "snapshotSha256": snapshot_sha256,
        "bodyText": body_text,
        "bodySize": len(raw_body),
    }


def _evaluate_risk_and_findings(
    *,
    case_id: int,
    target_url: str,
    final_url: str,
    domain: str,
    tls_info: dict[str, Any],
    security_headers: dict[str, Any],
    artifacts: dict[str, Any],
) -> tuple[int, str, list[ForensicFinding]]:
    score = 0
    findings: list[ForensicFinding] = []
    now = datetime.now(timezone.utc)

    final_parsed = urlparse(final_url)
    final_domain = (final_parsed.hostname or domain).lower()

    # 1. Unencrypted HTTP
    if final_parsed.scheme.lower() != "https":
        score += 25
        findings.append(
            ForensicFinding(
                case_id=case_id,
                rule_id="RULE_URL_NO_HTTPS",
                title=f"Unencrypted HTTP endpoint: {final_domain}",
                severity=CaseSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                status=FindingStatus.REQUIRES_REVIEW,
                summary=f"Target {target_url} resolved to unencrypted HTTP ({final_url}) without HTTPS enforcement.",
                indicators_json=[{"type": "URL", "value": final_url}],
                event_count=1,
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    # 2. Invalid or expired TLS certificate
    if tls_info.get("available") and not tls_info.get("valid"):
        score += 35
        findings.append(
            ForensicFinding(
                case_id=case_id,
                rule_id="RULE_URL_INVALID_TLS",
                title=f"Invalid or expired TLS certificate on {domain}",
                severity=CaseSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                status=FindingStatus.REQUIRES_REVIEW,
                summary=f"TLS inspection for {domain} reported an invalid certificate: {tls_info.get('error') or 'expired'}.",
                indicators_json=[{"type": "Domain", "value": domain}],
                event_count=1,
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    # 3. Punycode / IDN homograph or raw IP literal URL
    is_ip_literal = False
    try:
        ipaddress.ip_address(final_domain)
        is_ip_literal = True
    except ValueError:
        pass
    if "xn--" in final_domain or is_ip_literal:
        score += 30
        findings.append(
            ForensicFinding(
                case_id=case_id,
                rule_id="RULE_URL_SUSPICIOUS_HOST",
                title=f"Suspicious host pattern on {final_domain}",
                severity=CaseSeverity.HIGH,
                confidence=FindingConfidence.MEDIUM,
                status=FindingStatus.REQUIRES_REVIEW,
                summary=(
                    f"Target uses a raw IP literal ({final_domain}) instead of a registered domain."
                    if is_ip_literal
                    else f"Target domain ({final_domain}) uses Punycode (IDN), which is frequently abused in homograph phishing."
                ),
                indicators_json=[{"type": "URL", "value": final_url}],
                event_count=1,
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    # 4. Cross-domain form submission (credential harvesting indicator)
    cross_domain_forms = [
        f for f in artifacts.get("forms", []) if f.get("crossDomain")
    ]
    if cross_domain_forms:
        has_pw = any(f.get("hasPasswordField") for f in cross_domain_forms)
        score += 40 if has_pw else 20
        findings.append(
            ForensicFinding(
                case_id=case_id,
                rule_id="RULE_URL_CROSS_DOMAIN_FORM",
                title=f"Cross-domain form submission detected on {final_domain}",
                severity=CaseSeverity.CRITICAL if has_pw else CaseSeverity.HIGH,
                confidence=FindingConfidence.HIGH if has_pw else FindingConfidence.MEDIUM,
                status=FindingStatus.REQUIRES_REVIEW,
                summary=(
                    f"Found {len(cross_domain_forms)} HTML form(s) submitting data to an external domain"
                    + (" including a password input field (strong phishing indicator)." if has_pw else ".")
                ),
                indicators_json=[
                    {"type": "URL", "value": f["action"]} for f in cross_domain_forms[:5]
                ],
                event_count=len(cross_domain_forms),
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    # 5. Missing security headers
    missing_headers = [name for name, info in security_headers.items() if not info.get("present")]
    if len(missing_headers) >= 4:
        score += 15
        findings.append(
            ForensicFinding(
                case_id=case_id,
                rule_id="RULE_URL_WEAK_HEADERS",
                title=f"Missing {len(missing_headers)} of {len(SECURITY_HEADER_NAMES)} HTTP security headers on {final_domain}",
                severity=CaseSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                status=FindingStatus.REQUIRES_REVIEW,
                summary=f"Response from {final_url} is missing: {', '.join(missing_headers)}.",
                indicators_json=[{"type": "URL", "value": final_url}],
                event_count=1,
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    score = min(100, score)
    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level, findings


def serialize_url_investigation(record: UrlInvestigation) -> UrlInvestigationResponse:
    return UrlInvestigationResponse(
        id=record.id,
        investigation_code=record.investigation_code,
        case_id=record.case_id,
        case_number=record.case.case_number if record.case else None,
        target_url=record.target_url,
        final_url=record.final_url,
        domain=record.domain,
        submitted_by=record.submitted_by,
        status=record.status,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        http_status=record.http_status,
        page_title=record.page_title,
        snapshot_sha256=record.snapshot_sha256,
        evidence_code=record.evidence_code,
        findings_count=record.findings_count,
        dns_info=record.dns_info_json or {},
        tls_info=record.tls_info_json or {},
        http_info=record.http_info_json or {},
        security_headers=record.security_headers_json or {},
        artifacts=record.artifacts_json or {},
        notes=record.notes,
        created_at=record.created_at,
    )


def run_url_research(
    db: Session,
    request: UrlResearchRequest,
    *,
    organization_id: int | None = None,
    actor: str = SYSTEM_ACTOR,
) -> UrlInvestigationResponse:
    case = get_case_by_id(db, request.case_id, organization_id=organization_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked case not found.")

    target_url, hostname, port = normalize_and_validate_url(request.url)
    dns_info = resolve_and_guard_dns(hostname)
    tls_info = inspect_tls_certificate(hostname, port=port or 443)
    http_result = fetch_url_safely(target_url)

    final_url = http_result["finalUrl"]
    final_domain = (urlparse(final_url).hostname or hostname).lower()

    parser = _ForensicHtmlParser(final_url)
    if "html" in http_result["contentType"].lower() or "<html" in http_result["bodyText"][:500].lower():
        try:
            parser.feed(http_result["bodyText"])
        except Exception:
            pass

    page_title = " ".join("".join(parser.title_parts).split())[:300] or None
    outbound_domains = sorted(
        {
            (urlparse(link).hostname or "").lower()
            for link in parser.links
            if (urlparse(link).hostname or "").lower() not in ("", final_domain)
        }
    )[:30]
    external_scripts = sorted(
        {
            src
            for src in parser.scripts
            if (urlparse(src).hostname or "").lower() not in ("", final_domain)
        }
    )[:20]

    forms_enriched = []
    for form in parser.forms[:15]:
        action_host = (urlparse(form["action"]).hostname or final_domain).lower()
        forms_enriched.append(
            {
                **form,
                "actionHost": action_host,
                "crossDomain": bool(action_host and action_host != final_domain),
            }
        )

    iocs = extract_iocs(http_result["bodyText"][:200_000])[:40]
    artifacts = {
        "metaDescription": parser.meta_description,
        "linkCount": len(parser.links),
        "outboundDomains": outbound_domains,
        "externalScripts": external_scripts,
        "forms": forms_enriched,
        "extractedIocs": iocs,
    }

    risk_score, risk_level, new_findings = _evaluate_risk_and_findings(
        case_id=case.id,
        target_url=target_url,
        final_url=final_url,
        domain=hostname,
        tls_info=tls_info,
        security_headers=http_result["securityHeaders"],
        artifacts=artifacts,
    )

    now = datetime.now(timezone.utc)
    inv_code = f"FP-{now.year}-{uuid4().hex[:8].upper()}"
    submitter = (request.submitted_by or "").strip() or actor or case.reporter_name or SYSTEM_ACTOR
    actor = submitter

    http_info = {
        "statusCode": http_result["statusCode"],
        "elapsedMs": http_result["elapsedMs"],
        "contentType": http_result["contentType"],
        "server": http_result["server"],
        "poweredBy": http_result["poweredBy"],
        "bodySize": http_result["bodySize"],
        "redirectChain": http_result["redirectChain"],
    }

    evidence_code: str | None = None
    target_path = None
    try:
        if request.seal_as_evidence:
            evidence_code = f"EV-{now.year}-{uuid4().hex[:8].upper()}"
            dossier = {
                "investigationCode": inv_code,
                "caseNumber": case.case_number,
                "targetUrl": target_url,
                "finalUrl": final_url,
                "domain": hostname,
                "riskScore": risk_score,
                "riskLevel": risk_level,
                "snapshotSha256": http_result["snapshotSha256"],
                "dnsInfo": dns_info,
                "tlsInfo": tls_info,
                "httpInfo": http_info,
                "securityHeaders": http_result["securityHeaders"],
                "artifacts": artifacts,
                "capturedAt": now.isoformat(),
            }
            dossier_bytes = json.dumps(dossier, indent=2).encode("utf-8")
            sha256_hex = hashlib.sha256(dossier_bytes).hexdigest()
            sha512_hex = hashlib.sha512(dossier_bytes).hexdigest()
            md5_hex = hashlib.md5(dossier_bytes).hexdigest()

            safe_domain = _sanitize_filename(hostname)
            case_dir = _vault_root() / case.case_number
            case_dir.mkdir(parents=True, exist_ok=True)
            filename = f"url_research_{safe_domain}.json"
            target_path = case_dir / f"{evidence_code}_{filename}"
            target_path.write_bytes(dossier_bytes)

            ev_item = EvidenceItem(
                evidence_code=evidence_code,
                case_id=case.id,
                original_filename=filename,
                stored_path=str(target_path),
                mime_type="application/json",
                file_size=len(dossier_bytes),
                sha256=sha256_hex,
                sha512=sha512_hex,
                md5=md5_hex,
                evidence_type=EvidenceType.DOCUMENT,
                status=EvidenceStatus.ANALYZED,
                acquisition_source=final_url[:200],
                collected_by=actor,
                description=f"Automated digital footprint dossier for {target_url} (risk: {risk_level}, score: {risk_score}/100).",
                is_deleted=False,
                created_at=now,
                updated_at=now,
            )
            db.add(ev_item)
            db.flush()

            db.add(
                EvidenceVerification(
                    evidence_id=ev_item.id,
                    algorithm="SHA-256",
                    expected_hash=sha256_hex,
                    computed_hash=sha256_hex,
                    comparison_performed=True,
                    sha256_matches=True,
                    verified_by=actor,
                    notes="Initial cryptographic digest sealed during automated URL research.",
                    verified_at=now,
                )
            )
            append_custody_event(
                db,
                ev_item,
                action=CustodyAction.COLLECTED,
                actor=actor,
                to_custodian=actor,
                location="CyberTrace Digital Footprint Engine",
                notes=f"Captured & sealed URL research for {final_url}.",
            )
            for finding in new_findings:
                finding.evidence_id = ev_item.id

        for finding in new_findings:
            db.add(finding)

        record = UrlInvestigation(
            investigation_code=inv_code,
            case_id=case.id,
            target_url=target_url,
            final_url=final_url,
            domain=hostname,
            submitted_by=actor,
            status="COMPLETED",
            risk_score=risk_score,
            risk_level=risk_level,
            http_status=http_result["statusCode"],
            page_title=page_title,
            snapshot_sha256=http_result["snapshotSha256"],
            evidence_code=evidence_code,
            findings_count=len(new_findings),
            dns_info_json=dns_info,
            tls_info_json=tls_info,
            http_info_json=http_info,
            security_headers_json=http_result["securityHeaders"],
            artifacts_json=artifacts,
            notes=request.notes,
            created_at=now,
        )
        db.add(record)
        db.add(
            AuditLog(
                case_id=case.id,
                action="URL_RESEARCH_COMPLETED",
                actor=actor,
                changes_json={
                    "investigationCode": {"old": None, "new": inv_code},
                    "targetUrl": {"old": None, "new": target_url},
                    "riskLevel": {"old": None, "new": risk_level},
                    "riskScore": {"old": None, "new": risk_score},
                },
            )
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        if target_path is not None and target_path.exists():
            target_path.unlink(missing_ok=True)
        raise

    loaded = db.scalar(
        select(UrlInvestigation)
        .options(selectinload(UrlInvestigation.case))
        .where(UrlInvestigation.id == record.id)
    )
    assert loaded is not None
    return serialize_url_investigation(loaded)


def list_url_investigations(
    db: Session,
    *,
    organization_id: int | None = None,
    case_ref: str | None = None,
) -> list[UrlInvestigationResponse]:
    from app.models.case import Case

    stmt = (
        select(UrlInvestigation)
        .join(Case, UrlInvestigation.case_id == Case.id)
        .options(selectinload(UrlInvestigation.case))
        .where(Case.is_deleted.is_(False))
    )
    if organization_id is not None:
        stmt = stmt.where(Case.organization_id == organization_id)
    if case_ref:
        case = get_case_by_id(db, case_ref, organization_id=organization_id)
        if case is None:
            return []
        stmt = stmt.where(UrlInvestigation.case_id == case.id)
    rows = db.scalars(stmt.order_by(UrlInvestigation.created_at.desc(), UrlInvestigation.id.desc())).all()
    return [serialize_url_investigation(row) for row in rows]
