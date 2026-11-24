from collections.abc import Generator
from pathlib import Path
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.security import _totp_at, auth_rate_limiter
from app.db.base import Base
from app.db.session import get_db
from app.main import app


@pytest.fixture
def raw_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
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
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()
    get_settings.cache_clear()


def _register(client: TestClient, email: str, org_name: str, password: str = "SecurePass123!") -> dict:
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "fullName": email.split("@")[0].title(), "password": password, "organizationName": org_name},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_unauthenticated_and_invalid_tokens_rejected(raw_client: TestClient) -> None:
    for path in (
        "/api/v1/cases",
        "/api/v1/dashboard/overview",
        "/api/v1/evidence",
        "/api/v1/analysis/findings",
        "/api/v1/analysis/correlations",
        "/api/v1/footprint",
        "/api/v1/investigators",
        "/api/v1/audit-logs",
    ):
        assert raw_client.get(path).status_code == 401
        assert raw_client.get(path, headers={"Authorization": "Bearer forged-invalid-token"}).status_code == 401


def test_cross_organization_isolation_and_rbac_enforcement(raw_client: TestClient) -> None:
    # Org A admin creates a case
    org_a = _register(raw_client, "admin@orga.test", "Organization Alpha")
    headers_a = {"Authorization": f"Bearer {org_a['accessToken']}"}

    # Ensure password hash & MFA secret are never exposed in responses
    assert "passwordHash" not in org_a["user"]
    assert "mfaSecret" not in org_a["user"]

    case_a = raw_client.post("/api/v1/cases", json={"title": "Alpha Confidential Case"}, headers=headers_a).json()

    # Org A adds a READ_ONLY_AUDITOR
    auditor_add = raw_client.post(
        "/api/v1/investigators",
        json={
            "email": "auditor@orga.test",
            "fullName": "Read Only Auditor",
            "password": "AuditorPassword123!",
            "role": "READ_ONLY_AUDITOR",
        },
        headers=headers_a,
    )
    assert auditor_add.status_code == 201, auditor_add.text

    auditor_login = raw_client.post(
        "/api/v1/auth/login",
        json={"email": "auditor@orga.test", "password": "AuditorPassword123!"},
    )
    assert auditor_login.status_code == 200
    headers_auditor = {"Authorization": f"Bearer {auditor_login.json()['accessToken']}"}

    # Read-only auditor CAN read cases, but CANNOT create/edit/delete cases or upload evidence
    assert raw_client.get("/api/v1/cases", headers=headers_auditor).json()["total"] == 1
    assert raw_client.post("/api/v1/cases", json={"title": "Blocked"}, headers=headers_auditor).status_code == 403
    assert raw_client.patch(f"/api/v1/cases/{case_a['caseNumber']}", json={"status": "CLOSED"}, headers=headers_auditor).status_code == 403
    assert raw_client.delete(f"/api/v1/cases/{case_a['caseNumber']}", headers=headers_auditor).status_code == 403
    assert raw_client.post(
        "/api/v1/evidence/upload",
        data={"caseId": case_a["caseNumber"]},
        files={"file": ("test.log", b"hello", "text/plain")},
        headers=headers_auditor,
    ).status_code == 403

    # Org B admin cannot see or touch Org A's cases
    org_b = _register(raw_client, "admin@orgb.test", "Organization Beta")
    headers_b = {"Authorization": f"Bearer {org_b['accessToken']}"}

    assert raw_client.get("/api/v1/cases", headers=headers_b).json()["total"] == 0
    assert raw_client.get(f"/api/v1/cases/{case_a['caseNumber']}", headers=headers_b).status_code == 404
    assert raw_client.patch(f"/api/v1/cases/{case_a['caseNumber']}", json={"title": "Hijack"}, headers=headers_b).status_code == 404


def test_password_recovery_mfa_logout_and_audit_logs(raw_client: TestClient) -> None:
    reg = _register(raw_client, "analyst@lab.test", "Cyber Lab")
    headers = {"Authorization": f"Bearer {reg['accessToken']}"}

    # Setup & enable TOTP MFA
    setup = raw_client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    valid_code = _totp_at(secret, int(time.time() // 30))
    enable = raw_client.post("/api/v1/auth/mfa/enable", json={"code": valid_code}, headers=headers)
    assert enable.status_code == 200 and enable.json()["mfaEnabled"] is True

    # Login without MFA code must fail; with valid code must succeed
    assert raw_client.post("/api/v1/auth/login", json={"email": "analyst@lab.test", "password": "SecurePass123!"}).status_code == 401
    ok_login = raw_client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@lab.test", "password": "SecurePass123!", "totpCode": valid_code},
    )
    assert ok_login.status_code == 200

    # Logout revokes session
    token2 = ok_login.json()["accessToken"]
    assert raw_client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token2}"}).status_code == 204
    assert raw_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token2}"}).status_code == 401

    # Password recovery flow
    rec = raw_client.post("/api/v1/auth/password-recovery/request", json={"email": "analyst@lab.test"})
    assert rec.status_code == 200
    recovery_token = rec.json()["localRecoveryToken"]
    confirm = raw_client.post(
        "/api/v1/auth/password-recovery/confirm",
        json={"token": recovery_token, "newPassword": "NewStrongPassword456!"},
    )
    assert confirm.status_code == 200

    # Login with new password + MFA works
    rel = raw_client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@lab.test", "password": "NewStrongPassword456!", "totpCode": valid_code},
    )
    assert rel.status_code == 200
    new_headers = {"Authorization": f"Bearer {rel.json()['accessToken']}"}

    # Audit logs recorded auth events
    audits = raw_client.get("/api/v1/audit-logs", headers=new_headers).json()
    actions = {a["action"] for a in audits}
    assert "AUTH_REGISTER" in actions
    assert "AUTH_MFA_ENABLED" in actions
    assert "AUTH_LOGIN" in actions


def test_case_notes_evidence_download_correlation_manual_finding_and_ai_assistant(raw_client: TestClient) -> None:
    reg = _register(raw_client, "lead@forensics.test", "Forensics Unit")
    headers = {"Authorization": f"Bearer {reg['accessToken']}"}

    case = raw_client.post("/api/v1/cases", json={"title": "Correlation & AI Test"}, headers=headers).json()
    cnum = case["caseNumber"]

    # Case notes
    note = raw_client.post(f"/api/v1/cases/{cnum}/notes", json={"content": "Initial triage note."}, headers=headers)
    assert note.status_code == 201
    assert len(raw_client.get(f"/api/v1/cases/{cnum}/notes", headers=headers).json()) == 1

    # Upload log & download securely with nosniff header
    sample_log = (
        "2026-11-24T10:00:01Z sshd[1]: Failed password for root from 203.0.113.55 port 22 ssh2\n"
        "2026-11-24T10:00:02Z sshd[2]: Failed password for root from 203.0.113.55 port 22 ssh2\n"
        "2026-11-24T10:00:03Z sshd[3]: Accepted password for root from 203.0.113.55 port 22 ssh2\n"
        "2026-11-24T10:00:10Z sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/id\n"
    )
    ev = raw_client.post(
        "/api/v1/evidence/upload",
        data={"caseId": cnum, "evidenceType": "LOG_FILE"},
        files={"file": ("corr.log", sample_log.encode(), "text/plain")},
        headers=headers,
    ).json()
    dl = raw_client.get(f"/api/v1/evidence/{ev['evidenceCode']}/download", headers=headers)
    assert dl.status_code == 200
    assert dl.headers["x-content-type-options"] == "nosniff"
    assert b"203.0.113.55" in dl.content

    # Analyze & correlate events
    assert raw_client.post(f"/api/v1/analysis/evidence/{ev['evidenceCode']}/analyze", headers=headers).status_code == 200
    corr = raw_client.get("/api/v1/analysis/correlations", params={"caseId": cnum}, headers=headers).json()
    assert corr["total"] >= 2
    assert any(c["correlationType"] == "SHARED_SOURCE_IP" for c in corr["items"])

    # Manual finding linked to evidence
    manual = raw_client.post(
        "/api/v1/analysis/findings",
        json={
            "caseId": cnum,
            "evidenceId": ev["evidenceCode"],
            "title": "Root login followed by sudo command",
            "severity": "HIGH",
            "confidence": "HIGH",
            "summary": "Correlated SSH acceptance and subsequent sudo command from the same host.",
        },
        headers=headers,
    )
    assert manual.status_code == 201

    # Evidence-backed AI Investigation Assistant
    ai = raw_client.post(
        "/api/v1/analysis/ai/assist",
        json={"caseId": cnum, "question": "What are the main evidence gaps?"},
        headers=headers,
    )
    assert ai.status_code == 200
    ai_data = ai.json()
    assert ai_data["externalDataTransmitted"] is False
    assert "Requires Investigator Review" in ai_data["disclaimer"]
    assert ev["evidenceCode"] in ai_data["citations"]
