from collections.abc import Generator

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import auth_rate_limiter
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.case import Case


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
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
                "email": "lead@cybertrace.test",
                "fullName": "Lead Investigator",
                "password": "StrongPassword123!",
                "organizationName": "Test Forensics Lab",
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


def create_case(client: TestClient, **values: object) -> dict:
    response = client.post(
        "/api/v1/cases",
        json={"title": "Authentication log review", **values},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_case_lifecycle_records_audit_history(client: TestClient) -> None:
    created = create_case(
        client,
        description="Review authorized source records.",
        assignedTo="Investigator A",
        reporterName="Case reporter",
        severity="CRITICAL",
    )
    assert created["caseNumber"].startswith("CT-")
    assert created["title"] == "Authentication log review"
    assert created["status"] == "OPEN"
    assert created["severity"] == "CRITICAL"
    assert created["assignedTo"] == "Investigator A"
    assert created["reporterName"] == "Case reporter"

    edited = client.patch(
        f"/api/v1/cases/{created['id']}",
        json={"title": "Identity provider review", "status": "RESOLVED"},
    )
    assert edited.status_code == 200
    assert edited.json()["title"] == "Identity provider review"
    assert edited.json()["status"] == "RESOLVED"

    detail = client.get(f"/api/v1/cases/{created['caseNumber']}")
    assert detail.status_code == 200
    assert [entry["action"] for entry in detail.json()["auditHistory"]] == [
        "CASE_CREATED",
        "CASE_STATUS_CHANGED",
    ]
    assert detail.json()["auditHistory"][-1]["changesJson"]["status"] == {
        "old": "OPEN",
        "new": "RESOLVED",
    }


def test_case_list_filters_search_and_paginates(client: TestClient) -> None:
    create_case(client, title="Authentication review", status="OPEN", severity="CRITICAL")
    create_case(client, title="Endpoint review", status="IN_PROGRESS", severity="HIGH")
    create_case(client, title="Resolved access review", status="RESOLVED", severity="LOW")

    response = client.get(
        "/api/v1/cases",
        params={"q": "authentication", "status": "OPEN", "severity": "CRITICAL"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["page"] == 1
    assert response.json()["size"] == 50
    assert len(response.json()["items"]) == 1

    paginated = client.get("/api/v1/cases", params={"page": 2, "size": 1})
    assert paginated.json()["total"] == 3
    assert paginated.json()["page"] == 2
    assert paginated.json()["size"] == 1
    assert len(paginated.json()["items"]) == 1

    legacy_pagination = client.get("/api/v1/cases", params={"skip": 1, "limit": 1})
    assert legacy_pagination.json()["page"] == 2
    assert legacy_pagination.json()["size"] == 1


def test_case_metrics_and_soft_delete(client: TestClient) -> None:
    critical_open = create_case(client, severity="CRITICAL")
    create_case(client, title="Resolved case", status="RESOLVED", severity="LOW")

    metrics = client.get("/api/v1/cases/metrics")
    assert metrics.status_code == 200
    assert metrics.json() == {
        "totalCases": 2,
        "openCases": 1,
        "criticalCases": 1,
        "resolvedCases": 1,
    }

    deleted = client.delete(f"/api/v1/cases/{critical_open['id']}")
    assert deleted.status_code == 204
    assert client.get("/api/v1/cases").json()["total"] == 1
    assert client.get(f"/api/v1/cases/{critical_open['id']}").status_code == 404

    metrics_after_delete = client.get("/api/v1/cases/metrics").json()
    assert metrics_after_delete["totalCases"] == 1
    assert metrics_after_delete["criticalCases"] == 0


def test_mutation_and_audit_entry_share_transaction(client: TestClient) -> None:
    case = create_case(client)
    audit_detail = client.get(f"/api/v1/cases/{case['id']}").json()
    assert len(audit_detail["auditHistory"]) == 1

    response = client.patch(
        f"/api/v1/cases/{case['id']}",
        json={"severity": "HIGH", "assignedTo": "Investigator B"},
    )
    assert response.status_code == 200
    assert len(response.json()["auditHistory"]) == 2


def test_validation_errors_use_standard_envelope(client: TestClient) -> None:
    response = client.post("/api/v1/cases", json={"title": " ", "unknownField": True})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert response.json()["error"]["details"]
    assert client.post("/api/v1/cases", json={"title": 123}).status_code == 422


def test_empty_case_list_is_successful_and_not_a_mock(client: TestClient) -> None:
    response = client.get("/api/v1/cases")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "page": 1, "size": 50}


def test_soft_deleted_records_are_hidden_but_audit_is_retained(client: TestClient) -> None:
    case = create_case(client)
    response = client.delete(f"/api/v1/cases/{case['id']}")
    assert response.status_code == 204

    with app.state.test_session_factory() as session:
        audit_records = session.scalars(select(AuditLog).where(AuditLog.case_id == case["id"])).all()
        stored_case = session.get(Case, case["id"])
        assert stored_case.is_deleted is True
        assert [record.action for record in audit_records] == ["CASE_CREATED", "CASE_DELETED"]


def test_unconfigured_database_returns_service_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.db.session.get_session_factory", lambda: None)

    with pytest.raises(HTTPException) as error:
        next(get_db())

    assert error.value.status_code == 503


def test_readiness_endpoint_checks_database_connection(client: TestClient) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "connected"}


def test_audit_failure_rolls_back_case_creation(client: TestClient) -> None:
    def reject_audit_insert(mapper: object, connection: object, target: AuditLog) -> None:
        raise IntegrityError("audit insert", {}, RuntimeError("simulated failure"))

    event.listen(AuditLog, "before_insert", reject_audit_insert)
    try:
        response = client.post("/api/v1/cases", json={"title": "Atomic create test"})
    finally:
        event.remove(AuditLog, "before_insert", reject_audit_insert)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "database_conflict"
    assert client.get("/api/v1/cases").json()["total"] == 0


def test_update_audit_changes_use_camel_case_keys(client: TestClient) -> None:
    case = create_case(client, assignedTo="Investigator A")
    response = client.patch(
        f"/api/v1/cases/{case['caseNumber']}",
        json={"assignedTo": "Investigator B", "reporterName": "SOC Lead"},
    )
    assert response.status_code == 200
    latest_audit = response.json()["auditHistory"][-1]
    assert latest_audit["changesJson"]["assignedTo"] == {
        "old": "Investigator A",
        "new": "Investigator B",
    }
    assert latest_audit["changesJson"]["reporterName"] == {
        "old": None,
        "new": "SOC Lead",
    }


def test_metrics_count_all_active_and_resolved_statuses(client: TestClient) -> None:
    create_case(client, title="Open case", status="OPEN", severity="LOW")
    create_case(client, title="In progress case", status="IN_PROGRESS", severity="MEDIUM")
    create_case(client, title="Escalated case", status="ESCALATED", severity="CRITICAL")
    create_case(client, title="Resolved case", status="RESOLVED", severity="LOW")
    create_case(client, title="Closed case", status="CLOSED", severity="LOW")

    metrics = client.get("/api/v1/cases/metrics").json()
    assert metrics == {
        "totalCases": 5,
        "openCases": 3,
        "criticalCases": 1,
        "resolvedCases": 2,
    }


def test_dashboard_overview_returns_live_database_summary(client: TestClient) -> None:
    created = create_case(
        client,
        title="Suspicious login burst",
        status="ESCALATED",
        severity="CRITICAL",
        assignedTo="Investigator A",
    )
    response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    payload = response.json()
    assert payload["currentCaseId"] == created["caseNumber"]
    assert payload["metrics"]["activeInvestigations"]["value"] == 1
    assert payload["metrics"]["findingsRequiringReview"]["value"] == 1
    assert payload["metrics"]["eventsAnalyzed"]["value"] == 1
    assert payload["metrics"]["evidenceItems"]["value"] == 0
    assert len(payload["cases"]) == 1
    assert payload["cases"][0]["caseNumber"] == created["caseNumber"]
    assert payload["evidenceIntegrity"] == {"totalItems": 0, "verificationChecks": []}
    assert len(payload["activityEvents"]) == 1
    assert payload["activityEvents"][0]["caseId"] == created["caseNumber"]
    assert len(payload["analytics"]["eventVolume"]) == 7
