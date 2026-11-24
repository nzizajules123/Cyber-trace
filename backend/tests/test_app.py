from fastapi.testclient import TestClient

from app.main import app


def test_openapi_document_is_available() -> None:
    with TestClient(app) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "CyberTrace API"
    assert "/api/v1/cases" in response.json()["paths"]


def test_health_endpoint_is_available() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
