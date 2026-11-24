from collections.abc import Generator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.security import auth_rate_limiter
from app.db.base import Base
from app.db.session import get_db
from app.main import app


@pytest.fixture
def ai_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("EVIDENCE_VAULT_DIR", str(tmp_path / "vault"))
    monkeypatch.setenv("AI_PROVIDER", "deterministic")
    monkeypatch.setenv("AI_PROVIDER_ENABLED", "false")
    monkeypatch.setenv("AI_ALLOW_EXTERNAL_DATA", "false")
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


def _register(client: TestClient, email: str, org_name: str) -> dict:
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "fullName": email.split("@")[0].title(), "password": "StrongPassword123!", "organizationName": org_name},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_ai_endpoints_require_authentication(ai_client: TestClient) -> None:
    assert ai_client.get("/api/v1/ai/status").status_code == 401
    assert ai_client.get("/api/v1/ai/conversations").status_code == 401
    assert ai_client.post("/api/v1/ai/conversations", json={"caseId": "CT-2026-0001"}).status_code == 401


def test_ai_conversations_deterministic_citations_and_isolation(ai_client: TestClient) -> None:
    org_a = _register(ai_client, "lead@alpha.test", "Alpha Forensics")
    headers_a = {"Authorization": f"Bearer {org_a['accessToken']}"}

    # Check deterministic default status
    st = ai_client.get("/api/v1/ai/status", headers=headers_a).json()
    assert st["mode"] == "deterministic"
    assert st["isGenerativeLlm"] is False
    assert st["externalDataAllowed"] is False

    # Create a case with NO evidence yet -> assistant must clearly state missing evidence
    case = ai_client.post("/api/v1/cases", json={"title": "Ransomware Triage"}, headers=headers_a).json()
    cnum = case["caseNumber"]

    conv = ai_client.post("/api/v1/ai/conversations", json={"caseId": cnum}, headers=headers_a)
    assert conv.status_code == 201, conv.text
    conv_code = conv.json()["conversationCode"]

    msg1 = ai_client.post(
        f"/api/v1/ai/conversations/{conv_code}/messages",
        json={"content": "Which evidence has passed SHA-256 verification?"},
        headers=headers_a,
    )
    assert msg1.status_code == 201, msg1.text
    a1 = msg1.json()["assistantMessage"]
    assert a1["mode"] == "deterministic"
    assert a1["externalDataTransmitted"] is False
    assert "No evidence items are registered" in a1["content"]

    # Upload real evidence and ask again -> must cite real evidence code
    ev = ai_client.post(
        "/api/v1/evidence/upload",
        data={"caseId": cnum, "evidenceType": "LOG_FILE"},
        files={"file": ("auth.log", b"2026-11-24T10:00:01Z sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2\n", "text/plain")},
        headers=headers_a,
    ).json()

    msg2 = ai_client.post(
        f"/api/v1/ai/conversations/{conv_code}/messages",
        json={"content": "Which evidence has passed SHA-256 verification?"},
        headers=headers_a,
    )
    assert msg2.status_code == 201
    a2 = msg2.json()["assistantMessage"]
    assert ev["evidenceCode"] in a2["content"]
    assert any(c["ref"] == ev["evidenceCode"] for c in a2["citations"])

    # Read full conversation history (2 user + 2 assistant = 4 messages)
    detail = ai_client.get(f"/api/v1/ai/conversations/{conv_code}", headers=headers_a).json()
    assert len(detail["messages"]) == 4

    # Another investigator in the SAME org cannot access private conversation
    ai_client.post(
        "/api/v1/investigators",
        json={"email": "peer@alpha.test", "fullName": "Peer Analyst", "password": "PeerPassword123!", "role": "INVESTIGATOR"},
        headers=headers_a,
    )
    peer_token = ai_client.post("/api/v1/auth/login", json={"email": "peer@alpha.test", "password": "PeerPassword123!"}).json()["accessToken"]
    headers_peer = {"Authorization": f"Bearer {peer_token}"}
    assert ai_client.get(f"/api/v1/ai/conversations/{conv_code}", headers=headers_peer).status_code == 404
    assert ai_client.get("/api/v1/ai/conversations", headers=headers_peer).json()["total"] == 0

    # Another organization cannot create a conversation on Org A's case
    org_b = _register(ai_client, "lead@beta.test", "Beta Forensics")
    headers_b = {"Authorization": f"Bearer {org_b['accessToken']}"}
    assert ai_client.post("/api/v1/ai/conversations", json={"caseId": cnum}, headers=headers_b).status_code == 404

    # Archive / delete conversation
    assert ai_client.delete(f"/api/v1/ai/conversations/{conv_code}", headers=headers_a).status_code == 204
    assert ai_client.get(f"/api/v1/ai/conversations/{conv_code}", headers=headers_a).status_code == 404


def test_local_llm_provider_and_external_opt_in_guard(
    ai_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org = _register(ai_client, "ai@lab.test", "AI Lab")
    headers = {"Authorization": f"Bearer {org['accessToken']}"}
    case = ai_client.post("/api/v1/cases", json={"title": "LLM Provider Test"}, headers=headers).json()
    conv_code = ai_client.post("/api/v1/ai/conversations", json={"caseId": case["caseNumber"]}, headers=headers).json()["conversationCode"]

    # 1. External provider configured WITHOUT AI_ALLOW_EXTERNAL_DATA=true must stay deterministic & never transmit
    monkeypatch.setenv("AI_PROVIDER", "external")
    monkeypatch.setenv("AI_PROVIDER_ENABLED", "true")
    monkeypatch.setenv("AI_ALLOW_EXTERNAL_DATA", "false")
    monkeypatch.setenv("AI_PROVIDER_URL", "https://api.example-llm.invalid")
    monkeypatch.setenv("AI_API_KEY", "test-key")
    get_settings.cache_clear()

    blocked_ext = ai_client.post(
        f"/api/v1/ai/conversations/{conv_code}/messages",
        json={"content": "Summarize this investigation."},
        headers=headers,
    )
    assert blocked_ext.status_code == 201
    assert blocked_ext.json()["assistantMessage"]["mode"] == "deterministic"
    assert blocked_ext.json()["assistantMessage"]["externalDataTransmitted"] is False

    # 2. Local LLM (Ollama) mode calls local provider URL and handles valid response
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setenv("AI_PROVIDER_ENABLED", "true")
    monkeypatch.setenv("AI_PROVIDER_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("AI_MODEL", "llama3.1")
    get_settings.cache_clear()

    class _MockResp:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._payload

    class _MockClient:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def __enter__(self) -> "_MockClient":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def post(self, url: str, **kwargs: object) -> "_MockResp":
            return _MockResp(self._payload)

    monkeypatch.setattr(
        "app.integrations.ai_assistant.httpx.Client",
        lambda **kwargs: _MockClient({"message": {"content": "Local Ollama grounded summary."}}),
    )
    ok_local = ai_client.post(
        f"/api/v1/ai/conversations/{conv_code}/messages",
        json={"content": "Summarize this investigation."},
        headers=headers,
    )
    assert ok_local.status_code == 201
    assert ok_local.json()["assistantMessage"]["mode"] == "local_llm"
    assert ok_local.json()["assistantMessage"]["content"] == "Local Ollama grounded summary."
    assert ok_local.json()["assistantMessage"]["externalDataTransmitted"] is False

    # 3. Invalid / empty provider response returns 502 cleanly
    monkeypatch.setattr(
        "app.integrations.ai_assistant.httpx.Client",
        lambda **kwargs: _MockClient({}),
    )
    bad_local = ai_client.post(
        f"/api/v1/ai/conversations/{conv_code}/messages",
        json={"content": "Summarize this investigation."},
        headers=headers,
    )
    assert bad_local.status_code == 502
