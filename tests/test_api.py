from conftest import SWITCHED, ctx_for
from fastapi.testclient import TestClient

import maildoctor.api as api


def test_api_endpoints(monkeypatch):
    monkeypatch.setattr(api, "make_context", lambda settings=None: ctx_for(SWITCHED))
    monkeypatch.setattr(api, "make_llm", lambda s: None)
    c = TestClient(api.app)
    assert c.get("/api/health").json()["ok"]
    names = {t["name"] for t in c.get("/api/tools").json()}
    assert {"check_spf", "check_dkim", "analyze_headers", "decode_bounce", "email_client_settings"} <= names
    r = c.post("/api/investigate", json={"domain": "moved.com", "complaint": "spam"}).json()
    assert r["health_score"] < 50 and r["fixes"] and "text" in r
    t = c.post("/api/tool", json={"name": "check_mx", "args": {"domain": "moved.com"}}).json()
    assert t["data"]["email_provider"] == "Google Workspace"
    assert c.post("/api/investigate", json={}).status_code == 400
    assert "MailDoctor" in c.get("/").text
