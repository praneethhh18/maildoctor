from conftest import HEALTHY, SWITCHED, ctx_for
from fastapi.testclient import TestClient

import maildoctor.api as api
from maildoctor.problems import PROBLEMS, verify_fix


def test_verify_fix_not_fixed_then_fixed():
    r = verify_fix(ctx_for(SWITCHED), "moved.com", "fix.spf.add_include")
    assert r["fixed"] is False and "Not fixed yet" in r["message"]
    fixed = dict(SWITCHED)
    fixed[("moved.com", "TXT")] = ["v=spf1 include:_spf.google.com ~all"]
    fixed[("_spf.google.com", "TXT")] = ["v=spf1 ip4:1.1.1.1 ~all"]
    r2 = verify_fix(ctx_for(fixed), "moved.com", "fix.spf.add_include")
    assert r2["fixed"] is True and "Fixed" in r2["message"]


def test_verify_unverifiable_fix():
    r = verify_fix(ctx_for(HEALTHY), "good.in", "fix.client.settings")
    assert r["verifiable"] is False and r["fixed"] is None


def test_every_problem_routes_to_tools(monkeypatch):
    """Each plain-language problem must make the agent actually run relevant checks."""
    monkeypatch.setattr(api, "make_context", lambda settings=None: ctx_for(SWITCHED))
    monkeypatch.setattr(api, "make_llm", lambda s: None)
    c = TestClient(api.app)
    assert {p["id"] for p in c.get("/api/problems").json()} == {p["id"] for p in PROBLEMS}
    for p in PROBLEMS:
        r = c.post("/api/investigate", json={"domain": "moved.com", "problem_id": p["id"]}).json()
        tools = [s["tool"] for s in r["trace"]]
        assert len(tools) >= 2, (p["id"], tools)
        assert r["dns_provider"] == "GoDaddy" and r["email_provider"] == "Google Workspace"
    assert c.post("/api/investigate", json={"domain": "moved.com", "problem_id": "nope"}).status_code == 404
    v = c.post("/api/verify", json={"domain": "moved.com", "fix_id": "fix.dmarc.create"}).json()
    assert v["fixed"] is False
