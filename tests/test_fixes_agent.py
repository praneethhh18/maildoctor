import json

import httpx
import pytest
from conftest import HEALTHY, SWITCHED, ctx_for

from maildoctor.agent import LLMResponse, ScriptedLLM, ToolCall, investigate, scan
from maildoctor.cloudflare import CloudflareClient, CloudflareError
from maildoctor.fixes import FIXES, _merge_spf, build_fixes
from maildoctor.report import render_text
from maildoctor.tools import run_tool


# ---------------------------------------------------------------- fixes
def test_merge_spf_never_duplicates_and_keeps_strictest():
    merged = _merge_spf(["v=spf1 include:a.com ~all", "v=spf1 include:a.com include:b.com -all"], add=["c.com"])
    assert merged == "v=spf1 include:a.com include:b.com include:c.com -all"
    assert _merge_spf(["v=spf1 +all"]) == "v=spf1 ~all"


def test_switched_domain_fix_plan(switched_ctx):
    findings = []
    for t in ("check_mx", "check_spf", "check_dkim", "check_dmarc"):
        findings += run_tool(switched_ctx, t, {"domain": "moved.com"}).findings
    plans = {p.id: p for p in build_fixes(switched_ctx, "moved.com", findings)}
    spf = plans["fix.spf.add_include"].changes[0]
    assert spf.action == "update" and spf.value == "v=spf1 include:secureserver.net include:_spf.google.com ~all"
    assert "GoDaddy" in " ".join(plans["fix.spf.add_include"].steps)
    assert "google._domainkey" in " ".join(plans["fix.dkim.publish"].steps)
    assert plans["fix.dmarc.create"].changes[0].name == "_dmarc"


def test_spf_merge_plan_supersedes_add_include():
    c = ctx_for({("x.com", "MX"): ["1 smtp.google.com"], ("smtp.google.com", "A"): ["1.1.1.1"],
                 ("x.com", "TXT"): ["v=spf1 include:a.com ~all", "v=spf1 mx -all"], ("a.com", "TXT"): ["v=spf1 -all"]})
    f = run_tool(c, "check_spf", {"domain": "x.com"}).findings
    plans = [p.id for p in build_fixes(c, "x.com", f)]
    assert "fix.spf.merge" in plans and "fix.spf.add_include" not in plans
    merge = FIXES["fix.spf.merge"](c, "x.com")
    adds = [ch for ch in merge.changes if ch.action == "add"]
    assert len(adds) == 1 and adds[0].value == "v=spf1 include:a.com mx include:_spf.google.com -all"


# ---------------------------------------------------------------- agent
def test_offline_agent_finds_root_cause(switched_ctx):
    d = investigate(switched_ctx, None, "moved.com", "our emails to gmail go to spam")
    assert d.engine == "offline-playbook"
    assert any("provider was changed" in c for c in d.root_causes)
    assert d.health_score < 50
    assert "moved.com" in d.customer_reply
    assert "Agent trace" in render_text(d)


def test_llm_agent_loop_with_attachment_and_guardrails(switched_ctx):
    script = [
        LLMResponse(text="Start broad.", tool_calls=[ToolCall("1", "dns_overview", {"domain": "moved.com"})]),
        LLMResponse(text="MX is Google; check SPF and DKIM.", tool_calls=[
            ToolCall("2", "check_spf", {"domain": "moved.com"}),
            ToolCall("3", "check_dkim", {"domain": "moved.com", "selectors": ["google"]})]),
        LLMResponse(text="Look at the bounce.", tool_calls=[ToolCall("4", "decode_bounce", {"text": "@attachment"})]),
        LLMResponse(text="", tool_calls=[ToolCall("5", "submit_diagnosis", {
            "summary": "Moved to Google but SPF/DKIM still point at GoDaddy.",
            "root_causes": ["Provider switch not reflected in DNS"],
            "fix_ids": ["fix.spf.add_include", "fix.invented.by.model"],
            "customer_reply": "Your mailboxes moved to Google; update SPF and enable DKIM.", "confidence": "high"})]),
    ]
    llm = ScriptedLLM(script)
    d = investigate(switched_ctx, llm, "moved.com", "mails bounce", bounce="550 5.7.26 Unauthenticated email ... DMARC policy")
    assert d.engine == "scripted" and d.confidence == "high"
    assert [s.tool for s in d.trace] == ["dns_overview", "check_spf", "check_dkim", "decode_bounce", "submit_diagnosis"]
    assert [p.id for p in d.fixes][0] == "fix.spf.add_include"   # model's priority respected
    assert all(p.id != "fix.invented.by.model" for p in d.fixes)  # model cannot invent fixes
    tool_msgs = [m for m in llm.seen[-1] if m["role"] == "tool"]
    assert any("bounce.dmarc" in m["content"] for m in tool_msgs)  # attachment was substituted
    assert d.trace[3].args["text"] == "<attachment>"               # raw text not echoed into trace


def test_llm_agent_nudges_then_step_limit(switched_ctx):
    llm = ScriptedLLM([LLMResponse(text="hmm")] * 3)
    d = investigate(switched_ctx, llm, "moved.com", "help")
    assert d.confidence == "low"


def test_scan_healthy(healthy_ctx):
    d = scan(healthy_ctx, "good.in")
    assert d.health_score >= 80, render_text(d)
    assert not [f for f in d.findings if f.severity.value == "critical"]


# ---------------------------------------------------------------- cloudflare
def _cf_transport(records, calls):
    def handler(req: httpx.Request):
        calls.append((req.method, req.url.path, json.loads(req.content) if req.content else None))
        if req.url.path.endswith("/zones"):
            return httpx.Response(200, json={"success": True, "result": [{"id": "z1"}]})
        if req.method == "GET":
            return httpx.Response(200, json={"success": True, "result": records})
        return httpx.Response(200, json={"success": True, "result": {"id": "new1"}})
    return httpx.MockTransport(handler)


def test_cloudflare_preview_apply_rollback(switched_ctx):
    records = [{"id": "r1", "type": "TXT", "name": "moved.com", "content": "\"v=spf1 include:secureserver.net ~all\"", "ttl": 1}]
    calls = []
    cf = CloudflareClient("tok", client=httpx.Client(transport=_cf_transport(records, calls)))
    plan = FIXES["fix.spf.add_include"](switched_ctx, "moved.com")
    prev = cf.preview("moved.com", plan)
    assert len(prev["ops"]) == 1 and prev["ops"][0]["method"] == "PUT" and prev["ops"][0]["record_id"] == "r1"
    with pytest.raises(CloudflareError):
        cf.apply("z1", prev["ops"], "wrongcode")
    out = cf.apply("z1", prev["ops"], prev["approval_code"])
    assert out["rollback"][0]["method"] == "PUT" and "secureserver" in out["rollback"][0]["body"]["content"]
    assert cf.rollback("z1", out["rollback"]) == 1


def test_cloudflare_refuses_second_spf(switched_ctx):
    records = [{"id": "r1", "type": "TXT", "name": "moved.com", "content": "v=spf1 -all", "ttl": 1}]
    cf = CloudflareClient("tok", client=httpx.Client(transport=_cf_transport(records, [])))
    plan = FIXES["fix.spf.create"](switched_ctx, "moved.com")
    with pytest.raises(CloudflareError, match="second SPF"):
        cf.preview("moved.com", plan)
