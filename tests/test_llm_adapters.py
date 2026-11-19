import json

import httpx

from maildoctor.agent.llm import GeminiChat, OpenAIChat
from maildoctor.agent.prompts import FINISH_TOOL

TOOLS = [{"name": "check_mx", "description": "x", "parameters": {"type": "object", "properties": {"domain": {"type": "string"}},
                                                                    "required": ["domain"], "additionalProperties": False}}, FINISH_TOOL]
HISTORY = [
    {"role": "user", "content": "Domain: a.com"},
    {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "name": "check_mx", "args": {"domain": "a.com"}}]},
    {"role": "tool", "tool_call_id": "c1", "name": "check_mx", "content": json.dumps({"findings": []})},
]


def test_openai_request_and_parse():
    seen = {}

    def handler(req):
        seen["body"] = json.loads(req.content)
        seen["auth"] = req.headers["authorization"]
        return httpx.Response(200, json={"choices": [{"message": {"content": None, "tool_calls": [
            {"id": "c2", "type": "function", "function": {"name": "check_spf", "arguments": "{\"domain\": \"a.com\"}"}}]}}]})

    llm = OpenAIChat("k", "gpt-4o-mini", "https://api.openai.com/v1", client=httpx.Client(transport=httpx.MockTransport(handler)))
    r = llm.chat("sys", HISTORY, TOOLS)
    assert r.tool_calls[0].name == "check_spf" and r.tool_calls[0].args == {"domain": "a.com"}
    b = seen["body"]
    assert seen["auth"] == "Bearer k"
    assert b["messages"][0] == {"role": "system", "content": "sys"}
    assert b["messages"][2]["tool_calls"][0]["function"]["arguments"] == "{\"domain\": \"a.com\"}"
    assert b["messages"][3] == {"role": "tool", "tool_call_id": "c1", "content": HISTORY[2]["content"]}
    assert b["tools"][0]["type"] == "function"


def test_gemini_follows_retired_model_hint():
    urls = []

    def handler(req):
        urls.append(str(req.url))
        if "old-model" in str(req.url):
            return httpx.Response(404, json={"error": {"code": 404, "message":
                "This model models/old-model is no longer available. Please update your code to use models/new-model-9 for the latest features."}})
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "ok"}]}}]})

    llm = GeminiChat("gk", "old-model", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert llm.chat("sys", HISTORY, TOOLS).text == "ok"
    assert llm.name == "gemini:new-model-9" and "new-model-9:generateContent" in urls[-1]


def test_gemini_request_and_parse():
    seen = {}

    def handler(req):
        seen["body"] = json.loads(req.content)
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [
            {"text": "SPF next."}, {"functionCall": {"name": "check_spf", "args": {"domain": "a.com"}}}]}}]})

    llm = GeminiChat("gk", "gemini-2.0-flash", client=httpx.Client(transport=httpx.MockTransport(handler)))
    r = llm.chat("sys", HISTORY, TOOLS)
    assert r.text == "SPF next." and r.tool_calls[0].name == "check_spf"
    b = seen["body"]
    assert "key=gk" in seen["url"] and "gemini-2.0-flash:generateContent" in seen["url"]
    assert b["systemInstruction"]["parts"][0]["text"] == "sys"
    assert [c["role"] for c in b["contents"]] == ["user", "model", "user"]
    assert b["contents"][1]["parts"][0]["functionCall"]["name"] == "check_mx"
    assert b["contents"][2]["parts"][0]["functionResponse"]["name"] == "check_mx"
    decl = b["tools"][0]["functionDeclarations"][0]
    assert "additionalProperties" not in decl["parameters"]  # stripped for Gemini


def test_llm_timeout_falls_back_to_playbook():
    """A slow model must never crash the request: retry once, then use the rule-based playbook."""
    import httpx
    from maildoctor.agent import investigate
    from maildoctor.agent.llm import GeminiChat
    from conftest import HEALTHY, ctx_for

    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ReadTimeout("The read operation timed out", request=request)

    llm = GeminiChat("k", "gemini-x", client=httpx.Client(transport=httpx.MockTransport(handler)))
    diag = investigate(ctx_for(HEALTHY), llm, "good.in", "emails go to spam")
    assert calls["n"] == 2  # one retry
    assert any("AI agent unavailable" in l and "timed out" in l for l in diag.limits)
    assert diag.findings  # playbook still produced real checks


def test_api_errors_are_json():
    from fastapi.testclient import TestClient
    import maildoctor.api as api

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    api.make_context, old = boom, api.make_context
    try:
        r = TestClient(api.app, raise_server_exceptions=False).post("/api/scan", json={"domain": "good.in"})
    finally:
        api.make_context = old
    assert r.status_code == 500 and "kaboom" in r.json()["detail"]
