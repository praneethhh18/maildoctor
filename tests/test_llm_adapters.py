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
