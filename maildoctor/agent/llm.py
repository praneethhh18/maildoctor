"""Provider-agnostic LLM layer with tool (function) calling.

We use plain HTTP instead of vendor SDKs so you can SEE what tool calling is:
  - we send the model a list of tool schemas,
  - the model replies either with text, or with "call tool X with args {...}",
  - we run the tool and send the result back as a new message,
  - repeat until the model calls `submit_diagnosis`.

Internal message format (provider-neutral):
  {"role": "user"|"assistant"|"tool", "content": str,
   "tool_calls": [{"id","name","args"}],   # on assistant messages
   "tool_call_id": str, "name": str}       # on tool messages
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from ..config import Settings


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLM(Protocol):
    name: str

    def chat(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse: ...


class LLMError(RuntimeError):
    pass


def _send(client: httpx.Client, who: str, url: str, **kw) -> httpx.Response:
    """POST with one retry. Network problems (timeout, DNS, reset) become LLMError,
    so the agent loop can fall back to the rule-based playbook instead of crashing."""
    last: Exception | None = None
    for _ in range(2):
        try:
            r = client.post(url, **kw)
            if r.status_code in (429, 500, 502, 503, 504) and last is None:
                last = LLMError(f"{who} HTTP {r.status_code}")
                continue
            return r
        except httpx.ConnectTimeout as e:
            last = LLMError(f"{who} could not connect ({type(e).__name__})")
        except httpx.TimeoutException as e:
            # The model itself was too slow. Retrying would only double the wait.
            raise LLMError(f"{who} timed out ({type(e).__name__})") from e
        except httpx.HTTPError as e:
            last = LLMError(f"{who} network error ({type(e).__name__}: {e})")
    raise last  # type: ignore[misc]


# ---------------------------------------------------------------- OpenAI
class OpenAIChat:
    """Works with OpenAI and any OpenAI-compatible endpoint (Groq, OpenRouter, local)."""

    def __init__(self, api_key: str, model: str, base_url: str, client: httpx.Client | None = None, timeout: float = 90):
        self.name = f"openai:{model}"
        self.key, self.model, self.base = api_key, model, base_url.rstrip("/")
        self.c = client or httpx.Client(timeout=httpx.Timeout(timeout, connect=10))

    def chat(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse:
        msgs: list[dict] = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "assistant" and m.get("tool_calls"):
                msgs.append({"role": "assistant", "content": m.get("content") or None, "tool_calls": [
                    {"id": tc["id"], "type": "function", "function": {"name": tc["name"], "arguments": json.dumps(tc["args"])}}
                    for tc in m["tool_calls"]]})
            elif m["role"] == "tool":
                msgs.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            else:
                msgs.append({"role": m["role"], "content": m["content"]})
        body = {"model": self.model, "messages": msgs, "temperature": 0.1,
                "tools": [{"type": "function", "function": t} for t in tools], "tool_choice": "auto"}
        r = _send(self.c, "OpenAI", f"{self.base}/chat/completions", json=body,
                  headers={"Authorization": f"Bearer {self.key}"})
        if r.status_code >= 400:
            raise LLMError(f"OpenAI HTTP {r.status_code}: {r.text[:300]}")
        msg = r.json()["choices"][0]["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(tc["id"], tc["function"]["name"], args))
        return LLMResponse(text=msg.get("content") or "", tool_calls=calls)


# ---------------------------------------------------------------- Gemini
def _gemini_schema(s: Any) -> Any:
    """Gemini accepts an OpenAPI subset; strip keys it rejects."""
    if isinstance(s, dict):
        return {k: _gemini_schema(v) for k, v in s.items() if k not in {"additionalProperties", "default", "$schema"}}
    if isinstance(s, list):
        return [_gemini_schema(x) for x in s]
    return s


class GeminiChat:
    def __init__(self, api_key: str, model: str, client: httpx.Client | None = None, timeout: float = 90,
                 thinking: str = "low"):
        self.name = f"gemini:{model}"
        self.key, self.model = api_key, model
        # Newer Gemini models "think" before answering, which can take minutes.
        # Picking a tool is an easy decision, so we ask for little thinking.
        self.thinking = thinking
        self.c = client or httpx.Client(timeout=httpx.Timeout(timeout, connect=10))

    def _post(self, body: dict) -> httpx.Response:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        return _send(self.c, "Gemini", url, params={"key": self.key}, json=body)

    def chat(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse:
        contents: list[dict] = []
        for m in messages:
            if m["role"] == "user":
                contents.append({"role": "user", "parts": [{"text": m["content"]}]})
            elif m["role"] == "assistant":
                parts = []
                if m.get("content"):
                    parts.append({"text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    parts.append({"functionCall": {"name": tc["name"], "args": tc["args"]}})
                contents.append({"role": "model", "parts": parts or [{"text": ""}]})
            elif m["role"] == "tool":
                try:
                    payload = json.loads(m["content"])
                except json.JSONDecodeError:
                    payload = {"text": m["content"]}
                part = {"functionResponse": {"name": m["name"], "response": {"result": payload}}}
                # consecutive tool results go in one user turn
                if contents and contents[-1]["role"] == "user" and "functionResponse" in contents[-1]["parts"][0]:
                    contents[-1]["parts"].append(part)
                else:
                    contents.append({"role": "user", "parts": [part]})
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": contents,
            "tools": [{"functionDeclarations": [_gemini_schema(t) for t in tools]}],
            "generationConfig": {"temperature": 0.1},
        }
        if self.thinking and self.thinking != "off":
            body["generationConfig"]["thinkingConfig"] = {"thinkingLevel": self.thinking}
        r = self._post(body)
        if r.status_code == 400 and "thinking" in r.text.lower() and "thinkingConfig" in body["generationConfig"]:
            # This model doesn't support the setting: drop it for this and later calls.
            self.thinking = "off"
            body["generationConfig"].pop("thinkingConfig")
            r = self._post(body)
        if r.status_code == 404:
            # Google retires model names often and says which one to use instead.
            # Follow that hint once, so a renamed model doesn't break the product.
            m = re.search(r"use (?:models/)?([\w.\-]+)", r.text)
            if m and m.group(1) != self.model:
                self.model = m.group(1)
                self.name = f"gemini:{self.model}"
                r = self._post(body)
        if r.status_code >= 400:
            raise LLMError(f"Gemini HTTP {r.status_code}: {r.text[:300]}")
        cands = r.json().get("candidates") or []
        if not cands:
            raise LLMError("Gemini returned no candidates (safety block or quota)")
        text, calls = [], []
        for p in cands[0].get("content", {}).get("parts", []):
            if "text" in p:
                text.append(p["text"])
            if "functionCall" in p:
                fc = p["functionCall"]
                calls.append(ToolCall(f"call_{uuid.uuid4().hex[:8]}", fc["name"], fc.get("args") or {}))
        return LLMResponse(text="".join(text), tool_calls=calls)


# ---------------------------------------------------------------- Scripted (tests / demos)
class ScriptedLLM:
    """Replays a fixed list of responses. Lets us test the agent loop without any API."""

    def __init__(self, script: list[LLMResponse]):
        self.name = "scripted"
        self.script = list(script)
        self.seen: list[list[dict]] = []

    def chat(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse:
        self.seen.append(list(messages))
        return self.script.pop(0) if self.script else LLMResponse(text="done")


def make_llm(settings: Settings) -> LLM | None:
    p = settings.resolved_provider()
    if p == "gemini" and settings.gemini_api_key:
        return GeminiChat(settings.gemini_api_key, settings.gemini_model, timeout=settings.llm_timeout,
                          thinking=settings.gemini_thinking)
    if p == "openai" and settings.openai_api_key:
        return OpenAIChat(settings.openai_api_key, settings.openai_model, settings.openai_base_url,
                          timeout=settings.llm_timeout)
    return None
