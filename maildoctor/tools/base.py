"""Tool registry.

A *tool* is a plain Python function that takes a Context plus simple arguments
and returns a ToolResult. The @tool decorator records its name, description and
JSON-schema parameters so that:
  - the agent can show the LLM a menu of tools (function calling),
  - the API/CLI can call the same functions directly,
  - tests can call them with a FakeResolver.

This is the heart of "agentic" design: the LLM never touches DNS itself. It can
only *ask* for a tool to run, and the tool returns verified facts.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from ..config import Settings, get_settings
from ..dnsclient import CachingResolver, Resolver, make_resolver
from ..models import ToolResult


@dataclass
class Context:
    resolver: CachingResolver
    settings: Settings = field(default_factory=get_settings)
    http: httpx.Client | None = None
    # Results gathered during one run, keyed "tool:target". Lets tools reuse
    # each other's work (e.g. SPF check reads the detected email provider).
    memo: dict[str, ToolResult] = field(default_factory=dict)
    offline: bool = False  # True in tests: skip real HTTP/TLS/socket calls

    def client(self) -> httpx.Client:
        if self.http is None:
            self.http = httpx.Client(
                timeout=self.settings.http_timeout,
                follow_redirects=False,
                headers={"user-agent": "MailDoctor/0.1 (+diagnostics)"},
            )
        return self.http


def make_context(resolver: Resolver | None = None, settings: Settings | None = None, offline: bool = False) -> Context:
    s = settings or get_settings()
    if resolver is None:
        r = make_resolver(s)
    elif isinstance(resolver, CachingResolver):
        r = resolver
    else:
        r = CachingResolver(resolver)
    return Context(resolver=r, settings=s, offline=offline)


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[..., ToolResult]

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


REGISTRY: dict[str, ToolSpec] = {}


def tool(name: str, description: str, properties: dict[str, Any], required: list[str]):
    def deco(fn: Callable[..., ToolResult]):
        REGISTRY[name] = ToolSpec(
            name=name,
            description=description,
            parameters={"type": "object", "properties": properties, "required": required},
            fn=fn,
        )
        return fn

    return deco


def run_tool(ctx: Context, name: str, args: dict[str, Any]) -> ToolResult:
    """Run a tool safely. A crashing tool becomes an error result, never a crash
    of the whole agent, and its output is memoised for reuse."""
    spec = REGISTRY.get(name)
    if spec is None:
        return ToolResult(tool=name, target=str(args), ok=False, error=f"unknown tool '{name}'")
    target = str(args.get("domain") or args.get("host") or args.get("email") or "input")
    key = f"{name}:{target}:{sorted(args.items())}"
    if key in ctx.memo:
        return ctx.memo[key]
    try:
        res = spec.fn(ctx, **args)
    except TypeError as e:
        res = ToolResult(tool=name, target=target, ok=False, error=f"bad arguments: {e}")
    except Exception as e:  # pragma: no cover - defensive
        res = ToolResult(tool=name, target=target, ok=False, error=f"{type(e).__name__}: {e}",
                         data={"trace": traceback.format_exc(limit=3)})
    ctx.memo[key] = res
    return res


def norm_domain(d: str) -> str:
    d = (d or "").strip().lower()
    for p in ("https://", "http://"):
        if d.startswith(p):
            d = d[len(p):]
    if "@" in d:
        d = d.split("@", 1)[1]
    d = d.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


DOMAIN_PARAM = {"domain": {"type": "string", "description": "Domain name, e.g. example.com"}}
