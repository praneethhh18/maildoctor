"""HTTP API + web page.

Run:  uvicorn maildoctor.api:app --reload    then open http://127.0.0.1:8000

Endpoints
  GET  /api/health                       liveness + which LLM engine is active
  GET  /api/tools                        list the agent's tools (what it *can* do)
  GET  /api/problems                     plain-language problem catalog for the self-serve UI
  POST /api/verify      {domain, fix_id} "I did it, check again": re-runs only the checks behind that fix
  POST /api/scan        {domain}         fixed full checklist (fast, no LLM)
  POST /api/investigate {domain, complaint, headers?, bounce?, client_error?}   agentic
  POST /api/tool        {name, args}     run one tool directly (debugging / learning)
  POST /api/fix/preview {domain, fix_id, cloudflare_token}        diff + approval code
  POST /api/fix/apply   {zone_id, ops, approval_code, cloudflare_token}  apply + rollback data
  POST /api/fix/rollback{zone_id, rollback, cloudflare_token}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import __version__
from .agent import investigate, make_llm, scan
from .cloudflare import CloudflareClient, CloudflareError
from .config import get_settings
from .fixes import FIXES
from .problems import PROBLEMS, verify_fix
from .report import render_text
from .tools import REGISTRY, make_context, norm_domain, run_tool

app = FastAPI(title="MailDoctor", version=__version__)
WEB = Path(__file__).parent / "web"


class ScanIn(BaseModel):
    domain: str


class InvestigateIn(BaseModel):
    domain: str = ""
    problem_id: str = ""      # from /api/problems; fills the complaint for non-technical users
    complaint: str = ""
    headers: str = ""
    bounce: str = ""
    client_error: str = ""


class VerifyIn(BaseModel):
    domain: str
    fix_id: str


class ToolIn(BaseModel):
    name: str
    args: dict[str, Any] = {}


class PreviewIn(BaseModel):
    domain: str
    fix_id: str
    cloudflare_token: str


class ApplyIn(BaseModel):
    zone_id: str
    ops: list[dict[str, Any]]
    approval_code: str
    cloudflare_token: str


class RollbackIn(BaseModel):
    zone_id: str
    rollback: list[dict[str, Any]]
    cloudflare_token: str


def _diag_out(diag) -> dict:
    out = diag.model_dump(mode="json")
    out["text"] = render_text(diag)
    return out


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


@app.get("/api/health")
def health():
    s = get_settings()
    return {"ok": True, "version": __version__, "engine": s.resolved_provider()}


@app.get("/api/tools")
def tools():
    return [spec.schema() for spec in REGISTRY.values()]


@app.post("/api/scan")
def api_scan(body: ScanIn):
    if not norm_domain(body.domain):
        raise HTTPException(400, "domain required")
    return _diag_out(scan(make_context(), body.domain))


@app.post("/api/investigate")
def api_investigate(body: InvestigateIn):
    if not (body.domain or body.headers or body.bounce):
        raise HTTPException(400, "give a domain, headers or a bounce message")
    complaint = body.complaint
    if body.problem_id:
        p = next((x for x in PROBLEMS if x["id"] == body.problem_id), None)
        if p is None:
            raise HTTPException(404, "unknown problem")
        complaint = p["complaint"] + (f". In their words: {body.complaint}" if body.complaint else "")
    s = get_settings()
    diag = investigate(make_context(settings=s), make_llm(s), body.domain, complaint,
                       body.headers, body.bounce, body.client_error)
    return _diag_out(diag)


@app.get("/api/problems")
def problems():
    return PROBLEMS


@app.post("/api/verify")
def api_verify(body: VerifyIn):
    if not norm_domain(body.domain):
        raise HTTPException(400, "domain required")
    return verify_fix(make_context(), body.domain, body.fix_id)  # fresh context = no cached answers


@app.post("/api/tool")
def api_tool(body: ToolIn):
    if body.name not in REGISTRY:
        raise HTTPException(404, f"unknown tool {body.name}")
    return run_tool(make_context(), body.name, body.args).model_dump(mode="json")


@app.post("/api/fix/preview")
def fix_preview(body: PreviewIn):
    if body.fix_id not in FIXES:
        raise HTTPException(404, "unknown fix")
    plan = FIXES[body.fix_id](make_context(), norm_domain(body.domain))
    if not plan.changes:
        raise HTTPException(400, "this fix has only manual steps; nothing to apply via API")
    try:
        prev = CloudflareClient(body.cloudflare_token).preview(norm_domain(body.domain), plan)
    except CloudflareError as e:
        raise HTTPException(400, str(e))
    return {"plan": plan.model_dump(mode="json"), **prev}


@app.post("/api/fix/apply")
def fix_apply(body: ApplyIn):
    try:
        return CloudflareClient(body.cloudflare_token).apply(body.zone_id, body.ops, body.approval_code)
    except CloudflareError as e:
        raise HTTPException(400, str(e))


@app.post("/api/fix/rollback")
def fix_rollback(body: RollbackIn):
    try:
        return {"restored": CloudflareClient(body.cloudflare_token).rollback(body.zone_id, body.rollback)}
    except CloudflareError as e:
        raise HTTPException(400, str(e))
