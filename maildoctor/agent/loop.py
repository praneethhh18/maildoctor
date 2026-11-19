"""The agent loop: plan -> act (tool) -> observe -> decide -> ... -> submit.

    while steps remain:
        response = llm.chat(history, tools)
        if response asks for tools:   run them, append results, continue
        if response calls submit_diagnosis: build the Diagnosis and stop
        if response is plain text:    nudge the model to call a tool or submit

Everything the model sees from the world comes from deterministic tools, and
every step is recorded in `trace` so a human can audit the reasoning.

If no LLM key is configured, `offline_investigate` runs a rule-based playbook
so the product still works (and tests run without network).
"""

from __future__ import annotations

import json
import time
import re
from typing import Any

from ..fixes import build_fixes
from ..models import AgentStep, Diagnosis, Finding, Severity, ToolResult
from ..report import STANDARD_LIMITS, dedupe, health_score, infer_root_causes
from ..tools import REGISTRY, Context, norm_domain, run_tool
from .llm import LLM, LLMError, LLMResponse
from .prompts import FINISH_TOOL, SYSTEM_PROMPT

ATTACH = "@attachment"


def _summarise(r: ToolResult) -> str:
    if r.error:
        return f"error: {r.error}"
    bad = [f.title for f in r.findings if f.severity in {Severity.CRITICAL, Severity.WARNING}]
    return "; ".join(bad[:3]) if bad else (r.findings[0].title if r.findings else "no findings")


def _tool_menu() -> list[dict]:
    return [spec.schema() for spec in REGISTRY.values() if spec.name != "check_email_auth_all"] + [FINISH_TOOL]


def investigate(ctx: Context, llm: LLM | None, domain: str, complaint: str = "",
                headers: str = "", bounce: str = "", client_error: str = "") -> Diagnosis:
    d = norm_domain(domain) if domain else ""
    if llm is None:
        return _with_providers(ctx, offline_investigate(ctx, d, complaint, headers, bounce, client_error))
    try:
        return _with_providers(ctx, _llm_investigate(ctx, llm, d, complaint, headers, bounce, client_error))
    except Exception as e:  # LLMError, or anything unexpected from the model side
        diag = offline_investigate(ctx, d, complaint, headers, bounce, client_error)
        short = str(e).split("\n")[0][:160]
        diag.limits.insert(0, f"AI agent unavailable ({short}); used the rule-based playbook instead.")
        return _with_providers(ctx, diag)


def _with_providers(ctx: Context, diag: Diagnosis) -> Diagnosis:
    """Attach who-hosts-what (memoised, so usually free) so the UI can offer the right fix path."""
    if diag.domain:
        ov = run_tool(ctx, "dns_overview", {"domain": diag.domain})
        diag.dns_provider = ov.data.get("dns_provider")
        diag.email_provider = ov.data.get("email_provider")
    return diag


def _llm_investigate(ctx: Context, llm: LLM, d: str, complaint: str, headers: str, bounce: str, client_error: str) -> Diagnosis:
    attachments = {"headers": headers, "bounce": bounce}
    parts = [f"Domain: {d or '(not given)'}", f"Problem reported: {complaint or 'General health check'}"]
    if headers:
        parts.append("Attached: raw email headers (use analyze_headers with raw_headers='@attachment').")
    if bounce:
        parts.append("Attached: a bounce / error message (use decode_bounce with text='@attachment').")
    if client_error:
        parts.append(f"Email app error shown to the user: {client_error}")
    history: list[dict] = [{"role": "user", "content": "\n".join(parts)}]
    tools = _tool_menu()
    trace: list[AgentStep] = []
    results: list[ToolResult] = []
    final: dict[str, Any] | None = None
    nudges = 0

    deadline = time.monotonic() + ctx.settings.agent_budget
    for step in range(1, ctx.settings.max_agent_steps + 1):
        if time.monotonic() > deadline:
            raise LLMError(f"agent ran longer than {ctx.settings.agent_budget:.0f}s")
        resp: LLMResponse = llm.chat(SYSTEM_PROMPT, history, tools)
        if not resp.tool_calls:
            if nudges < 2:
                nudges += 1
                history.append({"role": "assistant", "content": resp.text})
                history.append({"role": "user", "content": "Continue: call the next tool, or call submit_diagnosis if you are done."})
                trace.append(AgentStep(step=step, thought=resp.text[:300], result_summary="(no tool call; nudged)"))
                continue
            final = {"summary": resp.text, "root_causes": [], "fix_ids": [], "customer_reply": "", "confidence": "low"}
            break
        history.append({"role": "assistant", "content": resp.text,
                        "tool_calls": [{"id": tc.id, "name": tc.name, "args": tc.args} for tc in resp.tool_calls]})
        for tc in resp.tool_calls:
            if tc.name == FINISH_TOOL["name"]:
                final = tc.args
                trace.append(AgentStep(step=step, thought=resp.text[:300], tool=tc.name, result_summary="diagnosis submitted"))
                break
            args = dict(tc.args)
            if args.get("raw_headers") == ATTACH:
                args["raw_headers"] = attachments["headers"]
            if args.get("text") == ATTACH:
                args["text"] = attachments["bounce"]
            r = run_tool(ctx, tc.name, args)
            results.append(r)
            shown = {k: (v if k not in {"raw_headers", "text"} else "<attachment>") for k, v in tc.args.items()}
            trace.append(AgentStep(step=step, thought=resp.text[:300], tool=tc.name, args=shown, result_summary=_summarise(r)))
            history.append({"role": "tool", "tool_call_id": tc.id, "name": tc.name,
                            "content": json.dumps(r.compact(), default=str)[:6000]})
        if final is not None:
            break

    findings = dedupe([f for r in results for f in r.findings])
    if final is None:  # ran out of steps
        final = {"summary": "Step limit reached; showing what was found.", "root_causes": infer_root_causes(findings),
                 "fix_ids": [], "customer_reply": "", "confidence": "low"}
    allowed = {fid for f in findings for fid in f.fix_ids}
    chosen = [fid for fid in final.get("fix_ids", []) if fid in allowed]  # model can't invent fixes
    target = [f for f in findings if any(fid in chosen for fid in f.fix_ids)] if chosen else findings
    fixes = build_fixes(ctx, d, target) if d else []
    if chosen:
        fixes.sort(key=lambda p: chosen.index(p.id) if p.id in chosen else 99)
    return Diagnosis(
        domain=d, complaint=complaint, summary=final.get("summary", ""),
        root_causes=final.get("root_causes") or infer_root_causes(findings),
        findings=findings, fixes=fixes, customer_reply=final.get("customer_reply", ""),
        health_score=health_score(findings), trace=trace, engine=llm.name,
        confidence=final.get("confidence", "medium"), limits=list(STANDARD_LIMITS))


# ---------------------------------------------------------------- offline playbook
PLAYBOOKS = [
    (r"spam|junk|not (reaching|delivered)|bounce|reject|gmail|outlook|deliver", ["check_mx", "check_spf", "check_dkim", "check_dmarc", "check_blacklists"]),
    (r"receiv|incoming|not getting|no (new )?mail|inbox empty", ["check_mx", "check_domain_registration"]),
    (r"website|site|page|ssl|https|certificate|not loading|down|404|500|502|503", ["check_website", "check_domain_registration"]),
    (r"outlook|thunderbird|iphone|android|apple mail|imap|smtp|pop|password|app|client|connect", ["email_client_settings"]),
    (r"expir|renew|suspend|hold|registrar|transfer", ["check_domain_registration"]),
    (r"dns|nameserver|propagat|moved|migrat", ["check_mx", "check_spf", "check_dkim", "check_website", "check_domain_registration"]),
    (r"blacklist|blocklist|spamhaus|listed", ["check_blacklists"]),
]
FULL_SCAN = ["check_mx", "check_spf", "check_dkim", "check_dmarc", "check_website", "check_domain_registration", "check_blacklists"]


def offline_investigate(ctx: Context, d: str, complaint: str = "", headers: str = "", bounce: str = "",
                        client_error: str = "") -> Diagnosis:
    plan: list[tuple[str, dict]] = []
    if headers:
        plan.append(("analyze_headers", {"raw_headers": headers}))
    if bounce:
        plan.append(("decode_bounce", {"text": bounce}))
    if d:
        plan.append(("dns_overview", {"domain": d}))
        c = complaint.lower()
        picked: list[str] = []
        for pat, tools in PLAYBOOKS:
            if re.search(pat, c):
                picked += [t for t in tools if t not in picked]
        for t in picked or FULL_SCAN:
            if t == "email_client_settings":
                plan.append((t, {"email_or_domain": d, "error_message": client_error}))
            else:
                plan.append((t, {"domain": d}))
        if client_error and not any(t == "email_client_settings" for t, _ in plan):
            plan.append(("email_client_settings", {"email_or_domain": d, "error_message": client_error}))

    trace, results = [], []
    for i, (name, args) in enumerate(plan, 1):
        r = run_tool(ctx, name, args)
        results.append(r)
        # follow one obvious lead like the LLM would: DKIM selector from headers
        if name == "analyze_headers" and d:
            sels = [s["s"] for s in r.data.get("dkim_signatures", []) if s.get("s")]
            if sels:
                plan.append(("check_dkim", {"domain": d, "selectors": sels}))
        shown = {k: ("<attachment>" if k in {"raw_headers", "text"} else v) for k, v in args.items()}
        trace.append(AgentStep(step=i, tool=name, args=shown, result_summary=_summarise(r)))

    findings = dedupe([f for r in results for f in r.findings])
    causes = infer_root_causes(findings)
    fixes = build_fixes(ctx, d, findings) if d else []
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    summary = (f"Found {len(crit)} critical issue(s). " + (causes[0] if causes else "")) if crit else \
        "No critical problems found in public DNS/web checks."
    reply = _template_reply(d, causes, fixes)
    return Diagnosis(domain=d, complaint=complaint, summary=summary.strip(), root_causes=causes, findings=findings,
                     fixes=fixes, customer_reply=reply, health_score=health_score(findings), trace=trace,
                     engine="offline-playbook", confidence="medium" if crit else "low", limits=list(STANDARD_LIMITS))


def _template_reply(d: str, causes: list[str], fixes) -> str:
    if not causes:
        return (f"I checked {d or 'your domain'} and its public DNS, website and email settings look healthy. "
                "If the problem continues, please send me the bounce message or the headers of an affected email.")
    first = fixes[0].title if fixes else "apply the fix below"
    return (f"I checked {d}. The main issue: {causes[0]} "
            f"First step: {first}. I've listed the exact records and steps. DNS changes usually take effect within an hour.")


def scan(ctx: Context, domain: str) -> Diagnosis:
    """Non-agentic full health scan (fixed checklist). Fast and free; used by monitoring."""
    d = norm_domain(domain)
    results = [run_tool(ctx, "dns_overview", {"domain": d})] + [run_tool(ctx, t, {"domain": d}) for t in FULL_SCAN]
    findings = dedupe([f for r in results for f in r.findings])
    return _with_providers(ctx, Diagnosis(
        domain=d, summary="Full health scan", root_causes=infer_root_causes(findings),
        findings=findings, fixes=build_fixes(ctx, d, findings), health_score=health_score(findings),
        engine="scan", trace=[AgentStep(step=i + 1, tool=r.tool, result_summary=_summarise(r)) for i, r in enumerate(results)],
        limits=list(STANDARD_LIMITS)))
