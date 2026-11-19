"""Scoring, root-cause rules and text rendering. Pure functions, easy to test."""

from __future__ import annotations

from .models import SEVERITY_WEIGHT, Diagnosis, Finding, Severity


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.id, f.title)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def health_score(findings: list[Finding]) -> int:
    penalty = sum(SEVERITY_WEIGHT[f.severity] for f in dedupe(findings) if f.severity not in {Severity.OK, Severity.INFO})
    return max(0, 100 - penalty)


# Correlation rules: several findings together point to one root cause.
# This is the deterministic version of what the LLM does more flexibly.
RULES = [
    ({"spf.provider_missing", "dkim.provider_missing"},
     "Email provider was changed (or newly set up) but the domain's SPF and DKIM were never updated for it; "
     "outgoing mail is unauthenticated and likely lands in spam."),
    ({"mx.mixed_providers"},
     "MX records point to two different providers, so incoming mail is split and some messages land in a mailbox nobody checks."),
    ({"domain.hold_status"}, "The registry has suspended the domain (hold/redemption), which takes down both website and email."),
    ({"domain.expired"}, "The domain has expired; renewing it restores website and email."),
    ({"domain.nxdomain"}, "The domain does not resolve at all (expired, on hold, or misspelled), so nothing works."),
    ({"spf.multiple"}, "There are two SPF records, which makes SPF fail for every message."),
    ({"spf.too_many_lookups"}, "SPF exceeds the 10-lookup limit, so SPF fails (permerror) for everyone."),
    ({"mx.missing"}, "The domain has no MX records, so it cannot receive email."),
    ({"bl.listed"}, "A sending IP or the domain is on a spam blocklist, so receivers reject or spam the mail."),
    ({"ssl.invalid"}, "The website's SSL certificate is invalid, so browsers block it."),
    ({"web.apex_no_address"}, "The domain has no website address record, so the site can't load."),
    ({"web.https_unreachable"}, "The web server isn't answering on HTTPS."),
    ({"hdr.dmarc_fail"}, "The receiver applied DMARC and the message failed alignment; fix SPF/DKIM for the sending service."),
    ({"bounce.auth"}, "The email app is failing to log in to the SMTP server (password/app-password/plan restriction)."),
    ({"bounce.user_unknown"}, "The recipient mailbox doesn't exist at the server the MX points to."),
    ({"client.no_mailbox"}, "The domain only forwards mail; there is no mailbox to connect an email app to."),
]


def infer_root_causes(findings: list[Finding]) -> list[str]:
    ids = {f.id for f in findings}
    causes = [text for need, text in RULES if need <= ids]
    if not causes:
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        causes = [f.title for f in crit[:3]]
    return causes


def render_text(d: Diagnosis) -> str:
    icon = {"ok": "✅", "info": "ℹ️ ", "warning": "⚠️ ", "critical": "❌", "unknown": "❔"}
    lines = [f"MailDoctor report for {d.domain}   health {d.health_score}/100   engine={d.engine}", ""]
    if d.complaint:
        lines.append(f"Complaint: {d.complaint}")
    if d.summary:
        lines += ["", "Summary:", f"  {d.summary}"]
    if d.root_causes:
        lines += ["", "Root cause(s):"] + [f"  • {c}" for c in d.root_causes]
    lines += ["", "Findings:"]
    order = {"critical": 0, "warning": 1, "unknown": 2, "info": 3, "ok": 4}
    for f in sorted(dedupe(d.findings), key=lambda x: order[x.severity.value]):
        lines.append(f"  {icon[f.severity.value]} {f.title}")
        if f.detail and f.severity.value in {"critical", "warning"}:
            lines.append(f"      {f.detail}")
    if d.fixes:
        lines += ["", "Fix plan:"]
        for i, p in enumerate(d.fixes, 1):
            lines.append(f"  {i}. {p.title}  (risk: {p.risk})")
            for c in p.changes:
                pr = f" priority {c.priority}" if c.priority is not None else ""
                old = f"   (replaces: {c.replaces})" if c.replaces and c.action != "add" else ""
                lines.append(f"     {c.action.upper():6} {c.type:5} {c.name:20} {c.value}{pr}{old}")
            for s in p.steps:
                lines.append(f"     - {s}")
    if d.customer_reply:
        lines += ["", "Suggested reply to customer:", f"  {d.customer_reply}"]
    if d.limits:
        lines += ["", "What this scan cannot see:"] + [f"  - {x}" for x in d.limits]
    if d.trace:
        lines += ["", "Agent trace:"]
        for s in d.trace:
            lines.append(f"  [{s.step}] {s.tool or 'think'} {s.args if s.args else ''} -> {s.result_summary}")
    return "\n".join(lines)


STANDARD_LIMITS = [
    "Mailbox-side problems (full storage, wrong password, deleted user) need the provider's admin panel or a bounce message.",
    "Whether mail actually lands in spam needs a real test message: paste its headers into analyze_headers.",
    "DKIM signing must be enabled inside the email provider; DNS only proves the key is published.",
]
