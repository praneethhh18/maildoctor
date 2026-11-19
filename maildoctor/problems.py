"""Self-serve layer: problems in the customer's words, and 'did my fix work?' checks.

Non-technical users don't know words like SPF or MX. They know "my emails go to
spam". This catalog maps plain problems to a complaint the agent understands,
and maps each fix to the checks that prove it worked.
"""

from __future__ import annotations

from .models import Finding, Severity
from .report import dedupe
from .tools import Context, norm_domain, run_tool

PROBLEMS = [
    {"id": "spam", "icon": "📥", "label": "My emails go to spam",
     "complaint": "Emails I send land in the recipient's spam/junk folder", "extra": "headers",
     "extra_label": "Optional: paste the 'Show original' headers of one of those emails"},
    {"id": "not_receiving", "icon": "📭", "label": "I'm not receiving emails",
     "complaint": "Not receiving incoming email; senders say their mail doesn't arrive or bounces", "extra": None},
    {"id": "bouncing", "icon": "↩️", "label": "My emails bounce back",
     "complaint": "Emails I send bounce back with an error", "extra": "bounce",
     "extra_label": "Paste the bounce message you got back (the 'Mail Delivery Subsystem' email)"},
    {"id": "site_down", "icon": "🌐", "label": "My website won't open",
     "complaint": "My website does not load / shows an error", "extra": None},
    {"id": "not_secure", "icon": "🔓", "label": "Browser says 'Not secure'",
     "complaint": "Browser shows 'Not secure' or a certificate/SSL warning on my website", "extra": None},
    {"id": "app_connect", "icon": "📱", "label": "Can't set up email in Outlook / phone",
     "complaint": "Can't add my mailbox to Outlook, Apple Mail, Thunderbird or my phone", "extra": "client_error",
     "extra_label": "What error does the app show? (copy the exact words)"},
    {"id": "moved", "icon": "🚚", "label": "Things broke after I moved provider",
     "complaint": "After moving my domain/DNS/email to a new provider, email or website stopped working properly", "extra": None},
    {"id": "expiry", "icon": "⏳", "label": "Is my domain about to expire?",
     "complaint": "Check domain registration, expiry and suspension status", "extra": None},
    {"id": "checkup", "icon": "🩺", "label": "Full checkup",
     "complaint": "General health check of domain, email and website", "extra": None},
]

# Which checks prove a given fix worked.
FIX_VERIFY = {
    "fix.spf.create": ["check_spf"], "fix.spf.merge": ["check_spf"], "fix.spf.add_include": ["check_spf"],
    "fix.spf.flatten": ["check_spf"], "fix.spf.policy": ["check_spf"],
    "fix.dmarc.create": ["check_dmarc"], "fix.dmarc.tighten": ["check_dmarc"], "fix.dmarc.add_rua": ["check_dmarc"],
    "fix.dkim.publish": ["check_dkim"],
    "fix.mx.set": ["check_mx"], "fix.mx.remove_conflict": ["check_mx"],
    "fix.web.point_dns": ["check_website"], "fix.web.www_cname": ["check_website"], "fix.ssl.reissue": ["check_website"],
    "fix.domain.renew_or_unhold": ["dns_overview", "check_domain_registration"],
    "fix.bl.delist": ["check_blacklists"],
}


def verify_fix(ctx: Context, domain: str, fix_id: str) -> dict:
    """Re-run only the checks behind one fix. 'fixed' = no problem finding still points at this fix."""
    d = norm_domain(domain)
    tools = FIX_VERIFY.get(fix_id)
    if not tools:
        return {"fix_id": fix_id, "verifiable": False, "fixed": None,
                "message": "This fix happens inside an app or account, so it can't be checked from outside. "
                           "Try the action again (send a test email / reconnect the app)."}
    findings: list[Finding] = []
    for t in tools:
        findings += run_tool(ctx, t, {"domain": d}).findings
    findings = dedupe(findings)
    still = [f for f in findings if fix_id in f.fix_ids and f.severity in {Severity.CRITICAL, Severity.WARNING}]
    unknown = [f for f in findings if f.severity == Severity.UNKNOWN]
    if still:
        fixed, msg = False, ("Not fixed yet: " + "; ".join(f.title for f in still) +
                             ". If you just changed DNS, wait 10–60 minutes and check again; old answers can be cached.")
    elif unknown and not any(f.severity == Severity.OK for f in findings):
        fixed, msg = None, "Couldn't confirm right now (a lookup failed). Try again in a few minutes."
    else:
        fixed, msg = True, "Fixed ✓  The problem is gone."
    return {"fix_id": fix_id, "verifiable": True, "fixed": fixed, "message": msg,
            "findings": [f.model_dump(mode="json") for f in findings]}
