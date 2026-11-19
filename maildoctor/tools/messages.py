"""Message-level tools: email headers, bounce messages, and email client settings.

Public DNS can't see everything. A real message header shows what the receiving
server actually decided (SPF/DKIM/DMARC pass/fail), and a bounce message says
exactly why delivery failed. These tools parse such messy text deterministically.
"""

from __future__ import annotations

import email
import email.utils
import re
from email import policy

from ..models import Finding, Severity, ToolResult
from ..providers import CLIENT_SETTINGS, email_provider_info, match_email_provider
from .base import Context, norm_domain, tool
from .email_auth import _mx_hosts, org_domain


def _dom(addr: str) -> str:
    _n, a = email.utils.parseaddr(addr or "")
    return a.rsplit("@", 1)[-1].lower().strip(">") if "@" in a else ""


@tool("analyze_headers",
      "Parse raw email headers (from 'Show original'/'View source'): SPF/DKIM/DMARC verdicts the receiver applied, "
      "alignment between From and signing domains, the server hops and delivery delays.",
      {"raw_headers": {"type": "string", "description": "Full raw header text of one email"}},
      ["raw_headers"])
def analyze_headers(ctx: Context, raw_headers: str) -> ToolResult:
    msg = email.message_from_string(raw_headers.split("\n\n", 1)[0] if "\n\n" in raw_headers else raw_headers,
                                    policy=policy.compat32)
    res = ToolResult(tool="analyze_headers", target=_dom(msg.get("From", "")) or "message")
    from_dom = _dom(msg.get("From", ""))
    rp_dom = _dom(msg.get("Return-Path", ""))
    dkim_sigs = []
    for sig in msg.get_all("DKIM-Signature", []) or []:
        tags = {k.strip(): v.strip() for k, v in (t.split("=", 1) for t in re.sub(r"\s+", "", sig).split(";") if "=" in t)}
        dkim_sigs.append({"d": tags.get("d", "").lower(), "s": tags.get("s", "")})
    auth_headers = (msg.get_all("Authentication-Results") or []) + (msg.get_all("ARC-Authentication-Results") or [])
    auth = " ".join(auth_headers)
    verdict = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", auth, re.I)
        verdict[mech] = m.group(1).lower() if m else None
    mailfrom = re.search(r"smtp\.mailfrom=([^\s;]+)", auth, re.I)
    mf_dom = (mailfrom.group(1).rsplit("@", 1)[-1].lower() if mailfrom else rp_dom)

    # Received hops (newest first in headers) -> compute delays
    hops = []
    for rcv in msg.get_all("Received", []) or []:
        when = rcv.rsplit(";", 1)[-1].strip() if ";" in rcv else ""
        try:
            ts = email.utils.parsedate_to_datetime(when)
        except Exception:
            ts = None
        by = re.search(r"\bby\s+([^\s;]+)", rcv)
        frm = re.search(r"\bfrom\s+([^\s;]+)", rcv)
        hops.append({"from": frm.group(1) if frm else "", "by": by.group(1) if by else "", "time": ts.isoformat() if ts else None, "_ts": ts})
    hops.reverse()  # oldest first
    delays = []
    for a, b in zip(hops, hops[1:]):
        if a["_ts"] and b["_ts"]:
            delays.append({"from": a["by"], "to": b["by"], "seconds": int((b["_ts"] - a["_ts"]).total_seconds())})
    for h in hops:
        h.pop("_ts", None)

    res.data = {"from_domain": from_dom, "return_path_domain": rp_dom, "mailfrom_domain": mf_dom,
                "dkim_signatures": dkim_sigs, "verdicts": verdict, "hops": hops, "delays": delays,
                "subject": msg.get("Subject", ""), "spam_headers": {k: v for k, v in msg.items() if k.lower().startswith(("x-spam", "x-ms-exchange-organization-scl"))}}

    for mech in ("spf", "dkim", "dmarc"):
        v = verdict[mech]
        if v in {"fail", "softfail", "permerror", "temperror", "neutral", "none"}:
            sev = Severity.CRITICAL if mech == "dmarc" or v in {"fail", "permerror"} else Severity.WARNING
            res.findings.append(Finding(id=f"hdr.{mech}_{v}", severity=sev, title=f"Receiver saw {mech.upper()}={v}",
                                        detail={"spf": "The sending server isn't authorised in the sender's SPF (or SPF is broken).",
                                                "dkim": "The message wasn't signed, or the signature didn't match the published key.",
                                                "dmarc": "Neither SPF nor DKIM passed *and aligned* with the From domain."}[mech],
                                        evidence={"authentication_results": auth[:400]},
                                        fix_ids={"spf": ["fix.spf.add_include"], "dkim": ["fix.dkim.publish"], "dmarc": ["fix.dkim.publish", "fix.spf.add_include"]}[mech]))
        elif v == "pass":
            res.findings.append(Finding(id=f"hdr.{mech}_pass", severity=Severity.OK, title=f"{mech.upper()} passed at receiver"))
    if from_dom:
        org_from = org_domain(from_dom)
        if dkim_sigs and not any(org_domain(s["d"]) == org_from for s in dkim_sigs):
            res.findings.append(Finding(
                id="hdr.dkim_unaligned", severity=Severity.WARNING, title="DKIM signed by a different domain than From",
                detail=f"Signed by {', '.join(s['d'] for s in dkim_sigs)} but From is {from_dom}. DKIM can pass yet still fail "
                       "DMARC. Set up custom-domain DKIM in the sending service.", fix_ids=["fix.dkim.publish"]))
        if mf_dom and org_domain(mf_dom) != org_from:
            res.findings.append(Finding(
                id="hdr.spf_unaligned", severity=Severity.INFO, title="Envelope sender (Return-Path) differs from From",
                detail=f"SPF was checked for {mf_dom}, not {from_dom}, so SPF alone can't satisfy DMARC. DKIM alignment must carry it."))
    slow = [x for x in delays if x["seconds"] > 600]
    if slow:
        res.findings.append(Finding(id="hdr.delay", severity=Severity.WARNING,
                                    title=f"Delivery delayed {max(x['seconds'] for x in slow) // 60} min at one hop",
                                    detail="A server held the message (greylisting, queue backlog, or spam scanning).",
                                    evidence={"slow_hops": slow}))
    if not any(dkim_sigs) and verdict["dkim"] is None:
        res.findings.append(Finding(id="hdr.unsigned", severity=Severity.WARNING, title="Message has no DKIM signature",
                                    fix_ids=["fix.dkim.publish"]))
    return res


# ---------------------------------------------------------------- bounces
_BOUNCE_CODES = [
    (r"5\.1\.1|user unknown|no such user|recipient (address )?rejected|does not exist|mailbox unavailable",
     "bounce.user_unknown", Severity.CRITICAL, "Recipient address does not exist",
     "Typo in the address, or the mailbox was deleted. If it's YOUR domain receiving, the mailbox may not be created at the provider the MX points to."),
    (r"5\.2\.2|mailbox full|quota|over quota|insufficient storage",
     "bounce.mailbox_full", Severity.WARNING, "Recipient mailbox is full",
     "The receiver must delete mail or upgrade storage. Nothing is wrong with the sender."),
    (r"5\.7\.26|dmarc|unauthenticated email|not authenticated",
     "bounce.dmarc", Severity.CRITICAL, "Rejected for failing authentication (DMARC/SPF/DKIM)",
     "Gmail/Yahoo/Outlook reject unauthenticated mail. Fix SPF include and DKIM for the sending service."),
    (r"5\.7\.23|spf (check )?fail|sender policy framework|not permitted by spf|5\.7\.27",
     "bounce.spf", Severity.CRITICAL, "Rejected because SPF failed",
     "The sending server isn't listed in your SPF record."),
    (r"5\.7\.1\b|\bblocked\b|blacklist|blocklist|spamhaus|\blisted\b|poor reputation|5\.7\.606|5\.7\.708|banned",
     "bounce.blocked", Severity.CRITICAL, "Blocked by the receiver (policy or reputation)",
     "The sending IP or domain is on a blocklist or has poor reputation. Check blacklists; on shared hosting ask the provider for a clean IP."),
    (r"5\.7\.0.*relay|relay (access )?denied|relaying denied|5\.7\.54|unable to relay",
     "bounce.relay", Severity.CRITICAL, "Relay denied",
     "Your email app tried to send without logging in to SMTP, or used the wrong outgoing server. Enable 'my outgoing server requires authentication'."),
    (r"5\.7\.(57|8)|535|authentication (failed|unsuccessful|required)|invalid credentials|username and password not accepted",
     "bounce.auth", Severity.CRITICAL, "SMTP login failed",
     "Wrong password, app password needed (2FA), SMTP AUTH disabled (Microsoft 365), or IMAP/SMTP not included in the plan (Zoho free)."),
    (r"5\.3\.4|message (size|too large)|exceeds .*size|552",
     "bounce.too_large", Severity.WARNING, "Message too large",
     "Attachments exceed the receiver's limit (often 20-25 MB). Send a link instead."),
    (r"4\.\d\.\d|try again later|temporar|greylist|deferred|451|421",
     "bounce.temporary", Severity.INFO, "Temporary failure (will retry)",
     "Greylisting or a busy server. The sending server retries automatically; only worry if it persists > 24 h."),
    (r"5\.4\.(4|1)|no (mx|mail exchanger)|host (or domain name )?not found|domain not found|unrouteable",
     "bounce.no_route", Severity.CRITICAL, "Recipient domain has no working mail server",
     "The recipient domain's MX is missing or wrong (or the domain expired). If it's your domain, check MX."),
    (r"5\.5\.(1|2)|5\.5\.3|too many recipients",
     "bounce.limits", Severity.WARNING, "Sending limits exceeded",
     "Too many recipients or messages per hour. Shared hosting typically caps outgoing mail; use a bulk email service for campaigns."),
]


@tool("decode_bounce",
      "Explain a bounce / NDR / 'Mail Delivery Subsystem' message or an SMTP error string in plain English, with likely cause and fix.",
      {"text": {"type": "string", "description": "The bounce message or error text"}},
      ["text"])
def decode_bounce(ctx: Context, text: str) -> ToolResult:
    t = text.lower()
    res = ToolResult(tool="decode_bounce", target="bounce")
    codes = re.findall(r"\b([245]\.\d{1,3}\.\d{1,3})\b", text)
    basic = re.findall(r"\b([245]\d\d)[ -]", text)
    rcpt = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", text)
    res.data = {"enhanced_codes": sorted(set(codes)), "smtp_codes": sorted(set(basic)), "addresses": sorted(set(rcpt))[:5]}
    matched = False
    rules = list(_BOUNCE_CODES)
    # A 4xx-only message is temporary, whatever words it contains: check that rule first.
    all_codes = codes + basic
    if all_codes and all(c.startswith("4") for c in all_codes):
        rules.sort(key=lambda r: r[1] != "bounce.temporary")
    for pat, fid, sev, title, detail in rules:
        if re.search(pat, t):
            fix = {"bounce.spf": ["fix.spf.add_include"], "bounce.dmarc": ["fix.dkim.publish", "fix.spf.add_include"],
                   "bounce.blocked": ["fix.bl.delist"], "bounce.no_route": ["fix.mx.set"],
                   "bounce.auth": ["fix.client.settings"], "bounce.relay": ["fix.client.settings"]}.get(fid, [])
            res.findings.append(Finding(id=fid, severity=sev, title=title, detail=detail, fix_ids=fix,
                                        evidence={"codes": res.data["enhanced_codes"] or res.data["smtp_codes"]}))
            matched = True
            if sev == Severity.CRITICAL:
                break  # first critical match is the primary cause
    if not matched:
        res.findings.append(Finding(id="bounce.unrecognised", severity=Severity.UNKNOWN, title="Bounce reason not recognised",
                                    detail="No known pattern matched. Share the full bounce including the 'Diagnostic-Code' line."))
    return res


# ---------------------------------------------------------------- email clients
_CLIENT_ERRORS = [
    (r"certificate|ssl|tls|untrusted|hostname", "Use the provider's own server name (not mail.yourdomain) so the SSL certificate matches; check port/SSL pairing (993 SSL, 465 SSL, 587 STARTTLS)."),
    (r"timed? ?out|cannot connect|connection refused|unreachable", "Wrong host or port, or the network/antivirus blocks it. Try 465 vs 587 for SMTP; some ISPs block port 25."),
    (r"auth|password|login|535|credentials", "Password wrong, or provider requires an App Password (2FA on) or OAuth; on Zoho Free, IMAP/POP isn't included."),
    (r"imap|pop", "IMAP/POP may be disabled in the mailbox settings or not included in the plan."),
    (r"send|smtp|outgoing|relay", "Enable 'outgoing server requires authentication' with the same username/password as incoming."),
]


@tool("email_client_settings",
      "Give the correct IMAP/POP/SMTP settings for a mailbox (detected from MX), and explain a client error message if provided "
      "(Outlook, Apple Mail, Thunderbird, Android/iPhone).",
      {"email_or_domain": {"type": "string"}, "error_message": {"type": "string", "description": "Optional error shown by the email app"}},
      ["email_or_domain"])
def email_client_settings(ctx: Context, email_or_domain: str, error_message: str = "") -> ToolResult:
    d = norm_domain(email_or_domain)
    res = ToolResult(tool="email_client_settings", target=d)
    mx, _ = _mx_hosts(ctx, d)
    prov = match_email_provider([h for _p, h in mx])
    if not prov:
        mail_a = ctx.resolver.resolve(f"mail.{d}", "A")
        res.data = {"provider": None, "mx": [h for _p, h in mx], "mail_host_exists": bool(mail_a.records)}
        res.findings.append(Finding(
            id="client.generic", severity=Severity.INFO, title="Provider not recognised: likely cPanel/host mail",
            detail=f"Try IMAP mail.{d}:993 (SSL), SMTP mail.{d}:465 (SSL) with the full email as username. If SSL errors appear, "
                   "use the server hostname shown in the hosting panel's 'Connect devices' page instead.",
            evidence={"mx": [h for _p, h in mx]}, fix_ids=["fix.client.settings"]))
    else:
        s = CLIENT_SETTINGS.get(prov[0])
        if prov[0] in {"improvmx", "cloudflare_routing"}:
            res.findings.append(Finding(id="client.no_mailbox", severity=Severity.WARNING, title=f"{prov[1]} has no mailbox to connect to",
                                        detail="Forwarding services can't be added to Outlook/IMAP. Read mail in the destination inbox."))
        elif s:
            fmt = lambda x: f"{x[0].replace('<domain>', d)}:{x[1]} ({x[2]})" if x else "not available"
            res.data = {"provider": prov[1], "imap": fmt(s["imap"]), "smtp": fmt(s["smtp"]), "pop": fmt(s.get("pop")), "note": s["note"]}
            res.findings.append(Finding(id="client.settings", severity=Severity.INFO, title=f"{prov[1]} settings",
                                        detail=f"IMAP {res.data['imap']}; SMTP {res.data['smtp']}; username = full email address. {s['note']}",
                                        evidence=res.data, fix_ids=["fix.client.settings"]))
    if error_message:
        tips = [tip for pat, tip in _CLIENT_ERRORS if re.search(pat, error_message.lower())]
        res.findings.append(Finding(id="client.error_explained", severity=Severity.WARNING, title="Likely cause of the app error",
                                    detail=" ".join(tips) or "Not a known pattern; confirm host, port, SSL type and password.",
                                    evidence={"error": error_message}))
    return res
