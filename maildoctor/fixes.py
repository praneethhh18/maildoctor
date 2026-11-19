"""Fix planner: turn findings into concrete, copy-pasteable DNS changes and steps.

Deterministic on purpose. An LLM may *choose and explain* fixes, but the record
values themselves are computed by code, so they are never hallucinated
(e.g. we never invent a DKIM key; we tell the user where to generate it).

Key safety rule implemented here: never add a second SPF record. Always merge
into the existing one.
"""

from __future__ import annotations

from typing import Callable

from .models import DnsChange, Finding, FixPlan
from .providers import EMAIL_PROVIDERS, email_provider_info, match_dns_provider, match_email_provider
from .tools.base import Context, norm_domain
from .tools.email_auth import _mx_hosts, _spf_records

# Official MX values per provider (keep in sync with provider docs)
PROVIDER_MX = {
    "google": [(1, "smtp.google.com")],
    "zoho": [(10, "mx.zoho.in"), (20, "mx2.zoho.in"), (50, "mx3.zoho.in")],
    "titan": [(10, "mx1.titan.email"), (20, "mx2.titan.email")],
    "hostinger": [(5, "mx1.hostinger.com"), (10, "mx2.hostinger.com")],
    "protonmail": [(10, "mail.protonmail.ch"), (20, "mailsec.protonmail.ch")],
    "fastmail": [(10, "in1-smtp.messagingengine.com"), (20, "in2-smtp.messagingengine.com")],
    "improvmx": [(10, "mx1.improvmx.com"), (20, "mx2.improvmx.com")],
}

DKIM_WHERE = {
    "google": "Google Admin console > Apps > Google Workspace > Gmail > Authenticate email > Generate new record, publish TXT at google._domainkey, then click 'Start authentication'.",
    "microsoft": "Microsoft Defender portal > Email & collaboration > Policies > DKIM: publish the two CNAMEs selector1._domainkey and selector2._domainkey, then Enable.",
    "zoho": "Zoho Mail Admin Console > Domains > your domain > Email Configuration > DKIM > Add selector, publish TXT at <selector>._domainkey, click Verify, then turn the DKIM status toggle ON.",
    "titan": "Titan control panel > Domain settings > DKIM: copy the TXT record, publish it, and verify.",
    "hostinger": "hPanel > Emails > your domain > DNS settings: publish the DKIM TXT records shown, then verify.",
    "godaddy": "GoDaddy email is usually Microsoft 365: use the Microsoft 365 DKIM steps or GoDaddy's Email & Office dashboard.",
}


def _dns_panel_hint(ctx: Context, d: str) -> str:
    ns = ctx.resolver.resolve(d, "NS").records
    p = match_dns_provider(ns)
    if not p:
        return "Make the change wherever the domain's DNS is hosted (the provider of its nameservers)."
    hints = {
        "cloudflare": "Cloudflare dashboard > your domain > DNS > Records. Mail records (MX/TXT) are never proxied; keep them 'DNS only'.",
        "godaddy": "GoDaddy > My Products > Domain > DNS > Manage DNS.",
        "hostinger": "hPanel > Domains > your domain > DNS / Nameservers > Manage DNS records.",
        "netsol": "Network Solutions Account Manager > My Domain Names > Manage > Advanced DNS records.",
        "namecheap": "Namecheap > Domain List > Manage > Advanced DNS.",
        "route53": "AWS console > Route 53 > Hosted zones > your domain > Create record.",
        "vercel": "Vercel > Domains > your domain > DNS records.",
    }
    return f"DNS is hosted at {p[1]}. " + hints.get(p[0], "Open that provider's DNS editor.")


def _provider(ctx: Context, d: str):
    mx, _ = _mx_hosts(ctx, d)
    return match_email_provider([h for _p, h in mx])


def _merge_spf(records: list[str], add: list[str] | None = None, drop: list[str] | None = None) -> str:
    """Merge one or more SPF records into a single valid record."""
    add, drop = add or [], drop or []
    mechs: list[str] = []
    policy = "~all"
    for rec in records:
        for t in rec.split()[1:]:
            low = t.lower()
            if low.lstrip("+-~?") == "all":
                # keep the stricter of the policies seen (-all > ~all > ?all)
                rank = {"-all": 3, "~all": 2, "?all": 1, "+all": 0, "all": 0}
                if rank.get(low, 0) > rank.get(policy, 0):
                    policy = low
                continue
            if low.startswith("redirect="):
                continue
            if any(low == f"include:{x}" for x in drop):
                continue
            if low not in (m.lower() for m in mechs):
                mechs.append(t)
    for inc in add:
        if f"include:{inc}".lower() not in (m.lower() for m in mechs):
            mechs.append(f"include:{inc}")
    if policy in {"+all", "all", "?all"}:
        policy = "~all"
    return " ".join(["v=spf1", *mechs, policy])


# ---------------------------------------------------------------- builders
def _spf_create(ctx, d):
    prov = _provider(ctx, d)
    inc = email_provider_info(prov[0]).get("spf_include") if prov else None
    val = f"v=spf1 include:{inc} ~all" if inc else "v=spf1 mx ~all"
    return FixPlan(id="fix.spf.create", title="Create an SPF record",
                   why="Tells receivers which servers may send mail for your domain.",
                   changes=[DnsChange(action="add", type="TXT", name="@", value=val)],
                   steps=[_dns_panel_hint(ctx, d), "Add one TXT record at @ (root) with the value above.",
                          "If other services send as your domain (newsletters, website forms), add their include: too, in the SAME record."])


_ZOHO_FAMILY = ("zoho.in", "zoho.com", "zohomail.in", "zohomail.com", "zoho.eu")


def _has_provider_include(records: list[str], prov_key: str, inc: str) -> bool:
    fam = _ZOHO_FAMILY if prov_key == "zoho" else (inc,)
    text = " ".join(records).lower()
    return any(f"include:{f}" in text for f in fam)


def _spf_merge(ctx, d):
    recs, _ = _spf_records(ctx, d)
    prov = _provider(ctx, d)
    inc = email_provider_info(prov[0]).get("spf_include") if prov else None
    need = inc and prov[0] not in {"improvmx", "cloudflare_routing"} and not _has_provider_include(recs, prov[0], inc)
    merged = _merge_spf(recs, add=[inc] if need else [])
    changes = [DnsChange(action="delete", type="TXT", name="@", replaces=r) for r in recs]
    changes.append(DnsChange(action="add", type="TXT", name="@", value=merged))
    return FixPlan(id="fix.spf.merge", title="Merge into ONE valid SPF record",
                   why="Two SPF records (or a broken one) make SPF fail for every message.",
                   changes=changes, risk="medium",
                   steps=[_dns_panel_hint(ctx, d), "Delete the old SPF TXT records, then add the single merged one.",
                          "Check that every service you send with is still listed."])


def _spf_add_include(ctx, d):
    recs, _ = _spf_records(ctx, d)
    prov = _provider(ctx, d)
    inc = email_provider_info(prov[0]).get("spf_include") if prov else None
    if not recs:
        return _spf_create(ctx, d)
    key = prov[0] if prov else ""
    drop = ["spf.improvmx.com"] if key != "improvmx" else []
    need = inc and not _has_provider_include(recs[:1], key, inc)
    new = _merge_spf(recs[:1], add=[inc] if need else [], drop=drop)
    steps = [_dns_panel_hint(ctx, d), "Edit the existing SPF record (don't add a second one)."]
    mailbox_inc = {p[3] for p in EMAIL_PROVIDERS}
    old = [t.split(":", 1)[1] for t in recs[0].split() if t.lower().startswith("include:")
           and t.split(":", 1)[1].lower() in mailbox_inc and t.split(":", 1)[1].lower() != (inc or "").lower()
           and not (key == "zoho" and "zoho" in t.lower())]
    if old:
        steps.append(f"Kept {', '.join(old)} to be safe. If nothing sends through it anymore (website forms, old hosting mail), "
                     "remove it as well.")
    return FixPlan(id="fix.spf.add_include", title=f"Authorise {prov[1] if prov else 'your mail provider'} in SPF",
                   why="Your mailbox provider sends your mail; it must be listed in SPF or messages fail SPF.",
                   changes=[DnsChange(action="update", type="TXT", name="@", value=new, replaces=recs[0])],
                   steps=steps)


def _spf_flatten(ctx, d):
    return FixPlan(id="fix.spf.flatten", title="Bring SPF under 10 DNS lookups", risk="medium",
                   why="Over 10 lookups = permerror = SPF fails for everyone.",
                   steps=["List services that really send as your domain; remove includes for ones you no longer use.",
                          "Move marketing/transactional senders to a subdomain (e.g. news.yourdomain) with its own SPF.",
                          "As a last resort, replace includes with the provider's published ip4/ip6 ranges (must be maintained when they change)."])


def _spf_policy(ctx, d):
    recs, _ = _spf_records(ctx, d)
    if not recs:
        return _spf_create(ctx, d)
    new = _merge_spf(recs[:1])
    return FixPlan(id="fix.spf.policy", title="Use a safe SPF policy (~all)", why="'+all'/'?all' give no protection.",
                   changes=[DnsChange(action="update", type="TXT", name="@", value=new, replaces=recs[0])],
                   steps=[_dns_panel_hint(ctx, d)])


def _dmarc_create(ctx, d):
    return FixPlan(id="fix.dmarc.create", title="Add a DMARC record (monitor mode)",
                   why="Protects against spoofing and is required by Gmail/Yahoo for bulk senders.",
                   changes=[DnsChange(action="add", type="TXT", name="_dmarc", value=f"v=DMARC1; p=none; rua=mailto:dmarc@{d}")],
                   steps=[_dns_panel_hint(ctx, d), f"Make sure dmarc@{d} exists (or use any mailbox you read).",
                          "After 1-2 weeks of clean reports, move to p=quarantine."])


def _dmarc_tighten(ctx, d):
    cur = ctx.resolver.resolve(f"_dmarc.{d}", "TXT").records
    cur_v = next((r for r in cur if r.lower().startswith("v=dmarc1")), "")
    new = "v=DMARC1; p=quarantine; " + "; ".join(p.strip() for p in cur_v.split(";")[1:] if p.strip() and not p.strip().lower().startswith("p="))
    return FixPlan(id="fix.dmarc.tighten", title="Move DMARC to quarantine", risk="medium",
                   why="Spoofed mail goes to spam instead of the inbox.",
                   changes=[DnsChange(action="update", type="TXT", name="_dmarc", value=new.rstrip("; "), replaces=cur_v or None)],
                   steps=["ONLY do this after SPF and DKIM pass for every service that sends as your domain; otherwise your own mail goes to spam.",
                          _dns_panel_hint(ctx, d)])


def _dmarc_add_rua(ctx, d):
    cur = ctx.resolver.resolve(f"_dmarc.{d}", "TXT").records
    cur_v = next((r for r in cur if r.lower().startswith("v=dmarc1")), "v=DMARC1; p=none")
    new = cur_v.rstrip("; ") + f"; rua=mailto:dmarc@{d}"
    return FixPlan(id="fix.dmarc.add_rua", title="Send DMARC reports to a mailbox",
                   why="Reports show who is sending mail as your domain.",
                   changes=[DnsChange(action="update", type="TXT", name="_dmarc", value=new, replaces=cur_v)],
                   steps=[_dns_panel_hint(ctx, d)])


def _dkim_publish(ctx, d):
    prov = _provider(ctx, d)
    where = DKIM_WHERE.get(prov[0]) if prov else None
    sel = email_provider_info(prov[0]).get("dkim_selectors", ["<selector>"])[:1] if prov else ["<selector>"]
    return FixPlan(id="fix.dkim.publish", title="Publish and activate DKIM",
                   why="DKIM signs your mail so receivers can trust it; required for DMARC alignment with most providers.",
                   steps=[where or "Generate a DKIM key in your email/sending provider's admin panel.",
                          f"Publish it as TXT at {sel[0]}._domainkey (value comes from the provider; never invent it).",
                          _dns_panel_hint(ctx, d),
                          "Wait for DNS (minutes to an hour), click Verify/Enable in the provider, then send a test and check 'dkim=pass' in the headers."])


def _mx_set(ctx, d):
    prov = _provider(ctx, d)
    vals = PROVIDER_MX.get(prov[0]) if prov else None
    changes = [DnsChange(action="add", type="MX", name="@", value=h, priority=p) for p, h in vals] if vals else []
    steps = [_dns_panel_hint(ctx, d)]
    if prov and prov[0] == "microsoft":
        steps.append(f"Microsoft 365 MX is <tenant-domain>.mail.protection.outlook.com (shown in M365 admin > Settings > Domains).")
    if not vals:
        steps.append("Copy the exact MX values from your email provider's setup page.")
    return FixPlan(id="fix.mx.set", title="Point MX to your email provider", why="MX decides where incoming mail is delivered.",
                   changes=changes, steps=steps, risk="high",
                   reversible=True)


def _mx_remove_conflict(ctx, d):
    mx, _ = _mx_hosts(ctx, d)
    primary = match_email_provider([mx[0][1]]) if mx else None
    keep_key = primary[0] if primary else None
    changes = []
    for p, h in mx:
        m = match_email_provider([h])
        if keep_key and (m is None or m[0] != keep_key):
            changes.append(DnsChange(action="delete", type="MX", name="@", value=h, priority=p, replaces=f"{p} {h}"))
    return FixPlan(id="fix.mx.remove_conflict", title=f"Keep only {primary[1] if primary else 'one provider'}'s MX records",
                   why="Mixed MX records split incoming mail between providers.", changes=changes, risk="high",
                   steps=["Confirm which provider actually hosts the mailboxes BEFORE deleting anything.", _dns_panel_hint(ctx, d)])


def _simple(fid, title, why, steps, risk="low"):
    return lambda ctx, d: FixPlan(id=fid, title=title, why=why, steps=[s.replace("{d}", d) for s in steps], risk=risk)


FIXES: dict[str, Callable[[Context, str], FixPlan]] = {
    "fix.spf.create": _spf_create,
    "fix.spf.merge": _spf_merge,
    "fix.spf.add_include": _spf_add_include,
    "fix.spf.flatten": _spf_flatten,
    "fix.spf.policy": _spf_policy,
    "fix.dmarc.create": _dmarc_create,
    "fix.dmarc.tighten": _dmarc_tighten,
    "fix.dmarc.add_rua": _dmarc_add_rua,
    "fix.dkim.publish": _dkim_publish,
    "fix.mx.set": _mx_set,
    "fix.mx.remove_conflict": _mx_remove_conflict,
    "fix.web.point_dns": _simple("fix.web.point_dns", "Point the domain to your website host",
                                 "Visitors need an A/AAAA (or flattened CNAME) record to reach the site.",
                                 ["Find the IP or target in your hosting panel ('Connect domain').",
                                  "Add/replace the A record at @ and a CNAME for www.",
                                  "If the host uses its own nameservers, change nameservers at the registrar instead (this moves ALL DNS, including email records)."], "medium"),
    "fix.web.www_cname": _simple("fix.web.www_cname", "Add www", "Many visitors type www.", ["Add CNAME www -> {d} (or your host's target)."]),
    "fix.ssl.reissue": _simple("fix.ssl.reissue", "Re-issue the SSL certificate", "Browsers block sites with invalid SSL.",
                               ["In the hosting panel, run AutoSSL / Let's Encrypt for {d} and www.{d}.",
                                "If DNS points elsewhere (e.g. Cloudflare proxy), the host can't validate: use Cloudflare SSL mode 'Full' and an origin certificate."]),
    "fix.domain.renew_or_unhold": _simple("fix.domain.renew_or_unhold", "Renew / remove hold at the registrar",
                                          "An expired or held domain takes down website and email.",
                                          ["Log in to the registrar, renew the domain and enable auto-renew.",
                                           "If status is clientHold, verify the registrant email (ICANN verification) or clear the billing/abuse issue.",
                                           "DNS returns within minutes to a few hours after the hold is lifted."], "medium"),
    "fix.bl.delist": _simple("fix.bl.delist", "Get delisted", "Blocklisted IPs/domains get rejected.",
                             ["Find and stop the cause first (compromised mailbox, form spam, bulk mail from shared hosting).",
                              "Request removal on each list's lookup page (Spamhaus, Barracuda, SpamCop).",
                              "On shared hosting, ask the provider to delist or move you to a clean IP."], "medium"),
    "fix.client.settings": _simple("fix.client.settings", "Fix the email app settings", "Most client errors are host/port/SSL/password mismatches.",
                                   ["Remove the account from the app and add it again manually with the IMAP/SMTP values shown.",
                                    "Username = full email address. Turn on 'outgoing server requires authentication'.",
                                    "If 2FA is on, create an App Password; for Microsoft 365 use an app that supports Modern Auth."]),
}


def build_fixes(ctx: Context, domain: str, findings: list[Finding]) -> list[FixPlan]:
    d = norm_domain(domain)
    seen, plans = set(), []
    order = sorted(findings, key=lambda f: {"critical": 0, "warning": 1, "unknown": 2, "info": 3, "ok": 4}[f.severity.value])
    for f in order:
        for fid in f.fix_ids:
            if fid in seen or fid not in FIXES:
                continue
            seen.add(fid)
            try:
                plans.append(FIXES[fid](ctx, d))
            except Exception as e:  # pragma: no cover
                plans.append(FixPlan(id=fid, title=fid, why=f"Could not build plan: {e}"))
    # never offer two SPF-changing plans at once: merge supersedes the others
    if "fix.spf.merge" in seen:
        plans = [p for p in plans if p.id not in {"fix.spf.add_include", "fix.spf.policy"}]
    return plans
