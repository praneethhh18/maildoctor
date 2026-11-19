"""Email routing and authentication checks: overview, MX, SPF, DKIM, DMARC.

Each function is deterministic: same DNS answers in -> same findings out.
Read docs/LEARN.md section 3 for what SPF, DKIM and DMARC actually do.
"""

from __future__ import annotations

import base64
import re

from ..dnsclient import ERROR, NXDOMAIN, OK
from ..models import Finding, Severity, ToolResult
from ..providers import (
    EMAIL_PROVIDERS,
    SENDER_SELECTORS,
    SPF_INCLUDE_HINTS,
    email_provider_info,
    match_dns_provider,
    match_email_provider,
    match_hosting,
)
from .base import DOMAIN_PARAM, Context, norm_domain, run_tool, tool

# Two-level public suffixes common for Indian/UK/AU customers (tiny built-in list).
_TWO_LEVEL = {"co.in", "org.in", "net.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in",
              "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "com.sg", "com.my"}


def org_domain(d: str) -> str:
    parts = d.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def _mx_hosts(ctx: Context, domain: str) -> tuple[list[tuple[int, str]], str]:
    a = ctx.resolver.resolve(domain, "MX")
    out = []
    for r in a.records:
        pr, _, host = r.partition(" ")
        try:
            out.append((int(pr), host.strip().rstrip(".").lower()))
        except ValueError:
            continue
    return sorted(out), a.status


# ---------------------------------------------------------------- overview
@tool("dns_overview",
      "First look at a domain: does it exist, who hosts its DNS, email and website. "
      "Call this first for almost any problem.",
      DOMAIN_PARAM, ["domain"])
def dns_overview(ctx: Context, domain: str) -> ToolResult:
    d = norm_domain(domain)
    r = ctx.resolver
    res = ToolResult(tool="dns_overview", target=d)
    ns = r.resolve(d, "NS")
    soa = r.resolve(d, "SOA")
    a = r.resolve(d, "A")
    aaaa = r.resolve(d, "AAAA")
    mx, mx_status = _mx_hosts(ctx, d)
    www_cname = r.resolve(f"www.{d}", "CNAME")
    www_a = r.resolve(f"www.{d}", "A")
    apex_cname = r.resolve(d, "CNAME")

    res.data = {
        "nameservers": ns.records, "soa": soa.records[:1], "a": a.records, "aaaa": aaaa.records,
        "mx": [f"{p} {h}" for p, h in mx], "www_cname": www_cname.records, "www_a": www_a.records,
    }

    if ns.status == NXDOMAIN and soa.status == NXDOMAIN:
        res.findings.append(Finding(
            id="domain.nxdomain", severity=Severity.CRITICAL, title="Domain does not resolve at all",
            detail="DNS says this domain does not exist. It may be misspelled, expired, suspended (clientHold) "
                   "or never registered. Check registration status next.",
            evidence={"ns": ns.status, "soa": soa.status}, fix_ids=["fix.domain.renew_or_unhold"]))
        return res
    if ns.status == ERROR:
        res.findings.append(Finding(id="dns.lookup_error", severity=Severity.UNKNOWN,
                                    title="DNS lookup failed", detail=f"Could not query nameservers ({ns.error}).",
                                    evidence={"error": ns.error}))

    dnsp = match_dns_provider(ns.records)
    res.data["dns_provider"] = dnsp[1] if dnsp else (ns.records[0] if ns.records else None)
    emailp = match_email_provider([h for _p, h in mx])
    res.data["email_provider"] = emailp[1] if emailp else None
    res.data["email_provider_key"] = emailp[0] if emailp else None
    hosting = match_hosting(www_cname.records + apex_cname.records, a.records + www_a.records)
    res.data["website_host"] = hosting

    res.findings.append(Finding(
        id="overview.providers", severity=Severity.INFO, title="Who runs what",
        detail=(f"DNS managed at: {res.data['dns_provider'] or 'unknown'}. "
                f"Email handled by: {res.data['email_provider'] or ('custom/unknown MX' if mx else 'nobody (no MX)')}. "
                f"Website hosted at: {hosting or ('server ' + ', '.join(a.records) if a.records else 'nowhere (no A record)')}."),
        evidence={"ns": ns.records, "mx": res.data["mx"], "a": a.records}))

    if len(ns.records) == 1:
        res.findings.append(Finding(id="dns.single_ns", severity=Severity.WARNING, title="Only one nameserver",
                                    detail="A single nameserver is a single point of failure. Most providers give at least two.",
                                    evidence={"ns": ns.records}))
    return res


# ---------------------------------------------------------------- MX
@tool("check_mx",
      "Check where the domain receives email (MX records): missing MX, mixed providers, broken targets.",
      DOMAIN_PARAM, ["domain"])
def check_mx(ctx: Context, domain: str) -> ToolResult:
    d = norm_domain(domain)
    res = ToolResult(tool="check_mx", target=d)
    mx, status = _mx_hosts(ctx, d)
    res.data["mx"] = [f"{p} {h}" for p, h in mx]
    if status == ERROR:
        res.findings.append(Finding(id="mx.lookup_error", severity=Severity.UNKNOWN, title="Could not look up MX"))
        return res
    if not mx:
        res.findings.append(Finding(
            id="mx.missing", severity=Severity.CRITICAL, title="No MX records: domain cannot receive email",
            detail="Senders will bounce mail with 'domain not found / no mail exchanger'. Add the MX records your email provider gives you.",
            fix_ids=["fix.mx.set"]))
        return res
    if len(mx) == 1 and mx[0][1] in {"", "."}:
        res.findings.append(Finding(id="mx.null", severity=Severity.INFO, title="Null MX: domain intentionally refuses email",
                                    detail="MX '0 .' means 'this domain never receives mail'. Fine for web-only domains, wrong if you expect email."))
        return res

    hosts = [h for _p, h in mx]
    providers = {}
    for h in hosts:
        m = match_email_provider([h])
        providers[h] = m[0] if m else "unknown"
    distinct = {v for v in providers.values() if v != "unknown"}
    res.data["providers"] = providers
    prov = match_email_provider(hosts)
    res.data["email_provider"] = prov[1] if prov else None
    res.data["email_provider_key"] = prov[0] if prov else None

    if len(distinct) > 1:
        res.findings.append(Finding(
            id="mx.mixed_providers", severity=Severity.CRITICAL, title="MX records point to different email providers",
            detail="Mail is split between providers at random, so some messages land in a mailbox the user never checks. "
                   "Keep only the MX records of the provider that hosts the mailboxes.",
            evidence={"providers": providers}, fix_ids=["fix.mx.remove_conflict"]))

    for p, h in mx:
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", h):
            res.findings.append(Finding(id="mx.ip_literal", severity=Severity.CRITICAL,
                                        title=f"MX points to an IP address ({h})",
                                        detail="MX must point to a hostname, not an IP. Many servers will refuse to deliver.",
                                        fix_ids=["fix.mx.set"]))
            continue
        ha = ctx.resolver.resolve(h, "A")
        h6 = ctx.resolver.resolve(h, "AAAA")
        if ha.status != ERROR and not ha.records and not h6.records:
            res.findings.append(Finding(id="mx.target_unresolvable", severity=Severity.CRITICAL,
                                        title=f"MX host {h} has no IP address",
                                        detail="The mail server named in MX does not exist in DNS, so delivery to it fails.",
                                        evidence={"host": h}, fix_ids=["fix.mx.set"]))
        hc = ctx.resolver.resolve(h, "CNAME")
        if hc.records:
            res.findings.append(Finding(id="mx.cname_target", severity=Severity.WARNING,
                                        title=f"MX host {h} is a CNAME",
                                        detail="RFC 2181 forbids MX targets that are aliases; some senders reject them."))

    if prov and prov[0] in {"improvmx", "cloudflare_routing"}:
        res.findings.append(Finding(
            id="mx.forwarding_only", severity=Severity.INFO, title=f"Email is forwarded by {prov[1]}",
            detail="There is no real mailbox; messages are forwarded elsewhere. Replies 'from' this domain need a separate sending service."))
    if not any(f.severity in {Severity.CRITICAL, Severity.WARNING} for f in res.findings):
        res.findings.append(Finding(id="mx.ok", severity=Severity.OK,
                                    title=f"MX OK{(' (' + prov[1] + ')') if prov else ''}", evidence={"mx": res.data["mx"]}))
    return res


# ---------------------------------------------------------------- SPF
_LOOKUP_MECHS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def _spf_records(ctx: Context, d: str) -> tuple[list[str], str]:
    a = ctx.resolver.resolve(d, "TXT")
    return [t for t in a.records if t.lower().startswith("v=spf1")], a.status


def _count_lookups(ctx: Context, d: str, depth: int, seen: set[str], stats: dict) -> None:
    """Walk an SPF record tree, counting DNS-querying terms (RFC 7208 limit: 10)."""
    if depth > 10 or d in seen:
        stats["loops"] = True
        return
    seen.add(d)
    recs, status = _spf_records(ctx, d)
    if not recs:
        stats["void"] += 1
        stats["broken_includes"].append(d)
        return
    for term in recs[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:"):
            stats["lookups"] += 1
            _count_lookups(ctx, t.split(":", 1)[1], depth + 1, seen, stats)
        elif t.startswith("redirect="):
            stats["lookups"] += 1
            _count_lookups(ctx, t.split("=", 1)[1], depth + 1, seen, stats)
        elif t in {"a", "mx", "ptr"} or t.startswith(("a:", "mx:", "a/", "mx/", "ptr:", "exists:")):
            stats["lookups"] += 1


@tool("check_spf",
      "Check the SPF record (which servers may send email for the domain): missing, duplicates, syntax, "
      "the 10-DNS-lookup limit, too-permissive policy, and whether the current email provider is authorised.",
      DOMAIN_PARAM, ["domain"])
def check_spf(ctx: Context, domain: str) -> ToolResult:
    d = norm_domain(domain)
    res = ToolResult(tool="check_spf", target=d)
    recs, status = _spf_records(ctx, d)
    res.data["records"] = recs
    if status == ERROR:
        res.findings.append(Finding(id="spf.lookup_error", severity=Severity.UNKNOWN, title="Could not look up SPF"))
        return res
    mx, _ = _mx_hosts(ctx, d)
    prov = match_email_provider([h for _p, h in mx])
    pinfo = email_provider_info(prov[0]) if prov else {}

    if not recs:
        res.findings.append(Finding(
            id="spf.missing", severity=Severity.CRITICAL, title="No SPF record",
            detail="Receivers cannot tell which servers may send for this domain, so mail is more likely to go to spam "
                   "and anyone can spoof it. Gmail/Yahoo require SPF or DKIM for bulk senders.",
            evidence={"email_provider": prov[1] if prov else None}, fix_ids=["fix.spf.create"]))
        return res
    if len(recs) > 1:
        res.findings.append(Finding(
            id="spf.multiple", severity=Severity.CRITICAL, title=f"{len(recs)} SPF records found (only one allowed)",
            detail="Two 'v=spf1' TXT records make SPF fail completely (permerror). This usually happens when a new "
                   "email service is added without editing the existing record. Merge them into one.",
            evidence={"records": recs}, fix_ids=["fix.spf.merge"]))
    rec = recs[0]
    terms = rec.split()
    res.data["record"] = rec

    # Policy
    last = terms[-1].lower() if terms else ""
    if last in {"+all", "all"}:
        res.findings.append(Finding(id="spf.pass_all", severity=Severity.CRITICAL, title="SPF ends with +all (anyone may send)",
                                    detail="'+all' authorises every server on the internet; it is worse than no SPF.",
                                    fix_ids=["fix.spf.policy"]))
    elif last == "?all":
        res.findings.append(Finding(id="spf.neutral_all", severity=Severity.WARNING, title="SPF ends with ?all (no protection)",
                                    detail="'?all' tells receivers nothing. Use ~all (soft fail) or -all (hard fail).",
                                    fix_ids=["fix.spf.policy"]))
    elif not any(t.lower().lstrip("+-~?") == "all" or t.lower().startswith("redirect=") for t in terms):
        res.findings.append(Finding(id="spf.no_all", severity=Severity.WARNING, title="SPF has no 'all' mechanism",
                                    detail="Without ~all or -all the record does not say what to do with other senders.",
                                    fix_ids=["fix.spf.policy"]))

    # Syntax
    bad = [t for t in terms[1:] if not re.match(r"^[+\-~?]?(all|include:|a\b|a:|a/|mx\b|mx:|mx/|ip4:|ip6:|ptr|exists:|redirect=|exp=)", t.lower())]
    if bad:
        res.findings.append(Finding(id="spf.syntax", severity=Severity.CRITICAL, title="SPF has invalid terms",
                                    detail=f"Unrecognised terms: {', '.join(bad)}. One typo breaks the whole record.",
                                    evidence={"bad_terms": bad}, fix_ids=["fix.spf.merge"]))
    if any(t.lower().lstrip("+-~?").startswith("ptr") for t in terms):
        res.findings.append(Finding(id="spf.ptr", severity=Severity.WARNING, title="SPF uses deprecated 'ptr'",
                                    detail="'ptr' is slow and discouraged by RFC 7208; some receivers ignore it."))

    # Lookup limit
    stats = {"lookups": 0, "void": 0, "loops": False, "broken_includes": []}
    for t in terms[1:]:
        tt = t.lstrip("+-~?").lower()
        if tt.startswith(("include:", "redirect=")):
            stats["lookups"] += 1
            _count_lookups(ctx, tt.split(":", 1)[1] if ":" in tt else tt.split("=", 1)[1], 1, {d}, stats)
        elif tt in {"a", "mx", "ptr"} or tt.startswith(("a:", "mx:", "a/", "mx/", "exists:")):
            stats["lookups"] += 1
    res.data["dns_lookups"] = stats["lookups"]
    if stats["lookups"] > 10:
        res.findings.append(Finding(
            id="spf.too_many_lookups", severity=Severity.CRITICAL,
            title=f"SPF needs {stats['lookups']} DNS lookups (limit is 10)",
            detail="Receivers stop at 10 lookups and treat SPF as failed (permerror), so legitimate mail fails SPF. "
                   "Remove unused services or replace includes with ip4/ip6 ranges (flattening).",
            evidence=stats, fix_ids=["fix.spf.flatten"]))
    elif stats["lookups"] >= 8:
        res.findings.append(Finding(id="spf.near_limit", severity=Severity.WARNING,
                                    title=f"SPF uses {stats['lookups']}/10 DNS lookups",
                                    detail="Adding one more service may push it over the limit."))
    if stats["broken_includes"]:
        res.findings.append(Finding(id="spf.broken_include", severity=Severity.CRITICAL,
                                    title="SPF includes a domain with no SPF record",
                                    detail=f"These includes do not resolve to SPF: {', '.join(stats['broken_includes'])}. "
                                           "That makes the whole SPF check error out.",
                                    evidence=stats, fix_ids=["fix.spf.merge"]))

    # Provider authorised?
    includes = [t.lstrip("+-~?").lower().split(":", 1)[1] for t in terms if t.lstrip("+-~?").lower().startswith("include:")]
    res.data["authorised_services"] = sorted({SPF_INCLUDE_HINTS.get(i, i) for i in includes})
    if pinfo and pinfo.get("spf_include") and prov[0] not in {"improvmx", "cloudflare_routing"}:
        fam = [pinfo["spf_include"]]
        if prov[0] == "zoho":
            fam = ["zoho.in", "zoho.com", "zohomail.in", "zohomail.com", "zoho.eu"]
        if not any(any(i == f or i.endswith("." + f) for f in fam) for i in includes):
            res.findings.append(Finding(
                id="spf.provider_missing", severity=Severity.CRITICAL,
                title=f"SPF does not authorise your email provider ({prov[1]})",
                detail=f"Your MX shows {prov[1]} hosts the mailboxes, but SPF doesn't include it. Mail you send will fail SPF "
                       "and likely land in spam. This often happens after switching email providers.",
                evidence={"includes": includes, "expected": pinfo["spf_include"]}, fix_ids=["fix.spf.add_include"]))
    # Includes belonging to a *mailbox* provider other than the one MX points to are probably leftovers.
    mailbox_includes = {p[3]: p[0] for p in EMAIL_PROVIDERS}
    stale = [i for i in includes if prov and i in mailbox_includes and mailbox_includes[i] != prov[0]
             and not (prov[0] == "zoho" and "zoho" in i)]
    res.data["probably_stale_includes"] = stale
    if stale:
        res.findings.append(Finding(id="spf.stale_include", severity=Severity.INFO,
                                    title="SPF still authorises an old email provider",
                                    detail=f"{', '.join(stale)} is in SPF but MX no longer points there. Remove it unless something "
                                           "(website forms, hosting mail) still sends through it; fewer includes = safer SPF."))
    if not any(f.severity in {Severity.CRITICAL, Severity.WARNING} for f in res.findings):
        res.findings.append(Finding(id="spf.ok", severity=Severity.OK, title="SPF OK", evidence={"record": rec}))
    return res


# ---------------------------------------------------------------- DKIM
def _dkim_key_bits(p: str) -> int | None:
    try:
        n = len(base64.b64decode(p + "=" * (-len(p) % 4), validate=True))
    except Exception:
        return None
    # Approximate RSA SPKI sizes: 1024-bit ~162 bytes, 2048-bit ~294 bytes
    if n < 100:
        return 512
    if n < 200:
        return 1024
    if n < 330:
        return 2048
    return 4096


@tool("check_dkim",
      "Check DKIM signing keys. Probes the selectors your email provider and common sending services use. "
      "Pass extra selectors if you know them (e.g. from an email header 's=' tag).",
      {**DOMAIN_PARAM, "selectors": {"type": "array", "items": {"type": "string"},
                                     "description": "Optional DKIM selectors to check, e.g. ['google','zmail']"}},
      ["domain"])
def check_dkim(ctx: Context, domain: str, selectors: list[str] | None = None) -> ToolResult:
    d = norm_domain(domain)
    res = ToolResult(tool="check_dkim", target=d)
    mx, _ = _mx_hosts(ctx, d)
    prov = match_email_provider([h for _p, h in mx])
    expected = email_provider_info(prov[0]).get("dkim_selectors", []) if prov else []
    probe = list(dict.fromkeys((selectors or []) + expected + SENDER_SELECTORS))
    found: dict[str, dict] = {}
    errors = 0
    for sel in probe:
        a = ctx.resolver.resolve(f"{sel}._domainkey.{d}", "TXT")
        if a.status == ERROR:
            errors += 1
            continue
        recs = [t for t in a.records if "p=" in t.replace(" ", "")]
        if not recs:
            continue
        rec = recs[0]
        tags = dict(kv.strip().split("=", 1) for kv in rec.split(";") if "=" in kv)
        p = tags.get("p", "").replace(" ", "")
        info = {"record": rec[:90] + ("…" if len(rec) > 90 else ""), "bits": _dkim_key_bits(p) if p else None,
                "revoked": p == "", "valid_base64": _dkim_key_bits(p) is not None if p else False}
        found[sel] = info
    res.data = {"selectors_found": found, "selectors_probed": len(probe), "email_provider": prov[1] if prov else None}

    if errors and not found:
        res.findings.append(Finding(id="dkim.lookup_error", severity=Severity.UNKNOWN, title="DKIM lookups failed"))
        return res
    for sel, info in found.items():
        if info["revoked"]:
            res.findings.append(Finding(id="dkim.revoked", severity=Severity.WARNING, title=f"DKIM key '{sel}' is empty (revoked)",
                                        detail="An empty p= means the key was deliberately revoked. Mail signed with it fails DKIM."))
        elif not info["valid_base64"]:
            res.findings.append(Finding(
                id="dkim.malformed", severity=Severity.CRITICAL, title=f"DKIM key '{sel}' is malformed",
                detail="The public key isn't valid base64. Usually a copy-paste error, stray quotes/spaces, or a 2048-bit key "
                       "split wrongly in the DNS panel.", evidence=info, fix_ids=["fix.dkim.publish"]))
        elif info["bits"] and info["bits"] < 1024:
            res.findings.append(Finding(id="dkim.weak_key", severity=Severity.WARNING, title=f"DKIM key '{sel}' is only {info['bits']}-bit",
                                        detail="Keys under 1024 bits are rejected by major receivers. Rotate to 2048-bit."))

    missing_expected = [s for s in expected if s not in found]
    if prov and expected and missing_expected and not any(s in found for s in expected):
        res.findings.append(Finding(
            id="dkim.provider_missing", severity=Severity.CRITICAL,
            title=f"No DKIM key for your email provider ({prov[1]})",
            detail=f"Expected a key at one of: {', '.join(s + '._domainkey' for s in expected)}. Without DKIM, your mail "
                   f"is unsigned; with a strict DMARC policy it will be rejected or spammed. Generate the key in {prov[1]}'s "
                   "admin console, publish the TXT record, then click Verify there.",
            evidence={"probed": expected}, fix_ids=["fix.dkim.publish"]))
    if not found and not prov:
        res.findings.append(Finding(id="dkim.none_found", severity=Severity.WARNING, title="No DKIM keys found on common selectors",
                                    detail="Could not find a DKIM key. If you know your selector (from an email header 's=' tag), re-run with it."))
    if found and not any(f.severity in {Severity.CRITICAL, Severity.WARNING} for f in res.findings):
        res.findings.append(Finding(id="dkim.ok", severity=Severity.OK,
                                    title=f"DKIM key(s) published: {', '.join(found)}", evidence={"selectors": list(found)}))
    res.findings.append(Finding(
        id="dkim.limits", severity=Severity.INFO, title="DKIM publication ≠ DKIM signing",
        detail="Public DNS shows the key exists. Whether the provider actually signs outgoing mail with it must be confirmed "
               "from a real message header (analyze_headers) or the provider's admin console (e.g. Zoho/Google 'Verify/Start authentication')."))
    return res


# ---------------------------------------------------------------- DMARC
def _parse_dmarc(rec: str) -> dict[str, str]:
    return {k.strip().lower(): v.strip() for k, v in (kv.split("=", 1) for kv in rec.split(";") if "=" in kv)}


@tool("check_dmarc",
      "Check the DMARC policy (what receivers do with mail that fails SPF/DKIM alignment, and where reports go).",
      DOMAIN_PARAM, ["domain"])
def check_dmarc(ctx: Context, domain: str) -> ToolResult:
    d = norm_domain(domain)
    res = ToolResult(tool="check_dmarc", target=d)
    a = ctx.resolver.resolve(f"_dmarc.{d}", "TXT")
    recs = [t for t in a.records if t.lower().replace(" ", "").startswith("v=dmarc1")]
    source = d
    if not recs and a.status != ERROR and org_domain(d) != d:
        b = ctx.resolver.resolve(f"_dmarc.{org_domain(d)}", "TXT")
        recs = [t for t in b.records if t.lower().replace(" ", "").startswith("v=dmarc1")]
        source = org_domain(d)
    res.data = {"records": recs, "policy_source": source}
    if a.status == ERROR:
        res.findings.append(Finding(id="dmarc.lookup_error", severity=Severity.UNKNOWN, title="Could not look up DMARC"))
        return res
    if not recs:
        res.findings.append(Finding(
            id="dmarc.missing", severity=Severity.WARNING, title="No DMARC record",
            detail="Without DMARC anyone can spoof your domain, and Gmail/Yahoo now require DMARC for bulk senders. "
                   "Start with p=none plus a report address, then tighten.", fix_ids=["fix.dmarc.create"]))
        return res
    if len(recs) > 1:
        res.findings.append(Finding(id="dmarc.multiple", severity=Severity.CRITICAL, title="Multiple DMARC records",
                                    detail="More than one DMARC record means receivers ignore DMARC entirely. Keep one.",
                                    evidence={"records": recs}, fix_ids=["fix.dmarc.create"]))
    tags = _parse_dmarc(recs[0])
    res.data["tags"] = tags
    p = tags.get("p", "").lower()
    if p not in {"none", "quarantine", "reject"}:
        res.findings.append(Finding(id="dmarc.invalid_policy", severity=Severity.CRITICAL, title="DMARC policy (p=) missing or invalid",
                                    detail=f"p='{p}'. The record is ignored without a valid p= tag.", fix_ids=["fix.dmarc.create"]))
    elif p == "none":
        res.findings.append(Finding(id="dmarc.monitor_only", severity=Severity.INFO, title="DMARC is monitor-only (p=none)",
                                    detail="Spoofed mail is still delivered. Once SPF and DKIM pass for all your senders, move to quarantine.",
                                    fix_ids=["fix.dmarc.tighten"]))
    if "rua" not in tags:
        res.findings.append(Finding(id="dmarc.no_reports", severity=Severity.WARNING, title="DMARC has no report address (rua)",
                                    detail="You get no visibility into who sends mail as your domain. Add rua=mailto:you@yourdomain.",
                                    fix_ids=["fix.dmarc.add_rua"]))
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and p in {"quarantine", "reject"}:
        res.findings.append(Finding(id="dmarc.partial_pct", severity=Severity.INFO, title=f"DMARC applies to only {pct}% of failing mail"))
    if not any(f.severity in {Severity.CRITICAL, Severity.WARNING} for f in res.findings):
        res.findings.append(Finding(id="dmarc.ok", severity=Severity.OK, title=f"DMARC present (p={p})", evidence=tags))
    return res


@tool("check_email_auth_all",
      "Convenience: run MX, SPF, DKIM and DMARC checks together and return the combined findings.",
      DOMAIN_PARAM, ["domain"])
def check_email_auth_all(ctx: Context, domain: str) -> ToolResult:
    d = norm_domain(domain)
    out = ToolResult(tool="check_email_auth_all", target=d)
    for name in ("check_mx", "check_spf", "check_dkim", "check_dmarc"):
        r = run_tool(ctx, name, {"domain": d})
        out.findings.extend(r.findings)
        out.data[name] = r.data
    return out


__all__ = ["dns_overview", "check_mx", "check_spf", "check_dkim", "check_dmarc", "org_domain", "EMAIL_PROVIDERS"]
