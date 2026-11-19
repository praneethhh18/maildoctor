"""Website, SSL, domain registration and reputation checks."""

from __future__ import annotations

import datetime as dt
import socket
import ssl

from ..dnsclient import ERROR
from ..models import Finding, Severity, ToolResult
from .base import DOMAIN_PARAM, Context, norm_domain, tool
from .email_auth import _mx_hosts, org_domain


def _is_private(ip: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_unspecified


# ---------------------------------------------------------------- SSL helper
def _cert_info(host: str, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    info: dict = {"host": host}
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        not_after = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        info.update({"valid": True, "expires": not_after.isoformat(),
                     "days_left": (not_after - dt.datetime.now(dt.timezone.utc)).days,
                     "issuer": issuer.get("organizationName", "")})
    except ssl.SSLCertVerificationError as e:
        info.update({"valid": False, "error": e.verify_message or str(e)})
    except Exception as e:
        info.update({"valid": None, "error": f"{type(e).__name__}: {e}"})
    return info


@tool("check_website",
      "Check whether the website loads: A/AAAA/CNAME for the domain and www, HTTP/HTTPS response, redirects, "
      "and the SSL certificate (validity, expiry, hostname mismatch).",
      DOMAIN_PARAM, ["domain"])
def check_website(ctx: Context, domain: str) -> ToolResult:
    d = norm_domain(domain)
    r = ctx.resolver
    res = ToolResult(tool="check_website", target=d)
    hosts = {}
    for h in (d, f"www.{d}"):
        a, aaaa, cn = r.resolve(h, "A"), r.resolve(h, "AAAA"), r.resolve(h, "CNAME")
        hosts[h] = {"a": a.records, "aaaa": aaaa.records, "cname": cn.records, "status": a.status}
    res.data["dns"] = hosts

    if not hosts[d]["a"] and not hosts[d]["aaaa"] and not hosts[d]["cname"]:
        res.findings.append(Finding(
            id="web.apex_no_address", severity=Severity.CRITICAL if not hosts[f"www.{d}"]["a"] else Severity.WARNING,
            title=f"{d} has no A/AAAA record",
            detail="Visitors typing the bare domain get 'site can't be reached'. Add the A record (or ALIAS/flattened "
                   "CNAME) your hosting provider gives you.", fix_ids=["fix.web.point_dns"]))
    if not hosts[f"www.{d}"]["a"] and not hosts[f"www.{d}"]["cname"]:
        res.findings.append(Finding(id="web.www_missing", severity=Severity.WARNING, title=f"www.{d} does not resolve",
                                    detail="Many people type www. Add a CNAME for www pointing to the apex or your host.",
                                    fix_ids=["fix.web.www_cname"]))
    for h, v in hosts.items():
        priv = [ip for ip in v["a"] if _is_private(ip)]
        if priv:
            res.findings.append(Finding(id="web.private_ip", severity=Severity.CRITICAL, title=f"{h} points to a private IP",
                                        detail=f"{', '.join(priv)} is not reachable from the internet.", fix_ids=["fix.web.point_dns"]))

    if ctx.offline:
        res.findings.append(Finding(id="web.http_skipped", severity=Severity.UNKNOWN, title="Live HTTP/SSL test skipped (offline mode)"))
        return res

    # HTTP(S) probes, following redirects manually so we can show the chain
    client = ctx.client()
    for scheme in ("https", "http"):
        url = f"{scheme}://{d}/"
        chain = []
        try:
            for _ in range(6):
                resp = client.get(url)
                chain.append({"url": url, "status": resp.status_code, "server": resp.headers.get("server", "")})
                if resp.status_code in {301, 302, 303, 307, 308} and "location" in resp.headers:
                    url = str(resp.url.join(resp.headers["location"]))
                    continue
                break
            res.data[f"{scheme}_chain"] = chain
            final = chain[-1]["status"]
            if scheme == "https":
                if final >= 500:
                    res.findings.append(Finding(
                        id="web.server_error", severity=Severity.CRITICAL, title=f"Website returns HTTP {final}",
                        detail="The server (or proxy like Cloudflare) is up but the site behind it is failing. "
                               "520-526 from Cloudflare usually means the origin server is down or its SSL is misconfigured.",
                        evidence={"chain": chain}))
                elif final in {401, 403}:
                    res.findings.append(Finding(id="web.forbidden", severity=Severity.WARNING, title=f"Website returns HTTP {final}",
                                                detail="Access denied: missing index file, wrong folder permissions, WAF block, or hosting suspension.",
                                                evidence={"chain": chain}))
                elif final == 404:
                    res.findings.append(Finding(id="web.not_found", severity=Severity.WARNING, title="Homepage returns 404",
                                                detail="DNS works but the hosting account has no site at this path (wrong document root or site not uploaded)."))
                else:
                    res.findings.append(Finding(id="web.https_ok", severity=Severity.OK, title=f"HTTPS responds ({final})",
                                                evidence={"chain": chain}))
            elif scheme == "http" and not any(c["url"].startswith("https") for c in chain[1:]) and final < 400:
                res.findings.append(Finding(id="web.no_https_redirect", severity=Severity.INFO, title="HTTP does not redirect to HTTPS",
                                            detail="Visitors on http:// stay unencrypted. Enable 'Always use HTTPS' / force SSL."))
        except Exception as e:
            res.data[f"{scheme}_error"] = f"{type(e).__name__}: {e}"
            if scheme == "https":
                res.findings.append(Finding(id="web.https_unreachable", severity=Severity.CRITICAL,
                                            title="HTTPS connection failed",
                                            detail=f"{type(e).__name__}. Causes: no SSL certificate, port 443 closed, server down, "
                                                   "or DNS pointing to the wrong server.", evidence={"error": str(e)}))

    cert = _cert_info(d, ctx.settings.http_timeout)
    res.data["ssl"] = cert
    if cert.get("valid") is False:
        res.findings.append(Finding(
            id="ssl.invalid", severity=Severity.CRITICAL, title="SSL certificate is invalid",
            detail=f"{cert.get('error')}. Browsers show 'Your connection is not private'. Common causes: certificate for a "
                   "different domain (hostname mismatch), expired, or self-signed. Re-issue SSL in the hosting panel.",
            evidence=cert, fix_ids=["fix.ssl.reissue"]))
    elif cert.get("valid"):
        days = cert.get("days_left", 0)
        if days < 0:
            res.findings.append(Finding(id="ssl.expired", severity=Severity.CRITICAL, title="SSL certificate expired", evidence=cert,
                                        fix_ids=["fix.ssl.reissue"]))
        elif days <= 14:
            res.findings.append(Finding(id="ssl.expiring", severity=Severity.WARNING, title=f"SSL expires in {days} days",
                                        detail="Auto-renew may be failing (often because DNS moved away from the host that issues it).",
                                        evidence=cert, fix_ids=["fix.ssl.reissue"]))
        else:
            res.findings.append(Finding(id="ssl.ok", severity=Severity.OK, title=f"SSL valid ({days} days left, {cert.get('issuer')})"))
    return res


# ---------------------------------------------------------------- RDAP
@tool("check_domain_registration",
      "Check domain registration via RDAP: registrar, expiry date, holds/suspension statuses, and whether "
      "the registry's nameservers match DNS.",
      DOMAIN_PARAM, ["domain"])
def check_domain_registration(ctx: Context, domain: str) -> ToolResult:
    d = org_domain(norm_domain(domain))
    res = ToolResult(tool="check_domain_registration", target=d)
    if ctx.offline:
        res.findings.append(Finding(id="rdap.skipped", severity=Severity.UNKNOWN, title="Registration lookup skipped (offline mode)"))
        return res
    try:
        resp = ctx.client().get(f"https://rdap.org/domain/{d}", follow_redirects=True)
        if resp.status_code == 404:
            res.findings.append(Finding(id="rdap.not_found", severity=Severity.CRITICAL, title="Domain not found in the registry",
                                        detail="It is unregistered, deleted after expiry, or the TLD has no public RDAP.",
                                        fix_ids=["fix.domain.renew_or_unhold"]))
            return res
        resp.raise_for_status()
        j = resp.json()
    except Exception as e:
        res.findings.append(Finding(id="rdap.error", severity=Severity.UNKNOWN, title="Registration data unavailable",
                                    detail=f"RDAP lookup failed ({type(e).__name__}). Check expiry in the registrar panel."))
        return res

    events = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    statuses = [s.lower() for s in j.get("status", [])]
    registrar = ""
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            v = ent.get("vcardArray", [None, []])[1]
            registrar = next((x[3] for x in v if x[0] == "fn"), "") or ent.get("handle", "")
    ns = sorted(n.get("ldhName", "").lower().rstrip(".") for n in j.get("nameservers", []))
    res.data = {"registrar": registrar, "events": events, "statuses": statuses, "registry_nameservers": ns}

    exp = events.get("expiration")
    if exp:
        try:
            exp_dt = dt.datetime.fromisoformat(exp.replace("Z", "+00:00"))
            days = (exp_dt - dt.datetime.now(dt.timezone.utc)).days
            res.data["days_to_expiry"] = days
            if days < 0:
                res.findings.append(Finding(id="domain.expired", severity=Severity.CRITICAL, title=f"Domain expired {-days} days ago",
                                            detail="Website and email stop working after expiry. Renew immediately; late renewal may cost a redemption fee.",
                                            fix_ids=["fix.domain.renew_or_unhold"]))
            elif days <= 30:
                res.findings.append(Finding(id="domain.expiring", severity=Severity.WARNING, title=f"Domain expires in {days} days",
                                            detail="Turn on auto-renew and check the card on file.", fix_ids=["fix.domain.renew_or_unhold"]))
            else:
                res.findings.append(Finding(id="domain.registration_ok", severity=Severity.OK,
                                            title=f"Registered ({registrar or 'registrar unknown'}), expires in {days} days"))
        except ValueError:
            pass
    bad = [s for s in statuses if any(k in s for k in ("hold", "redemption", "pending delete", "pendingdelete", "inactive"))]
    if bad:
        res.findings.append(Finding(
            id="domain.hold_status", severity=Severity.CRITICAL, title=f"Registry status: {', '.join(bad)}",
            detail="'clientHold'/'serverHold' removes the domain from DNS entirely (often unpaid renewal, failed WHOIS "
                   "email verification, or abuse complaint). 'redemptionPeriod' means it expired and must be restored.",
            fix_ids=["fix.domain.renew_or_unhold"]))
    live_ns = sorted(n.rstrip(".").lower() for n in ctx.resolver.resolve(norm_domain(domain), "NS").records)
    if ns and live_ns and set(ns) != set(live_ns):
        res.findings.append(Finding(id="domain.ns_mismatch", severity=Severity.WARNING,
                                    title="Registry nameservers differ from live DNS",
                                    detail="A nameserver change may still be propagating (up to 48h), or the zone is served from the wrong place.",
                                    evidence={"registry": ns, "live": live_ns}))
    return res


# ---------------------------------------------------------------- Blacklists
_IP_BLS = ["zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net"]
_DOMAIN_BLS = ["dbl.spamhaus.org", "multi.surbl.org"]


@tool("check_blacklists",
      "Check whether the domain or its mail/web server IPs are on major spam blocklists (Spamhaus, Barracuda, SpamCop, SURBL).",
      DOMAIN_PARAM, ["domain"])
def check_blacklists(ctx: Context, domain: str) -> ToolResult:
    d = norm_domain(domain)
    r = ctx.resolver
    res = ToolResult(tool="check_blacklists", target=d)
    ips: dict[str, str] = {}
    mx, _ = _mx_hosts(ctx, d)
    for _p, h in mx[:3]:
        for ip in r.resolve(h, "A").records[:2]:
            ips[ip] = f"mail server {h}"
    for ip in r.resolve(d, "A").records[:2]:
        ips.setdefault(ip, "website")
    listed, unknown = [], []
    for ip, role in ips.items():
        rev = ".".join(reversed(ip.split(".")))
        for bl in _IP_BLS:
            a = r.resolve(f"{rev}.{bl}", "A")
            if a.status == ERROR:
                unknown.append(bl)
            elif a.records:
                code = a.records[0]
                if code.startswith("127.255.255.") or code == "127.0.0.1":
                    unknown.append(bl)  # resolver blocked / query refused, not a listing
                else:
                    listed.append({"ip": ip, "role": role, "list": bl, "code": code})
    for bl in _DOMAIN_BLS:
        a = r.resolve(f"{d}.{bl}", "A")
        if a.records and not a.records[0].startswith("127.255.255."):
            listed.append({"domain": d, "list": bl, "code": a.records[0]})
        elif a.status == ERROR or (a.records and a.records[0].startswith("127.255.255.")):
            unknown.append(bl)
    res.data = {"checked_ips": ips, "listed": listed, "inconclusive_lists": sorted(set(unknown))}
    shared_host_note = (" If this is shared hosting/email, the IP is shared with other customers; ask the provider "
                        "to delist or move you to a clean IP.")
    if listed:
        res.findings.append(Finding(id="bl.listed", severity=Severity.CRITICAL, title=f"Listed on {len(listed)} blocklist(s)",
                                    detail="Receivers using these lists will reject or spam your mail." + shared_host_note,
                                    evidence={"listed": listed}, fix_ids=["fix.bl.delist"]))
    elif ips:
        res.findings.append(Finding(id="bl.clean", severity=Severity.OK, title="Not found on checked blocklists",
                                    evidence={"ips": list(ips)}))
    if unknown:
        res.findings.append(Finding(id="bl.inconclusive", severity=Severity.UNKNOWN,
                                    title="Some blocklists could not be queried",
                                    detail="Spamhaus refuses queries from public/cloud resolvers; run from a private resolver for a definite answer.",
                                    evidence={"lists": sorted(set(unknown))}))
    return res
