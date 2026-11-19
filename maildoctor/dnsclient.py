"""DNS lookups with a small, test-friendly interface.

Why a wrapper instead of calling dnspython everywhere?
  1. One place to add caching, timeouts and fallbacks.
  2. Some hosts block normal DNS (port 53). DNS-over-HTTPS (DoH) still works there.
  3. Tests can swap in a FakeResolver with canned answers, so checks are
     tested without the internet.

Every lookup returns a DnsAnswer with a *status*. Distinguishing "the name does
not exist" (NXDOMAIN) from "the name exists but has no record of this type"
(NOANSWER) from "the lookup failed" (ERROR) matters: only the first two are
real findings; an ERROR must be reported as UNKNOWN, never as "missing".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import httpx

from .config import Settings, get_settings

OK, NXDOMAIN, NOANSWER, ERROR = "ok", "nxdomain", "noanswer", "error"

# DNS record type numbers used by the DoH JSON API
_TYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


@dataclass
class DnsAnswer:
    name: str
    rtype: str
    status: str
    records: list[str] = field(default_factory=list)
    error: str = ""
    ttl: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == OK and bool(self.records)


class Resolver(Protocol):
    def resolve(self, name: str, rtype: str) -> DnsAnswer: ...


def _clean_txt(raw: str) -> str:
    """TXT data can arrive as '"part1" "part2"'. Join the parts into one string."""
    raw = raw.strip()
    if '"' not in raw:
        return raw
    parts, buf, inq, esc = [], [], False, False
    for ch in raw:
        if esc:
            buf.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            if inq:
                parts.append("".join(buf))
                buf = []
            inq = not inq
        elif inq:
            buf.append(ch)
    return "".join(parts) if parts else raw.strip('"')


class SystemResolver:
    """Uses dnspython over normal DNS."""

    def __init__(self, timeout: float = 4.0):
        import dns.resolver

        self._r = dns.resolver.Resolver()
        self._r.lifetime = timeout
        self._r.timeout = timeout

    def resolve(self, name: str, rtype: str) -> DnsAnswer:
        import dns.exception
        import dns.resolver

        try:
            ans = self._r.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(name, rtype, NXDOMAIN)
        except dns.resolver.NoAnswer:
            return DnsAnswer(name, rtype, NOANSWER)
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            return DnsAnswer(name, rtype, ERROR, error=type(e).__name__)
        except Exception as e:  # pragma: no cover - defensive
            return DnsAnswer(name, rtype, ERROR, error=str(e))
        recs: list[str] = []
        for r in ans:
            if rtype == "TXT":
                recs.append("".join(s.decode("utf-8", "replace") for s in r.strings))
            elif rtype == "MX":
                recs.append(f"{r.preference} {str(r.exchange).rstrip('.').lower()}")
            else:
                recs.append(r.to_text().rstrip(".").lower() if rtype in {"NS", "CNAME", "PTR"} else r.to_text())
        return DnsAnswer(name, rtype, OK, recs, ttl=ans.rrset.ttl if ans.rrset else None)


class DohResolver:
    """DNS-over-HTTPS via Google's JSON API (Cloudflare as backup)."""

    ENDPOINTS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]

    def __init__(self, timeout: float = 4.0, client: httpx.Client | None = None):
        self._c = client or httpx.Client(timeout=timeout, headers={"accept": "application/dns-json"})

    def resolve(self, name: str, rtype: str) -> DnsAnswer:
        last_err = ""
        for url in self.ENDPOINTS:
            try:
                resp = self._c.get(url, params={"name": name, "type": rtype})
                resp.raise_for_status()
                j = resp.json()
            except Exception as e:
                last_err = str(e)
                continue
            status = j.get("Status", 2)
            if status == 3:
                return DnsAnswer(name, rtype, NXDOMAIN)
            if status != 0:
                last_err = f"rcode {status}"
                continue
            want = _TYPE_NUM.get(rtype)
            recs, ttl = [], None
            for a in j.get("Answer", []) or []:
                if a.get("type") != want:
                    continue  # skip CNAME hops in the chain
                data = a.get("data", "")
                ttl = a.get("TTL", ttl)
                if rtype == "TXT":
                    recs.append(_clean_txt(data))
                elif rtype == "MX":
                    pr, _, host = data.partition(" ")
                    recs.append(f"{pr} {host.rstrip('.').lower()}")
                elif rtype in {"NS", "CNAME", "PTR"}:
                    recs.append(data.rstrip(".").lower())
                else:
                    recs.append(data)
            return DnsAnswer(name, rtype, OK if recs else NOANSWER, recs, ttl=ttl)
        return DnsAnswer(name, rtype, ERROR, error=last_err or "DoH failed")


class AutoResolver:
    """Try system DNS; if it errors (not NXDOMAIN/NOANSWER), retry over DoH."""

    def __init__(self, settings: Settings):
        self._sys = None
        try:
            self._sys = SystemResolver(settings.dns_timeout)
        except Exception:
            self._sys = None
        self._doh = DohResolver(settings.dns_timeout)

    def resolve(self, name: str, rtype: str) -> DnsAnswer:
        if self._sys is not None:
            a = self._sys.resolve(name, rtype)
            if a.status != ERROR:
                return a
        return self._doh.resolve(name, rtype)


class CachingResolver:
    """Memoises answers for one diagnosis run so the agent can re-ask cheaply."""

    def __init__(self, inner: Resolver):
        self.inner = inner
        self._cache: dict[tuple[str, str], DnsAnswer] = {}
        self.queries: list[tuple[str, str]] = []  # audit trail, shown in the trace

    def resolve(self, name: str, rtype: str) -> DnsAnswer:
        key = (name.lower().rstrip("."), rtype.upper())
        if key not in self._cache:
            self.queries.append(key)
            self._cache[key] = self.inner.resolve(*key)
        return self._cache[key]


class FakeResolver:
    """For tests and demos. `data` maps (name, type) -> list of records,
    or the strings 'nxdomain' / 'error'."""

    def __init__(self, data: dict[tuple[str, str], list[str] | str]):
        self.data = {(n.lower(), t.upper()): v for (n, t), v in data.items()}

    def resolve(self, name: str, rtype: str) -> DnsAnswer:
        v = self.data.get((name.lower().rstrip("."), rtype.upper()))
        if v is None:
            # if any record exists for the name, it's NOANSWER, else NXDOMAIN
            exists = any(n == name.lower() for (n, _t) in self.data)
            return DnsAnswer(name, rtype, NOANSWER if exists else NXDOMAIN)
        if v == "nxdomain":
            return DnsAnswer(name, rtype, NXDOMAIN)
        if v == "error":
            return DnsAnswer(name, rtype, ERROR, error="simulated")
        return DnsAnswer(name, rtype, OK, list(v))


def make_resolver(settings: Settings | None = None) -> CachingResolver:
    s = settings or get_settings()
    mode = s.dns_mode.lower()
    if mode == "doh":
        inner: Resolver = DohResolver(s.dns_timeout)
    elif mode == "system":
        inner = SystemResolver(s.dns_timeout)
    else:
        inner = AutoResolver(s)
    return CachingResolver(inner)
