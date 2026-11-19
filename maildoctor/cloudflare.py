"""Apply DNS fixes to Cloudflare, safely.

Human-in-the-loop design (read docs/LEARN.md section 6):
  1. preview(plan)   -> computes exact API operations + an approval code (hash).
  2. a human reviews the diff and sends the approval code back.
  3. apply(ops, code)-> refuses if the code doesn't match the previewed ops,
                        saves a backup of every record it touches, then applies.
  4. rollback(backup)-> restores the previous state.

The AGENT can propose plans but has no tool to call apply(). Only the API
endpoint, triggered by a person, can. That separation is the safety boundary.

The user's own scoped API token is used (Zone.DNS:Edit for one zone).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import httpx

from .models import DnsChange, FixPlan

API = "https://api.cloudflare.com/client/v4"


class CloudflareError(RuntimeError):
    pass


@dataclass
class Op:
    method: str               # POST / PUT / DELETE
    record_id: str | None
    body: dict[str, Any] | None
    before: dict[str, Any] | None  # existing record, kept for rollback

    def as_dict(self) -> dict[str, Any]:
        return {"method": self.method, "record_id": self.record_id, "body": self.body, "before": self.before}


def approval_code(ops: list[Op]) -> str:
    blob = json.dumps([o.as_dict() for o in ops], sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


class CloudflareClient:
    def __init__(self, token: str, client: httpx.Client | None = None):
        if not token:
            raise CloudflareError("Cloudflare API token required")
        self.c = client or httpx.Client(timeout=15)
        self.h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _req(self, method: str, path: str, **kw) -> Any:
        r = self.c.request(method, API + path, headers=self.h, **kw)
        try:
            j = r.json()
        except Exception:
            raise CloudflareError(f"HTTP {r.status_code}")
        if not j.get("success", False):
            raise CloudflareError("; ".join(e.get("message", "") for e in j.get("errors", [])) or f"HTTP {r.status_code}")
        return j["result"]

    def zone_id(self, domain: str) -> str:
        res = self._req("GET", "/zones", params={"name": domain})
        if not res:
            raise CloudflareError(f"zone {domain} not found for this token")
        return res[0]["id"]

    def records(self, zone: str) -> list[dict[str, Any]]:
        return self._req("GET", f"/zones/{zone}/dns_records", params={"per_page": 500})

    # ------------------------------------------------------------ planning
    @staticmethod
    def _fqdn(name: str, domain: str) -> str:
        return domain if name in {"@", "", domain} else (name if name.endswith(domain) else f"{name}.{domain}")

    @staticmethod
    def _norm(v: str) -> str:
        return (v or "").strip().strip('"').rstrip(".").lower()

    def plan_ops(self, domain: str, plan: FixPlan, existing: list[dict[str, Any]]) -> list[Op]:
        ops: list[Op] = []
        for ch in plan.changes:
            ops.extend(self._ops_for(domain, ch, existing))
        return ops

    def _find(self, existing, rtype, fqdn, value=None):
        out = []
        for r in existing:
            if r["type"] == rtype and r["name"].lower() == fqdn.lower():
                if value is None or self._norm(r["content"]) == self._norm(value):
                    out.append(r)
        return out

    def _ops_for(self, domain: str, ch: DnsChange, existing) -> list[Op]:
        fqdn = self._fqdn(ch.name, domain)
        body = {"type": ch.type, "name": fqdn, "content": ch.value, "ttl": 1}
        if ch.type == "MX":
            body["priority"] = ch.priority if ch.priority is not None else 10
        if ch.type in {"A", "AAAA", "CNAME"}:
            body["proxied"] = False
        if ch.action == "add":
            if self._find(existing, ch.type, fqdn, ch.value):
                return []  # already there: idempotent
            if ch.type == "TXT" and ch.value.lower().startswith("v=spf1") and self._spf_present(existing, fqdn):
                raise CloudflareError("Refusing to add a second SPF record; use an 'update' (merge) instead")
            return [Op("POST", None, body, None)]
        if ch.action == "update":
            match = self._find(existing, ch.type, fqdn, ch.replaces) if ch.replaces else self._find(existing, ch.type, fqdn)
            if ch.type == "TXT" and ch.value.lower().startswith("v=spf1") and not match:
                match = [r for r in self._find(existing, "TXT", fqdn) if self._norm(r["content"]).startswith("v=spf1")]
            if not match:
                return [Op("POST", None, body, None)]
            return [Op("PUT", match[0]["id"], body, _snapshot(match[0]))]
        if ch.action == "delete":
            match = self._find(existing, ch.type, fqdn, ch.replaces or ch.value)
            if ch.type == "MX" and not match and ch.value:
                match = [r for r in self._find(existing, "MX", fqdn) if self._norm(r["content"]) == self._norm(ch.value)]
            return [Op("DELETE", r["id"], None, _snapshot(r)) for r in match]
        raise CloudflareError(f"unknown action {ch.action}")

    def _spf_present(self, existing, fqdn) -> bool:
        return any(self._norm(r["content"]).startswith("v=spf1") for r in self._find(existing, "TXT", fqdn))

    # ------------------------------------------------------------ public flow
    def preview(self, domain: str, plan: FixPlan) -> dict[str, Any]:
        zone = self.zone_id(domain)
        ops = self.plan_ops(domain, plan, self.records(zone))
        return {"zone_id": zone, "ops": [o.as_dict() for o in ops], "approval_code": approval_code(ops)}

    def apply(self, zone: str, ops: list[dict[str, Any]], code: str) -> dict[str, Any]:
        op_objs = [Op(**o) for o in ops]
        if approval_code(op_objs) != code:
            raise CloudflareError("approval code does not match the previewed changes; preview again")
        done, backup = [], []
        for o in op_objs:
            if o.method == "POST":
                r = self._req("POST", f"/zones/{zone}/dns_records", json=o.body)
                backup.append({"method": "DELETE", "record_id": r["id"], "body": None, "before": None})
            elif o.method == "PUT":
                self._req("PUT", f"/zones/{zone}/dns_records/{o.record_id}", json=o.body)
                backup.append({"method": "PUT", "record_id": o.record_id, "body": o.before, "before": None})
            elif o.method == "DELETE":
                self._req("DELETE", f"/zones/{zone}/dns_records/{o.record_id}")
                backup.append({"method": "POST", "record_id": None, "body": o.before, "before": None})
            done.append(o.as_dict())
        return {"applied": done, "rollback": list(reversed(backup))}

    def rollback(self, zone: str, rollback_ops: list[dict[str, Any]]) -> int:
        n = 0
        for o in rollback_ops:
            if o["method"] == "DELETE":
                self._req("DELETE", f"/zones/{zone}/dns_records/{o['record_id']}")
            elif o["method"] == "PUT":
                self._req("PUT", f"/zones/{zone}/dns_records/{o['record_id']}", json=o["body"])
            elif o["method"] == "POST":
                self._req("POST", f"/zones/{zone}/dns_records", json=o["body"])
            n += 1
        return n


def _snapshot(r: dict[str, Any]) -> dict[str, Any]:
    keep = {"type", "name", "content", "ttl", "priority", "proxied"}
    return {k: v for k, v in r.items() if k in keep and v is not None}
