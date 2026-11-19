"""Data shapes shared across the project.

Every check returns a ToolResult made of Findings. A Finding is a single,
evidence-backed fact ("SPF record missing", "MX points to Google").
The agent and the UI both read the same structures, so nothing is hidden.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    OK = "ok"            # checked and healthy
    INFO = "info"        # neutral fact (e.g. "email hosted at Zoho")
    WARNING = "warning"  # works today but risky
    CRITICAL = "critical"  # broken / will break mail or site
    UNKNOWN = "unknown"  # could not be determined (lookup failed, needs access)


SEVERITY_WEIGHT = {
    Severity.OK: 0,
    Severity.INFO: 0,
    Severity.UNKNOWN: 3,
    Severity.WARNING: 8,
    Severity.CRITICAL: 25,
}


class Finding(BaseModel):
    id: str                       # stable code, e.g. "spf.missing"
    title: str                    # short human title
    severity: Severity
    detail: str = ""              # plain-English explanation
    evidence: dict[str, Any] = Field(default_factory=dict)  # raw data that proves it
    fix_ids: list[str] = Field(default_factory=list)       # links to fixes.FIXES


class ToolResult(BaseModel):
    tool: str
    target: str
    ok: bool = True               # False only if the tool itself crashed
    findings: list[Finding] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)  # structured facts for other tools/agent
    error: str | None = None

    def worst(self) -> Severity:
        order = [Severity.CRITICAL, Severity.WARNING, Severity.UNKNOWN, Severity.INFO, Severity.OK]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s
        return Severity.OK

    def compact(self) -> dict[str, Any]:
        """Small version sent back to the LLM (saves tokens)."""
        return {
            "tool": self.tool,
            "target": self.target,
            "error": self.error,
            "data": self.data,
            "findings": [
                {"id": f.id, "severity": f.severity.value, "title": f.title, "detail": f.detail}
                for f in self.findings
            ],
        }


class DnsChange(BaseModel):
    """One concrete DNS change a human can copy, or that can be applied via API."""
    action: str                   # "add" | "update" | "delete"
    type: str                     # "TXT", "MX", "CNAME", "A"
    name: str                     # "@", "_dmarc", "zmail._domainkey"
    value: str = ""
    priority: int | None = None
    replaces: str | None = None   # old value, for update/delete


class FixPlan(BaseModel):
    id: str
    title: str
    why: str
    changes: list[DnsChange] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)      # manual steps (registrar UI, client app)
    risk: str = "low"             # "low" | "medium" | "high"
    reversible: bool = True


class AgentStep(BaseModel):
    step: int
    thought: str = ""
    tool: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    result_summary: str = ""


class Diagnosis(BaseModel):
    domain: str
    complaint: str = ""
    summary: str = ""
    root_causes: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    fixes: list[FixPlan] = Field(default_factory=list)
    customer_reply: str = ""
    health_score: int = 100
    trace: list[AgentStep] = Field(default_factory=list)
    engine: str = "offline"       # which brain produced it: gemini/openai/offline
    dns_provider: str | None = None    # e.g. "Cloudflare" -> UI can offer one-click apply
    email_provider: str | None = None
    confidence: str = "medium"
    limits: list[str] = Field(default_factory=list)  # what public checks cannot see
