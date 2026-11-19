"""Settings, read from environment variables (see .env.example).

Keeping config in one place means the rest of the code never touches os.environ
directly, which makes testing and deployment easier.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def load_dotenv(path: str = ".env") -> None:
    """Tiny .env reader (KEY=value lines). Real environment variables win."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass
class Settings:
    # Which LLM drives the agent: "gemini", "openai", or "offline" (no LLM, rule playbook).
    llm_provider: str = field(default_factory=lambda: _env("MAILDOCTOR_LLM", "auto"))
    gemini_api_key: str = field(default_factory=lambda: _env("GEMINI_API_KEY"))
    gemini_model: str = field(default_factory=lambda: _env("GEMINI_MODEL", "gemini-3.8-flash"))
    openai_api_key: str = field(default_factory=lambda: _env("OPENAI_API_KEY"))
    openai_model: str = field(default_factory=lambda: _env("OPENAI_MODEL", "gpt-4o-mini"))
    openai_base_url: str = field(default_factory=lambda: _env("OPENAI_BASE_URL", "https://api.openai.com/v1"))

    # Agent guardrails
    max_agent_steps: int = field(default_factory=lambda: int(_env("MAILDOCTOR_MAX_STEPS", "12")))

    # DNS: "system" uses normal UDP/TCP DNS; "doh" forces DNS-over-HTTPS (useful on
    # hosts that block port 53). "auto" tries system first, then DoH.
    dns_mode: str = field(default_factory=lambda: _env("MAILDOCTOR_DNS", "auto"))
    dns_timeout: float = field(default_factory=lambda: float(_env("MAILDOCTOR_DNS_TIMEOUT", "4")))

    # Network timeouts for HTTP/TLS/RDAP checks
    http_timeout: float = field(default_factory=lambda: float(_env("MAILDOCTOR_HTTP_TIMEOUT", "8")))

    # LLM: seconds to wait for one model reply, and for the whole agent run.
    # If the run budget is used up, MailDoctor finishes with the rule-based playbook.
    llm_timeout: float = field(default_factory=lambda: float(_env("MAILDOCTOR_LLM_TIMEOUT", "90")))
    agent_budget: float = field(default_factory=lambda: float(_env("MAILDOCTOR_AGENT_BUDGET", "150")))

    def resolved_provider(self) -> str:
        """Pick the LLM provider. 'auto' = Gemini if key, else OpenAI if key, else offline."""
        p = self.llm_provider.lower()
        if p in {"gemini", "openai", "offline"}:
            return p
        if self.gemini_api_key:
            return "gemini"
        if self.openai_api_key:
            return "openai"
        return "offline"


def get_settings() -> Settings:
    return Settings()
