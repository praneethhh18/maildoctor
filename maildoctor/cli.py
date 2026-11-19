"""Command line.

  maildoctor scan example.com
  maildoctor investigate example.com "emails to gmail go to spam"
  maildoctor investigate example.com "bounce" --bounce-file bounce.txt
  maildoctor headers headers.txt
  maildoctor tool check_spf '{"domain":"example.com"}'
  maildoctor serve
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import investigate, make_llm, scan
from .config import get_settings
from .report import render_text
from .tools import REGISTRY, make_context, run_tool


def _read(p: str | None) -> str:
    return Path(p).read_text(encoding="utf-8", errors="replace") if p else ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="maildoctor", description="Diagnose domain, DNS, email and hosting problems.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="full checklist health scan (no LLM)")
    s.add_argument("domain")
    s.add_argument("--json", action="store_true")

    i = sub.add_parser("investigate", help="agentic investigation of a reported problem")
    i.add_argument("domain")
    i.add_argument("complaint", nargs="?", default="")
    i.add_argument("--headers-file")
    i.add_argument("--bounce-file")
    i.add_argument("--client-error", default="")
    i.add_argument("--json", action="store_true")

    h = sub.add_parser("headers", help="analyse a raw email header file")
    h.add_argument("file")

    t = sub.add_parser("tool", help="run a single tool")
    t.add_argument("name", choices=sorted(REGISTRY))
    t.add_argument("args", help='JSON arguments, e.g. {"domain":"example.com"}')

    sv = sub.add_parser("serve", help="start the web app")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)

    a = ap.parse_args(argv)
    settings = get_settings()
    ctx = make_context(settings=settings)

    if a.cmd == "scan":
        d = scan(ctx, a.domain)
        print(d.model_dump_json(indent=2) if a.json else render_text(d))
    elif a.cmd == "investigate":
        d = investigate(ctx, make_llm(settings), a.domain, a.complaint,
                        _read(a.headers_file), _read(a.bounce_file), a.client_error)
        print(d.model_dump_json(indent=2) if a.json else render_text(d))
    elif a.cmd == "headers":
        r = run_tool(ctx, "analyze_headers", {"raw_headers": _read(a.file)})
        print(r.model_dump_json(indent=2))
    elif a.cmd == "tool":
        r = run_tool(ctx, a.name, json.loads(a.args))
        print(r.model_dump_json(indent=2))
    elif a.cmd == "serve":
        import uvicorn

        uvicorn.run("maildoctor.api:app", host=a.host, port=a.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
