"""MailDoctor: an agentic assistant for domain, DNS, email and hosting problems.

Layers (read docs/LEARN.md for the full walkthrough):
  tools/   deterministic checks. They decide facts (pass/fail). No AI here.
  fixes    deterministic fix plans built from findings.
  agent/   the LLM decides *strategy*: which tool next, how findings connect,
           which fix to propose. It never decides whether a record is valid.
  api/cli  ways to run it.
"""

__version__ = "0.1.0"
