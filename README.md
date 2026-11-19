# 🩺 MailDoctor

**An agentic AI that investigates and fixes domain, DNS, email-delivery, email-app and website-hosting problems.**

Type a domain and a complaint in plain words ("emails to Gmail go to spam since we moved", "Outlook says authentication failed", "site shows not secure"). MailDoctor's agent decides which checks to run, follows leads from one result to the next, connects the findings to a root cause, and hands back:

- the **root cause** in plain English
- **exact DNS records** to add or change, with copy buttons (never invented; computed by code)
- **step-by-step instructions** for your DNS provider (Cloudflare, GoDaddy, Hostinger, Network Solutions…)
- a **ready-to-send reply** for the customer
- an **audit trail** of every step the agent took
- optional **one-click apply on Cloudflare**, with preview, explicit approval and rollback

> Why "agentic" and not "a chatbot"? See [docs/LEARN.md](docs/LEARN.md). In short: the LLM decides *strategy* (what to check next, what it means), while deterministic tools decide *facts* (does this record exist, is it valid).

## Self-serve for non-technical users

Open the web app, pick a problem in plain words (📥 *My emails go to spam*, 🌐 *My website won't open*, 📱 *Can't set up email on my phone*…), type your domain, and get:
numbered fix steps for **your** DNS provider → do one → press **"I did it, check again"** → MailDoctor re-runs just the checks behind that fix and tells you *Fixed ✓* or *Not yet* (and why). Domains on Cloudflare also get an optional **"do it for me"** with preview and undo. Technical details are tucked away; *Expert mode* shows everything.

## What it checks

| Area | Checks |
|---|---|
| Domain | existence, registrar, expiry, `clientHold`/`redemption` status, nameserver mismatch (RDAP) |
| DNS | nameservers, DNS host detection, single-NS risk |
| Receiving mail | MX present, mixed providers, IP-literal / unresolvable / CNAME targets, forwarding-only services |
| SPF | missing, duplicate records, syntax, `+all`/`?all`, **10-lookup limit (recursive)**, broken includes, provider not authorised, stale old-provider includes |
| DKIM | provider-specific + common sender selectors, revoked / malformed / weak keys, missing key for current provider |
| DMARC | missing, duplicates, invalid policy, monitor-only, no reports, org-domain fallback |
| Reputation | Spamhaus ZEN/DBL, Barracuda, SpamCop, SURBL (and honest "inconclusive" when a list refuses the query) |
| Website | A/AAAA/CNAME for apex and www, private IPs, HTTP(S) status and redirect chain, 5xx/403/404 meaning |
| SSL | validity, expiry, hostname mismatch |
| Message evidence | raw header analysis (SPF/DKIM/DMARC verdicts, alignment, hop delays), bounce/NDR decoding |
| Email apps | IMAP/SMTP/POP settings per provider and diagnosis of app error messages |

## Quick start

```bash
git clone https://github.com/praneethhh18/maildoctor && cd maildoctor
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env                                   # add GEMINI_API_KEY and/or OPENAI_API_KEY (optional)

pytest                                                  # 29 tests, no internet needed
maildoctor scan example.com                             # full checklist
maildoctor investigate example.com "emails go to spam"  # agentic investigation
maildoctor serve                                        # web app at http://127.0.0.1:8000
```

No API key? It still works: the agent falls back to a rule-based playbook (`engine: offline-playbook`).

## Choosing the brain

| `MAILDOCTOR_LLM` | Uses |
|---|---|
| `auto` (default) | Gemini if `GEMINI_API_KEY` is set, else OpenAI if `OPENAI_API_KEY`, else offline playbook |
| `gemini` | Google Gemini (free tier works) via function calling |
| `openai` | OpenAI or any OpenAI-compatible API (`OPENAI_BASE_URL` for Groq/OpenRouter/local) |
| `offline` | No LLM; deterministic playbook |

## API

| Method | Path | Body |
|---|---|---|
| GET | `/api/health` | – |
| GET | `/api/tools` | – |
| GET | `/api/problems` | – (plain-language problem catalog) |
| POST | `/api/scan` | `{domain}` |
| POST | `/api/investigate` | `{domain, problem_id?, complaint?, headers?, bounce?, client_error?}` |
| POST | `/api/verify` | `{domain, fix_id}` ("I did it, check again") |
| POST | `/api/tool` | `{name, args}` |
| POST | `/api/fix/preview` | `{domain, fix_id, cloudflare_token}` |
| POST | `/api/fix/apply` | `{zone_id, ops, approval_code, cloudflare_token}` |
| POST | `/api/fix/rollback` | `{zone_id, rollback, cloudflare_token}` |

## Deploy free

- **Render**: push the repo, "New Web Service", it picks up `render.yaml`. Add API keys as env vars.
- **Docker**: `docker build -t maildoctor . && docker run -p 8000:8000 --env-file .env maildoctor`

If the host blocks normal DNS (port 53), set `MAILDOCTOR_DNS=doh` to use DNS-over-HTTPS.

## Project layout

```
maildoctor/
  config.py        settings from env
  models.py        Finding, ToolResult, FixPlan, Diagnosis
  dnsclient.py     DNS with caching, DoH fallback, FakeResolver for tests
  providers.py     knowledge base: Google/Microsoft/Zoho/…; DNS hosts; IMAP/SMTP settings
  tools/           deterministic checks (the agent's hands)
  fixes.py         deterministic fix plans (never invents values)
  cloudflare.py    preview → approve → apply → rollback
  agent/           LLM adapters (Gemini/OpenAI), prompt, agent loop, offline playbook
  report.py        health score, root-cause rules, text report
  api.py, cli.py, web/index.html
tests/             fake DNS + scripted LLM; no network needed
docs/LEARN.md      how everything works, with exercises
```

## Limits (by design, stated in every report)

Public checks can't see mailbox storage, passwords, deleted users or actual spam placement. For those, paste a bounce message or the headers of a real email; MailDoctor reads those too.
