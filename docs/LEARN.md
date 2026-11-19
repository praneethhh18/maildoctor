# Learning MailDoctor: how it works and why

This guide walks through the project in the order you should read the code. Each section ends with a **Your turn** exercise. Do them by hand (no AI); that's how the fundamentals stick.

---

## 1. The problem we're solving

When "email doesn't work", the cause is usually one of a handful of DNS or account settings, but the symptom ("goes to spam", "bounces", "Outlook won't connect", "site not secure") doesn't tell you which. A support engineer investigates: looks at MX, then SPF, notices the provider changed, checks DKIM for that provider, and so on. Each answer decides the next question.

That chain of *"found X, so check Y"* is what makes this an **agent** problem rather than a "generate some text" problem.

---

## 2. Generative AI vs agentic AI (and where each lives in this repo)

| | Generative AI app | MailDoctor (agentic) |
|---|---|---|
| Input | prompt | goal + tools |
| What the model does | writes an answer | **chooses actions**, observes results, decides the next action |
| Where facts come from | the model's memory (can hallucinate) | **tools** that query real DNS/HTTP/RDAP |
| Output | text | structured diagnosis + concrete fixes + audit trail |
| Safety | none | model can't invent fixes or apply changes; a human approves |

The golden rule of this codebase:

> **Code decides facts. The LLM decides strategy.**

- `maildoctor/tools/` decides "SPF has 12 lookups". It is plain Python, fully tested.
- `maildoctor/agent/` decides "SPF is fine but DKIM is missing for Google, and the MX changed, so the customer switched providers and forgot DNS".

---

## 3. Email & DNS concepts (the domain knowledge)

| Record | Lives at | Answers the question | Typical breakage |
|---|---|---|---|
| **NS** | registrar | "Which company's servers answer DNS for this domain?" | Moved DNS to Cloudflare but edited records at the old host |
| **A / AAAA** | `@`, `www` | "Which IP serves the website?" | Points to old host or a private IP |
| **CNAME** | `www`, subdomains | "This name is an alias of that name" | CNAME at apex, CNAME on MX target |
| **MX** | `@` | "Which servers receive mail for this domain?" | Missing, or two providers mixed |
| **SPF** (TXT `v=spf1`) | `@` | "Which servers may *send* as this domain?" | Two records, >10 lookups, provider not listed |
| **DKIM** (TXT at `selector._domainkey`) | per sender | "Here's the public key; check the signature on the message" | Key not published, or published but not *activated* in the provider |
| **DMARC** (TXT at `_dmarc`) | `@` | "If SPF/DKIM don't pass *and align* with From, do X; send reports to Y" | Missing, or set to reject before DKIM works |

**Alignment** is the subtle one. DMARC passes only if SPF or DKIM passes *for the same domain as the visible From address*. A newsletter tool can pass DKIM as `sendgrid.net` and still fail DMARC for `yourshop.com`. `analyze_headers` detects exactly this.

**The 10-lookup rule.** Every `include:`, `a`, `mx`, `ptr`, `exists:` and `redirect=` costs one DNS lookup, *including the ones inside included records*. Over 10 means SPF permerror. That's why `check_spf` walks the tree recursively (`_count_lookups`).

**Your turn 3.1.** Open `tests/test_tools.py::test_spf_lookup_limit`. Draw the tree of includes on paper and count the lookups yourself. Why is it 12?

**Your turn 3.2.** Real-life example: when we set up `nexusagent.in` on Zoho, DKIM was published in DNS but Zoho still said "unverified". Which `check_dkim` finding explains why DNS alone can't prove DKIM works? (Hint: `dkim.limits`.)

---

## 4. Architecture

```
            ┌───────────────────────── you / customer ──────────────────────────┐
            │  "emails go to spam since we moved to Google"  + optional bounce   │
            └──────────────────────────────┬────────────────────────────────────┘
                                           ▼
   api.py / cli.py ──► agent/loop.py  ── investigate()
                          │   ▲
          tool schemas ─► │   │ ◄─ tool results (compact JSON)
                          ▼   │
                     agent/llm.py  (GeminiChat | OpenAIChat | ScriptedLLM | none→offline playbook)
                          │
             "call check_spf(domain=…)"
                          ▼
                 tools/base.run_tool ──► tools/*.py ──► dnsclient (DNS / DoH)  + HTTP/TLS/RDAP
                          │
                    Findings (facts) ──► fixes.py (exact records) ──► report.py (score, root cause)
                          │
                          ▼
                     Diagnosis (JSON) ──► web page / CLI text
                                         └─► cloudflare.py  preview → human approves → apply → rollback
```

Read the files in this order: `models.py` → `dnsclient.py` → `tools/base.py` → `tools/email_auth.py` → `fixes.py` → `agent/llm.py` → `agent/loop.py` → `api.py`.

---

## 5. How tool calling actually works

We call the LLM APIs with plain HTTP (no SDK) so you can see the protocol. One round:

1. We send: the system prompt, the conversation so far, and a **menu of tools** (name + description + JSON-schema of arguments). `tools/base.py` builds the menu from the `@tool` decorators.
2. The model replies with either text, or a **tool call**:
   ```json
   {"name": "check_dkim", "args": {"domain": "moved.com", "selectors": ["google"]}}
   ```
3. We run the real Python function, then append its result as a `tool` message:
   ```json
   {"tool": "check_dkim", "findings": [{"id": "dkim.provider_missing", "severity": "critical", ...}]}
   ```
4. Repeat until the model calls `submit_diagnosis` (a "finish" tool whose arguments are the final structured answer).

Gemini and OpenAI spell this differently (`functionCall`/`functionResponse` vs `tool_calls`/`role: tool`). `agent/llm.py` translates our neutral message format to each. `tests/test_llm_adapters.py` shows the exact JSON on the wire.

**Guardrails in `agent/loop.py`:**
- max steps (`MAILDOCTOR_MAX_STEPS`)
- if the model rambles without calling a tool, we nudge it twice, then stop
- the model can only pick `fix_ids` that appeared on real findings (`allowed` set); invented ones are dropped
- big attachments (headers/bounces) are passed as `"@attachment"` so they aren't echoed back and forth, and the trace never stores them
- if the LLM API fails, we fall back to the offline playbook and say so in `limits`

**Your turn 5.1.** In `tests/test_fixes_agent.py::test_llm_agent_loop_with_attachment_and_guardrails` the scripted model asks for `fix.invented.by.model`. Find the exact line in `loop.py` that drops it.

**Your turn 5.2.** Add a new tool `check_caa(domain)` that reads CAA records (which CAs may issue SSL). Use `@tool` in a new file `tools/caa.py`, import it in `tools/__init__.py`, and write a test with `FakeResolver`. The agent will see it automatically. Why does it need no change in `loop.py`?

---

## 6. Safety: human-in-the-loop DNS changes

Changing live DNS can take down a customer's email. So `cloudflare.py`:

1. **preview** computes the exact API operations against the *current* records and an **approval code** (a hash of those operations).
2. A human reads the diff in the UI and clicks approve; the code is sent back.
3. **apply** recomputes the hash and refuses if anything changed since the preview. Before each write it saves the old record.
4. **rollback** replays the saved state.

Extra rule: it refuses to create a second SPF record; SPF changes are always merges (`fixes._merge_spf`).

The agent has **no tool** that applies changes. That separation is deliberate: AI proposes, human disposes.

**Your turn 6.1.** Why is the approval code a hash of the operations instead of a random token?

---

## 7. Testing without the internet

- `FakeResolver` returns canned DNS answers, so every check is tested deterministically.
- `ScriptedLLM` replays a fixed list of model responses, so the agent loop is tested without an API key or cost.
- `httpx.MockTransport` fakes the Cloudflare and LLM HTTP APIs.

Run `pytest -q`. All 29 tests run in under a second.

**Your turn 7.1.** Write a test for a domain whose SPF has `include:` pointing to a domain with *no* SPF record. Which finding should appear? (`spf.broken_include`.)

---

## 8. How a report is scored

`report.health_score`: start at 100, subtract 25 per critical, 8 per warning, 3 per unknown (unique findings). `report.RULES` maps *combinations* of findings to one root cause (e.g. `spf.provider_missing` + `dkim.provider_missing` ⇒ "provider changed but DNS wasn't updated"). The LLM does this correlation more flexibly; the rules make the offline mode useful and give the LLM a baseline to beat.

---

## 9. Running it for real

```bash
maildoctor scan nexusagent.in
maildoctor investigate nexusagent.in "dkim shows unverified in zoho"
MAILDOCTOR_LLM=gemini GEMINI_API_KEY=... maildoctor investigate yourclient.com "mails bounce" --bounce-file bounce.txt
maildoctor serve
```

---

## 10. Roadmap (next rounds)

1. **Next.js dashboard** with saved domains and history
2. **Monitoring**: scheduled `scan()` per domain, alert on new criticals (SPF changed, SSL < 14 days, domain expiring)
3. **Multi-domain workspace** for agencies, PDF client reports
4. **More fixers**: GoDaddy/Hostinger APIs, Domain Connect
5. **Live delivery tests**: send a test mail to a seed inbox and read back headers automatically
6. **Eval set**: 50 real support cases with expected root causes; measure the agent against the offline playbook

**Your turn 10.1.** Pick roadmap item 2. Sketch on paper: what data must be stored per domain to detect "SPF *changed*" rather than just "SPF is bad"?
