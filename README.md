# Cybernexis Burp Suite Pro Agent

**Agentic security testing inside [Burp Suite](https://portswigger.net/burp), driven by local Ollama, OpenAI-compatible, or Anthropic models.**

[![Java](https://img.shields.io/badge/Java-11+-ED8B00?logo=openjdk&logoColor=white)](#requirements)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Professional-FF6633)](#requirements)
[![Providers](https://img.shields.io/badge/LLM-Ollama%20%7C%20OpenAI%20%7C%20Anthropic-000000)](#model-providers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Cybernexis Agent is a Burp extension: chat with an LLM that can inspect scope, sitemap, and issues, send requests, fuzz, spray credentials, and write findings back into Burp. **Playbooks** steer a task toward one vuln class (IDOR, JWT, SSRF, GraphQL, …). A blank task can also pick a playbook from live Burp state — sitemap, scanner issues, HTTP, and the token map — when you ask to test or use *Send to Cybernexis*.

With local Ollama, prompts stay on your machine. Remote providers receive the prompts and selected Burp traffic needed for the task.

It is **not** an LLM. You bring a tool-capable model through Ollama, an OpenAI-compatible endpoint, or Anthropic. It is **not** affiliated with PortSwigger.

<p align="center">
  <img src="docs/architecture.svg" alt="Cybernexis architecture: analyst to chat, playbooks and surface hints, agent loop, model provider, and Burp Suite" width="880">
</p>

## Screenshots

<p align="center">
  <img src="docs/screenshots/chat.png" alt="Cybernexis Agent chat" width="880">
</p>
<p align="center">
  <img src="docs/screenshots/tool-card.png" alt="Tool call with Burp HTTP editor" width="880">
</p>
<p align="center">
  <img src="docs/screenshots/settings.png" alt="Cybernexis Settings" width="880">
</p>

## Features

- **Multi-task chat** — independent sessions with live request / tool-call counts, markdown answers, and native Burp request/response editors on tool cards
- **Playbooks** — vuln-class checklists mapped to Cybernexis tools (not payload packs). Pick one from `+` → **Playbooks**, or let a blank task attach one from your message or Burp state
- **Surface hints** — sitemap paths, issue names, HTTP bodies/headers, and the token map are scored (GraphQL, JWT, SQLi, SSRF, IDOR, …). The strongest class is loaded; others stay visible to the model
- **Approvals** — Manual, Smart (high-impact tools escalate), or Auto
- **Host focus** — naming a URL locks that task to that host (`www.` included; sibling subdomains stay out)
- **Variables** — `extract_from_response` → `{{csrf}}` in later `send_request` / `fuzz_request` / `brute_force`
- **Target memory** — durable per-host notes and a token map (JWT, UUID, CSRF, session cookies) across tasks
- **Live fuzzing** — status, length, reflection, error signatures, timing anomalies (blind SSRF / command injection)
- **Password spray** — built-in wordlists and `{{pass}}` / `{{user}}` markers; no huge lists pasted into the model
- **Model providers** — Ollama native, OpenAI-compatible Chat Completions, or Anthropic Messages; local or remote base URL
- **Optional passive scanner** — off by default; in-scope traffic → selected model → native Burp issues (`Cybernexis:`)
- **Right-click** — *Send to Cybernexis* from Proxy, Repeater, Target, or Scanner
- **Safety** — out-of-scope action tools can be blocked; conversation context is budgeted so long runs stay stable

## Requirements

| | |
|---|---|
| JDK | 11+ (Burp must run on a JDK if you use `run_custom_script`) |
| Maven | 3.8+ |
| Burp | Professional 2024.x+ (built against Montoya API `2025.12`) |
| Provider | Ollama, an OpenAI-compatible Chat Completions endpoint, or Anthropic |
| Model | tool-capable; for example a local Ollama model, an OpenAI API model, or a Claude model |

## Install

```bash
git clone https://github.com/caglarcakici/cybernexis-burp-agent.git
cd cybernexis-burp-agent
mvn -q package -DskipTests
```

1. Burp → **Extensions → Add** → type **Java** → select `target/cybernexis-agent.jar`
2. Open the **Cybernexis** suite tab
3. **Settings** — choose a provider protocol, set base URL, model, and optional API token, then **Test connection** and **Save**. Custom chat/model-list paths are under **Advanced**.

Unload any older build of the extension first so you do not get two suite tabs.

## Usage

Ask in **Chat**, for example:

- *What's in scope?*
- *List the sitemap for this host*
- *Inspect issue 3*
- *https://target.example/ test this host*
- *Test JWT on the login API*
- *Send request 42 to Repeater*
- *Extract the CSRF token from message 10 and brute-force the login*

Right-click any HTTP message → **Send to Cybernexis** to start a task with that exchange loaded. If the URL, body, or headers look like GraphQL, JWT, SSRF, and so on, the matching playbook is attached automatically.

| Mode | Behaviour |
|---|---|
| **Manual** | Confirm every action tool |
| **Smart** | Auto-run most tools; ask for crawl, audit, fuzz, brute-force, scripts, and live `send_request` |
| **Auto** | Run everything |

Enable **Block action tools targeting out-of-scope hosts** in Settings unless you intend otherwise.

### New task (`+`)

| Group | What it does |
|---|---|
| **Blank** | No extra instructions. A playbook can still attach from your first test prompt or from Burp state. |
| **Engagement** | Broad roles: Web App, API, Recon (read-only), Triage existing findings. |
| **Playbooks** | One vuln-class checklist (table below). Pins that playbook for the task. |

A chip in the transcript shows `Template · …` or `Playbook · JWT · from your message` / `from sitemap …`.

## Playbooks

Each playbook is a short methodology: test order, which Cybernexis tools to call, and a `## Finding / ## Evidence / ## Recommendation` write-up. They do not embed exploit payload catalogs or third-party scanners (no sqlmap, jwt_tool, …).

| Playbook | Use when |
|---|---|
| **Fast checking** | First-pass triage; no new attacks unless you ask |
| **IDOR / BOLA** | Object IDs in URLs, bodies, or nested API resources |
| **API security** | REST/JSON: BOLA, BFLA, mass assignment, verb tampering |
| **JWT** | Bearer/JWT in headers, cookies, or the token map |
| **OAuth / OIDC** | `/authorize`, `redirect_uri`, `state`, `code` |
| **SSRF** | Webhook/`url=` style parameters; confirm with Collaborator or timing |
| **Business logic** | Cart, checkout, coupon, workflow skip |
| **GraphQL** | `/graphql`, introspection, nested IDs |
| **XSS** | Reflected/stored input; use `fuzz_request` reflection flags |
| **SQLi** | Parameterized queries; error / timing / OOB detection only |
| **Open redirect / HPP** | `next=`, `returnUrl`, duplicate parameters |
| **Reporting** | Turn current issues into a client-ready write-up |

### How auto-attach works

1. **Your message wins.** “Test IDOR on /users” loads **IDOR / BOLA** immediately.
2. **Otherwise, if you asked to test** (or *Send to Cybernexis*), Cybernexis scores the focus host:
   - Sitemap paths (`/graphql`, `/oauth/authorize`, `/users/42`, `?url=`, cart/checkout, …)
   - Burp issue names (“SQL injection”, “Cross-site scripting”, “External service interaction”, …)
   - HTTP request/response (GraphQL body, `Authorization: Bearer eyJ…`)
   - Target memory token kinds (JWT)
3. The **strongest** class is attached if it clears a minimum score. A lone `?q=` search box is not enough to start XSS/SQLi.
4. Weaker classes stay in **Surface hints** inside the system prompt so the model can continue after the current pass.

Auto-attach does **not** run if:

- The question is inspect-only (*What's in scope?*, *list the sitemap*, *list issues*)
- You already picked a playbook from the `+` menu (it stays pinned)
- The task has no focus host and you did not name a URL (avoids scoring the whole project)

Playbooks tell the model to start that class (read-only first, then confirm). They do **not** bypass Manual/Smart approvals. High-impact tools still need your OK unless the session is in Auto.

## Model providers

| Protocol | Default base URL | Authentication | Endpoint |
|---|---|---|---|
| **Ollama native** | `http://127.0.0.1:11434` | None; optional Bearer token for a protected gateway | `/api/chat` |
| **OpenAI-compatible** | `https://api.openai.com` | Bearer token | `/v1/chat/completions` |
| **Anthropic Messages** | `https://api.anthropic.com` | `x-api-key` token | `/v1/messages` |

Custom base URLs are supported, including gateways and self-hosted OpenAI-compatible servers. Chat and model-list paths follow the selected protocol; override them in **Advanced** if a gateway uses a different path. A base URL may include the trailing `/v1`; Cybernexis avoids adding it twice.

For example, DeepSeek's OpenAI-compatible API uses protocol **OpenAI-compatible** and base URL `https://api.deepseek.com`. Its Anthropic-compatible API uses protocol **Anthropic Messages** and base URL `https://api.deepseek.com/anthropic`.

API tokens are masked in the Settings UI and stored in Burp's extension preferences. Treat the Burp user profile as sensitive. Remote providers receive model prompts, tool results, and any Burp traffic included in those prompts. Review your provider's data policy before using remote models with confidential targets.

## Tools (overview)

The model only calls names from the live catalog. Highlights:

| Area | Examples |
|---|---|
| Recon | `inspect_scope`, `list_sitemap`, `list_issues`, `search_http_messages` |
| HTTP | `inspect_http_message`, `send_request`, `send_to` |
| Attack | `fuzz_request`, `brute_force`, `crawl_and_audit`, `audit_request` |
| Session | `extract_from_response`, `set_variable`, `remember`, `scan_tokens` |
| Other | Collaborator, Organizer, BChecks, `run_custom_script`, compare, hash/encode |

`fuzz_request` sends payloads through Burp (not only Intruder staging). `brute_force` uses built-in lists (`passwords-top100` / `top250` / `top500`) and clusters responses for likely hits and lockouts.

## Configuration

Persisted in Burp preferences (survives reload):

- Provider protocol, base URL, model, API token, temperature, max tokens / steps / timeout
- Chat/model-list endpoints (Advanced)
- Context budget (characters kept per turn)
- Default approval mode
- Scope enforcement
- Passive scanner (default **off**)

## Build from source

```bash
mvn test package
```

Loadable shaded jar: `target/cybernexis-agent.jar`. Flexmark is bundled; the Montoya API is `provided` by Burp.

## Responsible use

Only test systems you are authorized to test. High-impact tools send live traffic. Keep **Smart** or **Manual** mode unless you trust the current target and model.

## Disclaimer

Cybernexis Agent is an independent open-source extension. It is not affiliated with, endorsed by, or sponsored by PortSwigger Ltd. Burp Suite is a trademark of PortSwigger Ltd.

## License

[MIT](LICENSE)
