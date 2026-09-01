# Cybernexis Burp Suite Pro Agent

**Agentic security testing inside [Burp Suite](https://portswigger.net/burp), driven by a model you run locally with [Ollama](https://ollama.com).**

[![Java](https://img.shields.io/badge/Java-11+-ED8B00?logo=openjdk&logoColor=white)](#requirements)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Professional-FF6633)](#requirements)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-000000)](#requirements)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Cybernexis Agent is a Burp extension: chat with an LLM that can inspect scope, sitemap, and issues, send requests, fuzz, spray credentials, and write findings back into Burp. Traffic and prompts stay on your machine.

It is **not** an LLM. You bring the model (any tool-capable Ollama model). It is **not** affiliated with PortSwigger.

```mermaid
flowchart LR
    You((You)) --> Chat[Cybernexis chat]
    Chat --> Ollama[Local Ollama]
    Ollama --> Tools[Tools]
    Tools --> Burp[Burp Suite]
    Burp -->|scope · HTTP · findings| Chat
```

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
- **Approvals** — Manual, Smart (high-impact tools escalate), or Auto
- **Host focus** — naming a URL locks that task to that host (`www.` included; sibling subdomains stay out)
- **Variables** — `extract_from_response` → `{{csrf}}` in later `send_request` / `fuzz_request` / `brute_force`
- **Target memory** — durable per-host notes and a token map (JWT, UUID, CSRF, session cookies) across tasks
- **Live fuzzing** — status, length, reflection, error signatures, timing anomalies (blind SSRF / command injection)
- **Password spray** — built-in wordlists and `{{pass}}` / `{{user}}` markers; no huge lists pasted into the model
- **Optional passive scanner** — off by default; in-scope traffic → local model → native Burp issues (`Cybernexis:`)
- **Right-click** — *Send to Cybernexis* from Proxy, Repeater, Target, or Scanner
- **Safety** — out-of-scope action tools can be blocked; conversation context is budgeted so long runs stay stable

## Requirements

| | |
|---|---|
| JDK | 11+ (Burp must run on a JDK if you use `run_custom_script`) |
| Maven | 3.8+ |
| Burp | Professional 2024.x+ (built against Montoya API `2025.12`) |
| Ollama | running at `http://127.0.0.1:11434` |
| Model | tool-capable, e.g. `orcarouter/Qwen3.8-27B-Uncensored:latest` |

## Install

```bash
git clone https://github.com/caglarcakici/cybernexis-burp-agent.git
cd cybernexis-burp-agent
mvn -q package -DskipTests
```

1. Burp → **Extensions → Add** → type **Java** → select `target/cybernexis-agent.jar`
2. Open the **Cybernexis** suite tab
3. **Settings** — set Ollama base URL and model, **Test connection**, **Save**

Unload any older build of the extension first so you do not get two suite tabs.

## Usage

Ask in **Chat**, for example:

- *What's in scope?*
- *List the sitemap for this host*
- *Inspect issue 3*
- *Send request 42 to Repeater*
- *Extract the CSRF token from message 10 and brute-force the login*

Right-click any HTTP message → **Send to Cybernexis** to start a task with that exchange loaded.

| Mode | Behaviour |
|---|---|
| **Manual** | Confirm every action tool |
| **Smart** | Auto-run most tools; ask for crawl, audit, fuzz, brute-force, scripts, and live `send_request` |
| **Auto** | Run everything |

Enable **Block action tools targeting out-of-scope hosts** in Settings unless you intend otherwise.

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

- Ollama URL, model, temperature, max tokens / steps / timeout
- Context budget (characters kept per turn)
- Default approval mode
- Scope enforcement
- OpenAI-compatible `/v1` endpoint (optional)
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
