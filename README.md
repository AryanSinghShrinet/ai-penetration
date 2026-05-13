# ai-pentester

An AI-powered penetration testing and bug bounty framework that combines automated scanning, machine-learning anomaly detection, and LLM-assisted attack planning. Designed for use against targets authorised through platforms such as HackerOne and Bugcrowd.

> **Legal notice:** Only use this tool against systems you are explicitly authorised to test. Unauthorised use is illegal and unethical. The authors accept no liability for misuse.

---

## Features

- **AI attack planner** — Claude / GPT-driven ReAct-style reasoning loop that prioritises test cases based on recon findings
- **21 vulnerability classes** — XSS, SQLi, SSRF, IDOR, SSTI, LFI, RFI, XXe, CORS, LDAP injection, command injection, brute-force, security headers, and more
- **ML anomaly detection** — Isolation Forest + MLP ensemble trained on response behaviour; self-learning pipeline records scan results for retraining
- **Modular recon pipeline** — subdomain discovery, JS route extraction (React / Vue / Angular / webpack), parameter mining, passive OSINT, attack surface scoring
- **PoC generation** — structured JSON + Markdown proof-of-concept reports per finding
- **Web dashboard** — Flask-based UI for live scan progress, vulnerability details, and attack-chain visualisation
- **Attack graph chaining** — multi-step exploit chain builder using a directed graph model

---

## Architecture

```
main.py
└── core/orchestrator.py          ← 5-phase scan loop
    ├── Phase 1: Recon            ← crawler, subdomain discovery, parameter miner
    ├── Phase 2: AI Planning      ← ai_reasoning/attack_planner.py (LLM)
    ├── Phase 3: Execution        ← core/executor.py + core/worker.py (threaded)
    ├── Phase 4: ML Analysis      ← core/ml_analysis/ (anomaly detection)
    └── Phase 5: Reporting        ← reporting/ (PoC + Markdown + JSON)
```

---

## Quick start

### 1. Prerequisites

- Python 3.10+
- An Anthropic or OpenAI API key (for the AI planning layer)

### 2. Install

```bash
#git clone https://github.com/<your-username>/ai-pentester.git
cd ai-pentester
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure

```bash
# Set your AI API key (at least one is required)
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENAI_API_KEY="sk-..."

# Optional: configure session auth (never commit real credentials)
export SESSION_COOKIE="sessionid=<value>"
```

Edit `config/settings.yaml` to set your target and scan parameters:

```yaml
target: "https://your-authorised-target.com"

scan:
  threads: 4
  max_requests: 2000
  timeout: 15
```

Edit `config/scope.yaml` to define allowed domains and paths.

### 4. Run

```bash
# Full scan
python main.py --target https://your-target.com

# Specify output directory
python main.py --target https://your-target.com --output ./my-reports

# Dry-run (no HTTP requests sent)
python main.py --target https://your-target.com --dry-run

# Web dashboard
python web/app.py
```

---

## Configuration reference

| File | Purpose |
|---|---|
| `config/settings.yaml` | Target URL, thread count, request limits, proxy, TLS |
| `config/scope.yaml` | Allowed domains, paths, and exclusion rules |
| `config/auth.yaml` | Auth type (cookie / bearer / header) — use env vars for values |
| `config/ai.yaml` | AI model selection, temperature, max tokens |
| `config/payload_sources.yaml` | External payload feed URLs |
| `config/chain_patterns.yaml` | Attack chain definitions |

---

## Vulnerability classes

| Category | Covered |
|---|---|
| Injection | SQLi, XSS (reflected/stored/DOM), SSTI, LDAP injection, command injection, XXE |
| Access control | IDOR, auth bypass, brute-force |
| Server-side | SSRF, LFI, RFI, file upload |
| Configuration | CORS misconfiguration, security headers, information disclosure |
| Business logic | Workflow abuse, rate-limit bypass |

---

## ML pipeline

Train the ML classifier on existing scan data:

```bash
python train_ml.py
```

The self-learning pipeline (`core/ml_analysis/self_learner.py`) automatically records confirmed and refuted findings during scans and periodically retrains the model.

---

## Project layout

```
ai-pentester/
├── ai_reasoning/       AI attack planning (LLM interface)
├── analysis/           Response analysis, anomaly detection
├── business_logic/     Workflow and business-logic test cases
├── config/             YAML configuration files
├── core/               Scan engine (orchestrator, executor, worker, payloads…)
│   ├── ml_analysis/    ML classifier, predictor, self-learner
│   ├── recon/          Crawler, passive recon, scoring
│   └── scanner/        Attack surface, vuln templates, scheduler
├── discovery/          Endpoint discovery, parameter mining
├── fuzzing/            Adaptive fuzzer, payload mutation
├── graph/              Attack chain graph builder
├── ml/                 Standalone ML module (features, dataset loader)
├── recon/              Top-level recon (subdomain discovery, OSINT)
├── reporting/          PoC generator, report builder, verifier
├── vulnerability/      Per-class vulnerability modules
├── web/                Flask dashboard and templates
├── main.py             CLI entry point
├── train_ml.py         ML training script
└── requirements.txt
```

---

## Requirements

See `requirements.txt`. Key dependencies:

- `requests`, `flask`, `pyyaml`
- `scikit-learn`, `numpy`, `pandas`, `joblib`
- `anthropic` or `openai` (AI planning layer)

---

## Contributing

1. Fork the repository and create a feature branch
2. Write tests for new vulnerability classes or modules
3. Open a pull request with a clear description of the change

---

## Disclaimer

This tool is intended for **authorised security testing only**. Always obtain written permission before scanning any system. The authors are not responsible for any damage caused by misuse of this software.
