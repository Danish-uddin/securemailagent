# 🔐 SecureMailAgent
### AI-Powered Email Security Operations Center

> Built by **Danish Mohammed** — Cybersecurity Professional | Cloud Security · AppSec · AI Security  
> 🔗 [Live Demo](https://securemailagent-frontend.onrender.com) ·

---

## What Is This?

SecureMailAgent is a multi-agent AI system that defends email workflows against threat categories that traditional SOAR systems completely miss.

**The core insight:** SOAR tools rely on IOC matching — known bad URLs, malicious attachments, flagged sender domains. A skilled attacker sends an email with no IOCs whatsoever. Clean domain. No URLs. No attachments. Just carefully crafted language designed to manipulate a human into wiring money, sharing credentials, or bypassing approval chains.

**SecureMailAgent catches these.** Five specialized LangGraph agents analyze every email through semantic, behavioral, and contextual lenses — not just IOC matching.

---

## Live Demo

🌐 **[securemailagent-frontend.onrender.com](https://securemailagent-frontend.onrender.com)**

> ⚡ Free tier hosting — first load may take 30 seconds to wake up. Subsequent interactions are fast.

---

## Three Demo Modes

The dashboard has a toggle that tells the complete story in 3 minutes:

| Mode | What Happens | What It Shows |
|---|---|---|
| ⚡ **SOAR Only** | Only VirusTotal IOC scanning | Zero-IOC BEC passes through undetected |
| 🧠 **AI Agents + 🛡️ Protection OFF** | Agents run, security layers disabled | PII leaks into reasoning, agents vulnerable to manipulation |
| 🧠 **AI Agents + 🛡️ Protection ON** | Full pipeline with all defenses | Llama Guard blocks injections, Presidio redacts PII |

---

## The Five Agents

```
Email → Llama Guard → Semantic Intent → AI Threat → Behavioral → Orchestration → Audit
              ↓ (if BLOCKED)                              ↓ (borderline)
           Audit (fast pass)                       Human Review Queue
```

### 1. 🎯 Semantic Intent Agent
Detects zero-IOC social engineering through psychological pattern analysis. No bad URLs needed — catches BEC, executive impersonation, and authority manipulation purely through understanding intent.

**Protected by:** Llama Guard input screening

### 2. 🧠 AI Pipeline Threat Agent
Specifically targets attacks designed to manipulate AI systems — prompt injections hidden in email bodies that a human would never notice but an AI assistant would process as instructions.

**Protected by:** Self-aware detection patterns

### 3. 📊 Behavioral Analysis Agent
Reads Redis session history across all emails this session. Detects coordinated campaigns — three emails from three different domains targeting the same financial workflow — even when each individual email looks low-risk.

**Protected by:** Redis integrity layer

### 4. ⚡ Response Orchestration Agent
Executes five structured response steps automatically: containment, escalation, evidence collection, threat intelligence feedback, recipient alerting. Replaces 15-20 minutes of manual SOC analyst work.

**Protected by:** Guardrails AI output validation + Presidio PII redaction

### 5. 📋 Audit Agent
Maps every incident to OWASP LLM Top 10 and MITRE ATLAS frameworks. Auto-generates compliance-ready documentation for every threat detected.

**Protected by:** Presidio output scanning

---

## Attack Scenarios

### Email Attack Launcher
| Attack | Threat Category | Caught By |
|---|---|---|
| 🎭 Zero-IOC Social Eng | BEC / Wire Transfer | Semantic Intent Agent |
| 🧠 AI Pipeline Inject | LLM Prompt Injection | AI Threat Agent |
| 📋 Indirect Injection | Phishing with IOC | VirusTotal + Semantic |
| 🎯 Coordinated Campaign | Multi-vector Campaign | Behavioral Agent |
| 💼 Exec Impersonation | Authority Bias Attack | Semantic Intent Agent |
| 🔗 AI Assistant Hijack | Indirect Injection | AI Threat Agent |
| 🎯 SOAR Only Malicious | Known Malicious URL | VirusTotal only |

### Agent Attack Console
| Attack | Targets | Blocked By |
|---|---|---|
| 💉 Direct Prompt Inject | Agent reasoning | Llama Guard |
| 🎭 Role Confusion | Agent identity | Guardrails AI |
| 📖 Fictional Framing | Context boundary | Llama Guard |
| 📜 Context Window Poison | Memory injection | Behavioral Agent |
| 🔀 Indirect HTML Inject | Hidden payload | AI Threat Agent |
| 🧩 Multi-turn Manipulation | Session state | Behavioral Agent |
| 🔓 PII Leak Test | Data exfiltration | Presidio (ON vs OFF) |

---

## Tech Stack

```
AI/ML Pipeline          Security Layers         Infrastructure
─────────────────       ─────────────────       ─────────────────
LangGraph               Llama Guard             FastAPI
Groq (LLM)             Guardrails AI           WebSockets
LangSmith              Presidio (PII)          Redis
                        VirusTotal              Mailpit
                                                Docker
                                                Render
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   React Dashboard                    │
│  SOAR/AI Toggle · Protection Toggle · Live Pipeline  │
└──────────────────────┬──────────────────────────────┘
                       │ WebSocket
┌──────────────────────▼──────────────────────────────┐
│                  FastAPI Backend                     │
│                                                      │
│  ┌─────────┐    ┌──────────────────────────────┐    │
│  │VirusTotal│    │      LangGraph Pipeline       │    │
│  │  (pre)   │    │                              │    │
│  └─────────┘    │  Llama Guard → Semantic →    │    │
│                  │  AI Threat → Behavioral →   │    │
│                  │  Orchestration → Audit       │    │
│                  └──────────────────────────────┘    │
│                                                      │
│  ┌──────────┐   ┌──────────┐   ┌───────────────┐   │
│  │  Redis   │   │ Presidio │   │  Guardrails   │   │
│  │ (memory) │   │  (PII)   │   │  (output val) │   │
│  └──────────┘   └──────────┘   └───────────────┘   │
└──────────────────────────────────────────────────────┘
                       │ SMTP / HTTP API
┌──────────────────────▼──────────────────────────────┐
│                    Mailpit                           │
│           Live Inbox · Threat Tags                   │
└──────────────────────────────────────────────────────┘
```

---

## Run Locally

### Prerequisites
- Docker Desktop
- API Keys: Groq, VirusTotal

### Setup

```bash
# Clone the repo
git clone https://github.com/Danish-uddin/securemailagent.git
cd securemailagent

# Copy env file and fill in your keys
cp .env.example .env

# Start all services
docker compose up --build
```

### Access
- **Dashboard:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **Mailpit Inbox:** http://localhost:8025

---

## Environment Variables

```env
GROQ_API_KEY=          # Free at console.groq.com
VIRUSTOTAL_API_KEY=    # Free at virustotal.com
REDIS_HOST=            # Defaults to 'redis' in Docker
REDIS_PORT=            # Defaults to 6379
MAILPIT_URL=           # Defaults to http://mailpit:8025
MAILHOG_SMTP_HOST=     # Defaults to 'mailpit'
MAILHOG_SMTP_PORT=     # Defaults to 1025
```

---

## Project Structure

```
securemailagent/
├── backend/
│   ├── agents/
│   │   ├── pipeline.py          # LangGraph 5-agent pipeline
│   │   └── prompts.py           # All agent system prompts
│   ├── integrations/
│   │   └── virustotal.py        # VT scanning
│   ├── security/
│   │   ├── presidio.py          # PII detection & redaction
│   │   └── guardrails_check.py  # Output validation
│   ├── memory/
│   │   └── redis_client.py      # Session memory
│   └── main.py                  # FastAPI + WebSocket server
├── frontend/
│   └── src/
│       └── App.jsx              # React SOC dashboard
├── docker-compose.yml
├── render.yaml
└── .env.example
```

---

## Key Design Decisions

**Why LangGraph?** State machine architecture gives precise control over agent routing — borderline threats go to human review, clear threats get contained, blocked injections skip to audit.

**Why Groq?** Near-instant LLM inference. Pipeline completes in 8-15 seconds instead of 45+ seconds with other providers.

**Why Mailpit?** Lightweight SMTP server with REST API — enables real-time email tagging and threat visualization without external email infrastructure.

**Why Redis for behavioral memory?** Agents need cross-email session context to detect coordinated campaigns. Redis gives sub-millisecond reads on session history.

---

## OWASP LLM Top 10 Coverage

| OWASP Category | Attack Demonstrated | Defense Layer |
|---|---|---|
| LLM01 — Prompt Injection | Direct + Indirect Injection | Llama Guard |
| LLM02 — Insecure Output | Role Confusion, Fictional Framing | Guardrails AI |
| LLM06 — Sensitive Info | PII Leak Test | Presidio |
| LLM08 — Excessive Agency | Agent Config Spoof | Llama Guard |
| LLM09 — Overreliance | SOAR Bypass Demo | Multi-agent validation |

---

## Built By

**Danish Mohammed**  
Cybersecurity Professional — Cloud Security · Vulnerability Management · IAM · AppSec  

*SecureMailAgent demonstrates practical AI security engineering — not just using AI, but securing AI pipelines against the next generation of threats.*