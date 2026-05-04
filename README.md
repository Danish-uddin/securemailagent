# SecureMailAgent
### AI-Powered Email Security Operations Center
**Built by Danish Mohammed**

A multi-agent LangGraph system defending AI-assisted email workflows against 
threat categories invisible to SOAR systems.

# SecureMailAgent — AI-Powered Email Security Operations Center

A multi-agent LangGraph system defending AI-assisted email workflows against 
threat categories invisible to SOAR systems.

## Three Modes
- **SOAR Only** — VirusTotal IOC scanning only
- **AI Agents + Protection OFF** — LLM agents without defense layers
- **AI Agents + Protection ON** — Full pipeline with Llama Guard, Guardrails AI, Presidio

## Stack
LangGraph · Groq · Llama Guard · Guardrails AI · Presidio · VirusTotal · 
Redis · LangSmith · FastAPI · WebSockets · React · Mailpit · Docker

## Run Locally
1. Clone the repo
2. Copy `.env.example` to `.env` and fill in your API keys
3. `docker compose up --build`
4. Open `http://localhost:3000`

## API Keys Required
- GROQ_API_KEY — free at console.groq.com
- VIRUSTOTAL_API_KEY — free at virustotal.com