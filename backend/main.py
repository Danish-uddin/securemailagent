from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import json
import asyncio
import httpx
from agents.pipeline import pipeline
from memory.redis_client import (
    write_email_to_session,
    get_session_stats,
    add_to_blocklist,
    clear_session
)

MAILPIT_URL = os.getenv("MAILPIT_URL", "http://mailpit:8025")

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        print(f"Startup: clearing Mailpit at {MAILPIT_URL}")
        async with httpx.AsyncClient(timeout=5) as client:
            res = await client.get(f"{MAILPIT_URL}/api/v1/messages")
            messages = res.json().get("messages", [])
            if messages:
                ids = [m["ID"] for m in messages]
                await client.request(
                    "DELETE",
                    f"{MAILPIT_URL}/api/v1/messages",
                    json={"IDs": ids}
                )
                print(f"Cleared {len(ids)} messages on startup")
    except Exception as e:
        print(f"Startup clear error: {e}")
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_connections: list[WebSocket] = []

async def delete_latest_and_resend(
    email_from: str,
    subject: str,
    body: str,
    tags: list
):
    await asyncio.sleep(1)
    try:
        print(f"Startup: clearing Mailpit at {MAILPIT_URL}")
        async with httpx.AsyncClient(timeout=5) as client:
            res = await client.get(f"{MAILPIT_URL}/api/v1/messages")
            messages = res.json().get("messages", [])
            if not messages:
                return
            latest_id = messages[0]["ID"]
            await client.request(
                "DELETE",
                f"{MAILPIT_URL}/api/v1/messages",
                json={"IDs": [latest_id]}
            )
        await send_smtp(email_from, subject, body, tags)
        print(f"Retagged email with: {tags}")
    except Exception as e:
        print(f"Retag error: {e}")




@app.get("/health")
@app.head("/health")
def health():
    return {"status": "ok"}

@app.post("/clear-inbox")
async def clear_inbox():
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            res = await client.get(f"{MAILPIT_URL}/api/v1/messages")
            messages = res.json().get("messages", [])
            if messages:
                ids = [m["ID"] for m in messages]
                await client.request(
                    "DELETE",
                    f"{MAILPIT_URL}/api/v1/messages",
                    json={"IDs": ids}
                )
        return {"status": "cleared"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

@app.get("/test-smtp")
async def test_smtp():
    import smtplib
    from email.mime.text import MIMEText
    host = os.getenv("MAILHOG_SMTP_HOST", "mailpit")
    port = int(os.getenv("MAILHOG_SMTP_PORT", 1025))
    try:
        msg = MIMEText("Test email body")
        msg['From'] = "test@test.com"
        msg['To'] = "inbox@test.com"
        msg['Subject'] = "SMTP Test"
        s = smtplib.SMTP(host, port, timeout=10)
        s.send_message(msg)
        s.quit()
        return {"status": "success", "host": host, "port": port}
    except Exception as e:
        return {"status": "error", "error": str(e), "host": host, "port": port}

@app.get("/session/stats")
def session_stats():
    return get_session_stats()

@app.post("/session/clear")
def session_clear():
    clear_session()
    return {"status": "cleared"}

@app.post("/test-security-events")
async def test_security_events():
    await broadcast({
        "type": "security_event",
        "layer": "INPUT",
        "tool": "Llama Guard",
        "detail": "Prompt injection blocked at Triage Agent input — agents never activated",
        "target": "Triage Agent input layer"
    })
    await asyncio.sleep(0.5)
    await broadcast({
        "type": "security_event",
        "layer": "OUTPUT",
        "tool": "Guardrails AI",
        "detail": "Role confusion blocked — agent attempted unauthorized response format",
        "target": "Orchestration Agent output"
    })
    await asyncio.sleep(0.5)
    await broadcast({
        "type": "security_event",
        "layer": "LEAKAGE",
        "tool": "Presidio",
        "detail": "PII detected and redacted — entities: EMAIL_ADDRESS",
        "target": "Audit Agent log output"
    })
    return {"status": "sent"}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    active_connections.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(ws)

async def broadcast(message: dict):
    for ws in active_connections:
        try:
            await ws.send_text(json.dumps(message))
        except:
            pass

async def run_pipeline(
    email_from: str,
    subject: str,
    body: str,
    mode: str = "ai",
    protection: str = "on"

):
    await broadcast({
        "type": "pipeline_start",
        "email_from": email_from,
        "subject": subject,
        "mode": mode
    })

    await asyncio.sleep(0.3)

    from integrations.virustotal import scan_email_sync
    vt_result = {
        "status": "skipped",
        "clean": True,
        "summary": "No URLs found",
        "details": None
    }
    try:
        vt_result = await asyncio.get_event_loop().run_in_executor(
            None, scan_email_sync, body
        )
    except Exception as e:
        print(f"VT PRE-PIPELINE ERROR: {e}")

    # SOAR ONLY MODE — skip all agents
    if mode == "soar":
        is_malicious = not vt_result.get("clean", True)
        classification = "malicious" if is_malicious else "safe"
        threat_type = "Malicious URL" if is_malicious else "No IOCs Detected"

        await broadcast({
            "type": "agent_update",
            "agent": "soar_only",
            "status": "SOAR_SCAN",
            "reasoning": (
                f"SOAR ONLY MODE — AI agents disabled. "
                f"VirusTotal result: {vt_result.get('summary', 'No URLs found')}. "
                f"{'Malicious URL detected — blocking.' if is_malicious else 'No IOCs found — email passes through undetected. A zero-IOC social engineering attack would not be caught in this mode.'}"
            )
        })
        await asyncio.sleep(0.8)

        tags = ["MALICIOUS", "MALICIOUS_URL"] if is_malicious else ["UNDETECTED", "SOAR_BYPASS"]
        asyncio.create_task(
            delete_latest_and_resend(email_from, subject, body, tags)
        )

        await broadcast({
            "type": "pipeline_complete",
            "classification": classification,
            "threat_type": threat_type,
            "severity": "HIGH" if is_malicious else "NONE",
            "confidence": 1.0 if is_malicious else 0.0,
            "owasp": "",
            "mitre": "",
            "blocked": is_malicious,
            "email_from": email_from,
            "subject": subject,
            "threat_intel": {"virustotal": vt_result},
            "mode": "soar"
        })
        return

    # AI AGENTS MODE — full pipeline
    initial_state = {
        "email_from": email_from,
        "email_subject": subject,
        "email_body": body,
        "llama_guard_result": "",
        "classification": "",
        "confidence": 0.0,
        "route": "",
        "agent_outputs": [],
        "current_agent": "",
        "threat_type": "",
        "severity": "",
        "owasp": "",
        "mitre": "",
        "blocked": False,
        "threat_intel": {"virustotal": vt_result},
        "security_events": [],
        "protection": protection
    }

    result = pipeline.invoke(initial_state)

    for output in result["agent_outputs"]:
        await broadcast({
            "type": "agent_update",
            "agent": output["agent"],
            "status": output["status"],
            "reasoning": output["reasoning"]
        })
        await asyncio.sleep(0.8)

    for event in result.get("security_events", []):
        await broadcast(event)

    import re
    classification = result.get("classification", "")
    threat_type = result.get("threat_type", "UNKNOWN")
    clean_threat = re.sub(
        r'[^A-Z0-9]+', '_',
        threat_type.upper()
    ).strip('_')

    if classification == "safe":
        tags = ["SAFE"]
    else:
        tags = ["MALICIOUS", clean_threat]

    asyncio.create_task(
        delete_latest_and_resend(email_from, subject, body, tags)
    )

    write_email_to_session({
        "email_from": email_from,
        "email_subject": subject,
        "email_body": body[:200],
        "classification": result["classification"],
        "threat_type": result["threat_type"],
        "confidence": result["confidence"],
        "severity": result.get("severity", "LOW"),
        "blocked": result.get("blocked", False),
        "reasoning_summary": (
            result["agent_outputs"][1]["reasoning"][:100]
            if len(result["agent_outputs"]) > 1 else ""
        )
    })

    if result.get("blocked"):
        domain = email_from.split("@")[-1] if "@" in email_from else ""
        if domain:
            add_to_blocklist(domain)

    #print(f"THREAT INTEL BROADCAST: {result.get('threat_intel', {})}")

    await broadcast({
            "type": "pipeline_complete",
            "classification": result["classification"],
            "threat_type": result["threat_type"],
            "severity": result.get("severity", "LOW"),
            "confidence": result["confidence"],
            "owasp": result.get("owasp", ""),
            "mitre": result.get("mitre", ""),
            "blocked": result.get("blocked", False),
            "email_from": email_from,
            "subject": subject,
            "threat_intel": result.get("threat_intel", {}),
            "mode": "ai",
            "agent_outputs": result.get("agent_outputs", [])
        })

async def send_smtp(from_addr: str, subject: str, body: str, tags: list = None):
    mailpit_url = os.getenv("MAILPIT_URL", "http://mailpit:8025")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            payload = {
                "From": {"Email": from_addr, "Name": ""},
                "To": [{"Email": "soc@danish-securemailagent.com", "Name": ""}],
                "Subject": subject,
                "HTML": body
            }
            if tags:
                payload["Tags"] = tags
            res = await client.post(
                f"{mailpit_url}/api/v1/send",
                json=payload
            )
            print(f"Mailpit send: {res.status_code} {res.text}")
    except Exception as e:
        print(f"Mailpit send error: {e}")

@app.post("/send-email")
async def send_email(payload: dict):
    from_addr = payload.get("from", "test@example.com")
    subject = payload.get("subject", "Test Email")
    body = payload.get("body", "Test body")

    mode = payload.get("mode", "ai")
    protection = payload.get("protection", "on")
    try:
        await send_smtp(from_addr, subject, body)
        asyncio.create_task(
            run_pipeline(from_addr, subject, body, mode, protection)
        )

        return {"status": "sent"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

@app.post("/send-test-email")
async def send_test_email():
    from_addr = "cfo@fakecorp-finance.net"
    subject = "Urgent: Board Approval Required"
    body = """Hi,<br><br>
I was reviewing Q3 numbers with Sarah before the board meeting this afternoon.
Legal needs the wire transfer approved before 3pm today — $47,500 to the vendor account.<br><br>
I am back to back in meetings so please handle this directly without going through
the usual chain. I will explain after the meeting.<br><br>John"""
    try:
        await send_smtp(from_addr, subject, body)
        asyncio.create_task(
            run_pipeline(from_addr, subject, body)
        )
        return {"status": "sent"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}