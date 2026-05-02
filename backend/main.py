from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import json
import asyncio
from agents.pipeline import pipeline
from memory.redis_client import (
    write_email_to_session,
    get_session_stats,
    add_to_blocklist,
    clear_session
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_connections: list[WebSocket] = []

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/session/stats")
def session_stats():
    return get_session_stats()

@app.post("/session/clear")
def session_clear():
    clear_session()
    return {"status": "cleared"}

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

async def run_pipeline(email_from: str, subject: str, body: str):
    await broadcast({
        "type": "pipeline_start",
        "email_from": email_from,
        "subject": subject
    })

    await asyncio.sleep(0.3)

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
        "blocked": False
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

    write_email_to_session({
        "email_from": email_from,
        "email_subject": subject,
        "email_body": body[:200],
        "classification": result["classification"],
        "threat_type": result["threat_type"],
        "confidence": result["confidence"],
        "severity": result.get("severity", "LOW"),
        "blocked": result.get("blocked", False),
        "reasoning_summary": result["agent_outputs"][1]["reasoning"][:100] if len(result["agent_outputs"]) > 1 else ""
    })

    if result.get("blocked"):
        domain = email_from.split("@")[-1] if "@" in email_from else ""
        if domain:
            add_to_blocklist(domain)

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
        "subject": subject
    })

def send_smtp(from_addr: str, subject: str, body: str):
    msg = MIMEMultipart("alternative")
    msg['From'] = from_addr
    msg['To'] = "inbox@securemailagent.com"
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    host = os.getenv("MAILHOG_SMTP_HOST", "mailhog")
    port = int(os.getenv("MAILHOG_SMTP_PORT", 1025))
    with smtplib.SMTP(host, port) as server:
        server.send_message(msg)

@app.post("/send-email")
async def send_email(payload: dict):
    from_addr = payload.get("from", "test@example.com")
    subject = payload.get("subject", "Test Email")
    body = payload.get("body", "Test body")
    try:
        send_smtp(from_addr, subject, body)
        asyncio.create_task(run_pipeline(from_addr, subject, body))
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
        send_smtp(from_addr, subject, body)
        asyncio.create_task(run_pipeline(from_addr, subject, body))
        return {"status": "sent"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}