from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import smtplib
from email.mime.text import MIMEText
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/send-test-email")
def send_test_email():
    try:
        msg = MIMEText("This is a test email from SecureMailAgent backend.")
        msg['From'] = "attacker@fakecorp.com"
        msg['To'] = "inbox@securemailagent.com"
        msg['Subject'] = "Urgent: Wire Transfer Request"

        with smtplib.SMTP("mailhog", 1025) as server:
            server.send_message(msg)

        return {"status": "sent"}

    except Exception as e:
        return {"status": "error", "detail": str(e)}