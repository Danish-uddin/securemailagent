import redis
import json
import os
from datetime import datetime

r = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True
)

SESSION_KEY = "securemailagent:session:emails"
BLOCKLIST_KEY = "securemailagent:session:blocklist"

def write_email_to_session(email_data: dict):
    entry = {
        **email_data,
        "timestamp": datetime.now().isoformat()
    }
    r.rpush(SESSION_KEY, json.dumps(entry))
    r.expire(SESSION_KEY, 86400)

def get_session_emails() -> list:
    try:
        raw = r.lrange(SESSION_KEY, 0, -1)
        return [json.loads(e) for e in raw]
    except:
        return []

def add_to_blocklist(domain: str, ip: str = None):
    r.sadd(BLOCKLIST_KEY, domain)
    if ip:
        r.sadd(BLOCKLIST_KEY, ip)
    r.expire(BLOCKLIST_KEY, 86400)

def is_blocklisted(value: str) -> bool:
    try:
        return r.sismember(BLOCKLIST_KEY, value)
    except:
        return False

def get_session_stats() -> dict:
    emails = get_session_emails()
    return {
        "total": len(emails),
        "threats": len([e for e in emails if e.get("classification") != "safe"]),
        "blocked": len([e for e in emails if e.get("blocked")]),
        "safe": len([e for e in emails if e.get("classification") == "safe"])
    }

def clear_session():
    r.delete(SESSION_KEY)
    r.delete(BLOCKLIST_KEY)