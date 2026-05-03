import httpx
import os
import asyncio

MAILPIT_URL = os.getenv("MAILPIT_URL", "http://mailpit:8025")

async def get_latest_message_id() -> str | None:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            res = await client.get(
                f"{MAILPIT_URL}/api/v1/messages"
            )
            if res.status_code == 200:
                messages = res.json().get("messages", [])
                if messages:
                    return messages[0]["ID"]
        return None
    except Exception as e:
        print(f"Mailpit get messages error: {e}")
        return None

async def tag_message(message_id: str, tags: list) -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            res = await client.put(
                f"{MAILPIT_URL}/api/v1/messages",
                json={"IDs": [message_id], "Tags": tags}
            )
            print(f"Mailpit tag result: {res.status_code} — {tags}")
            return res.status_code == 200
    except Exception as e:
        print(f"Mailpit tag error: {e}")
        return False

async def tag_latest_as_malicious(threat_type: str):
    await asyncio.sleep(1)
    message_id = await get_latest_message_id()
    if not message_id:
        print("Mailpit: no message found to tag")
        return
    clean_threat = threat_type.upper().replace(" ", "_").replace("/", "_")
    tags = ["MALICIOUS", "NEEDS_QUARANTINE", clean_threat]
    await tag_message(message_id, tags)
    print(f"Tagged message {message_id} with {tags}")