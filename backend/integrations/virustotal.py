import httpx
import os
import re
import base64
import time
from datetime import datetime

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

_last_call_time = None
RATE_LIMIT_SECONDS = 16

def extract_urls(text: str) -> list:
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)

def _wait_for_rate_limit():
    global _last_call_time
    if _last_call_time:
        elapsed = time.time() - _last_call_time
        if elapsed < RATE_LIMIT_SECONDS:
            time.sleep(RATE_LIMIT_SECONDS - elapsed)
    _last_call_time = time.time()

def _format_date(timestamp: int) -> str:
    if not timestamp:
        return "Unknown"
    try:
        return datetime.fromtimestamp(timestamp).strftime("%b %d %Y")
    except:
        return "Unknown"

def _time_ago(timestamp: int) -> str:
    if not timestamp:
        return "Unknown"
    try:
        diff = datetime.now() - datetime.fromtimestamp(timestamp)
        if diff.days > 0:
            return f"{diff.days} days ago"
        hours = diff.seconds // 3600
        if hours > 0:
            return f"{hours} hours ago"
        return f"{diff.seconds // 60} minutes ago"
    except:
        return "Unknown"

def scan_url_sync(url: str) -> dict:
    if not API_KEY:
        return {
            "status": "skipped",
            "clean": True,
            "summary": "No API key configured",
            "details": None
        }
    try:
        _wait_for_rate_limit()
        url_id = base64.urlsafe_b64encode(
            url.encode()).decode().rstrip("=")

        with httpx.Client(timeout=10) as client:
            res = client.get(
                f"{BASE_URL}/urls/{url_id}",
                headers={"x-apikey": API_KEY}
            )

            if res.status_code == 200:
                attrs = res.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                total = sum(stats.values()) or 1
                reputation = attrs.get("reputation", 0)
                votes = attrs.get("total_votes", {})
                first_seen = attrs.get("first_submission_date", 0)
                last_scanned = attrs.get("last_analysis_date", 0)
                final_url = attrs.get("last_final_url", url)

                print(f"VT SUCCESS: {malicious}/{total} engines flagged")

                return {
                    "status": "success",
                    "clean": malicious == 0 and suspicious == 0,
                    "summary": f"{malicious}/{total} engines flagged" if malicious > 0 else f"Clean — 0/{total} engines",
                    "details": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "total_engines": total,
                        "reputation": reputation,
                        "votes_harmless": votes.get("harmless", 0),
                        "votes_malicious": votes.get("malicious", 0),
                        "first_seen": _format_date(first_seen),
                        "last_scanned": _time_ago(last_scanned),
                        "redirected": final_url != url,
                        "final_url": final_url
                    }
                }

            elif res.status_code == 404:
                print(f"VT: URL not in database")
                return {
                    "status": "not_found",
                    "clean": True,
                    "summary": "URL not in VT database",
                    "details": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "total_engines": 0,
                        "reputation": 0,
                        "votes_harmless": 0,
                        "votes_malicious": 0,
                        "first_seen": "Never scanned",
                        "last_scanned": "Never",
                        "redirected": False,
                        "final_url": url
                    }
                }

            elif res.status_code == 429:
                print(f"VT: Rate limited")
                return {
                    "status": "rate_limited",
                    "clean": True,
                    "summary": "Rate limit hit — skipped",
                    "details": None
                }

            print(f"VT: API error {res.status_code}")
            return {
                "status": "skipped",
                "clean": True,
                "summary": f"API error {res.status_code}",
                "details": None
            }

    except Exception as e:
        print(f"VT EXCEPTION: {e}")
        return {
            "status": "error",
            "clean": True,
            "summary": "Scan skipped",
            "details": None
        }

def scan_email_sync(email_body: str) -> dict:
    urls = extract_urls(email_body)
    print(f"VT: Found {len(urls)} URLs: {urls}")
    if not urls:
        return {
            "status": "no_urls",
            "clean": True,
            "summary": "No URLs found in email",
            "details": None
        }
    return scan_url_sync(urls[0])