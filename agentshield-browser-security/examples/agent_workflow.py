import os, httpx

BASE = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
TOKEN = os.getenv("API_AUTH_TOKEN", "")
headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
agent = "agent-demo"

with httpx.Client(base_url=BASE, headers=headers, timeout=30) as c:
    r = c.post("/v1/browser/session", json={}, headers={"X-Agent-Id": agent})
    r.raise_for_status()
    sid = r.json()["session_id"]
    c.post(f"/v1/browser/navigate", json={"session_id": sid, "url": "https://example.com"}, headers={"X-Agent-Id": agent}).raise_for_status()
    ext = c.post("/v1/browser/extract", json={"session_id": sid}, headers={"X-Agent-Id": agent})
    print(ext.json().get("title"))
    c.delete(f"/v1/browser/session/{sid}", headers={"X-Agent-Id": agent}).raise_for_status()
    print("closed", sid)
