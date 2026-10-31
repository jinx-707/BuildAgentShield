"""Example AI Agent script demonstrating interaction with AgentShield Email Security gateway."""

import asyncio
import json
from uuid import uuid4
import httpx

SERVICE_URL = "http://localhost:8001"
GATEWAY_INTERNAL_TOKEN = "dev-secret-token"
TENANT_ID = "tenant-enterprise-demo"
AGENT_ID = "agent-customer-support-01"


async def run_demo():
    print("==================================================")
    print(" AgentShield Email Security - AI Agent Demo")
    print("==================================================")

    headers = {
        "Authorization": f"Bearer {GATEWAY_INTERNAL_TOKEN}",
        "X-Tenant-ID": TENANT_ID,
        "X-Agent-ID": AGENT_ID,
        "X-Request-ID": f"req-demo-{uuid4()}",
    }

    async with httpx.AsyncClient(base_url=SERVICE_URL, headers=headers, timeout=10.0) as client:
        # 1. Health check
        print("\n1. Checking service health...")
        resp = await client.get("/health")
        print(f"Status {resp.status_code}: {resp.json()}")

        # 2. Check OAuth start endpoint
        print("\n2. Initiating Google OAuth 2.0 flow (Least privilege: read-only)...")
        oauth_start_resp = await client.get("/online/email/oauth/google/start")
        print(f"Status {oauth_start_resp.status_code}")
        data = oauth_start_resp.json()
        print(f"Authorization URL: {data['authorization_url'][:80]}...")
        print(f"CSRF State Token: {data['state']}")
        print(f"Requested Scopes: {data['scopes']}")

        # 3. Query connected accounts (sanitized, zero tokens)
        print("\n3. Listing authorized mailboxes for this agent...")
        accounts_resp = await client.get("/online/email/accounts")
        print(f"Status {accounts_resp.status_code}")
        accounts = accounts_resp.json()
        print(f"Connected accounts count: {len(accounts)}")
        for acc in accounts:
            print(f" - Account {acc['id']}: {acc['account_email']} (Status: {acc['status']})")

        # 4. Demonstrate security enforcement on outbound email (DLP check)
        print("\n4. Testing egress DLP protection with simulated sensitive data...")
        fake_account_id = str(uuid4())
        leaky_send_payload = {
            "account_id": fake_account_id,
            "to": [{"email": "partner@vendor.example.com", "name": "Partner"}],
            "subject": "Confidential details",
            "body_text": "Please find the client credit card: 4111-1111-1111-1111 and AWS key AKIAIOSFODNN7EXAMPLE",
        }
        send_resp = await client.post("/online/email/send", json=leaky_send_payload)
        print(f"Outbound send status: {send_resp.status_code}")
        print(f"Security response: {send_resp.json()}")

        print("\n==================================================")
        print(" AgentShield Email Security Demo Complete")
        print("==================================================")


if __name__ == "__main__":
    try:
        asyncio.run(run_demo())
    except httpx.ConnectError:
        print("\n[!] Service not running on http://localhost:8001.")
        print("Start the service with: uvicorn app.main:app --port 8001")

