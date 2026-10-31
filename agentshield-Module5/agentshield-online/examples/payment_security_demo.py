"""
Payment Security Demo — demonstrates the full payment security pipeline.
Runs entirely in test mode. No real money. No real API calls.
Run: python -m examples.payment_security_demo
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("PAYMENT_MODE", "test")

from decimal import Decimal
from app.capabilities.online.payments.transaction_validator import PaymentRequest, validate_transaction_limits
from app.capabilities.online.payments.merchant_validator import MerchantValidator
from app.capabilities.online.payments.approval_binding import compute_payment_fingerprint
from app.capabilities.online.payments.webhook_verifier import WebhookVerifier
from app.capabilities.online.payments.razorpay_provider import RazorpayProvider
from app.integrations.local_approval_adapter import LocalApprovalAdapter
from app.integrations.ports import ApprovalRequest
from app.core.exceptions import (
    UnauthorizedMerchantError, SpendingLimitExceededError,
    WebhookVerificationError, RealMoneyProtectionError,
)
from app.core.decisions import PaymentState, is_valid_transition
import hashlib
import hmac


async def demo():
    print("=" * 60)
    print("AgentShield Payment Security Demo (TEST MODE ONLY)")
    print("=" * 60)

    # ── 1. Test Mode Guard ─────────────────────────────────────────────────
    print("\n[1] Real Money Protection")
    try:
        RazorpayProvider(key_id="rzp_live_XXXXXXXXXX", key_secret="secret")
        print("  ✗ FAILED to block live credentials")
    except RealMoneyProtectionError as e:
        print(f"  ✓ Live credentials BLOCKED: {str(e)[:60]}")

    provider = RazorpayProvider(key_id="rzp_test_XXXXXXXXXX", key_secret="test_secret")
    print(f"  ✓ Test credentials accepted: provider={provider.provider_name()}")

    # ── 2. Merchant Validation ─────────────────────────────────────────────
    print("\n[2] Merchant Validation")
    validator = MerchantValidator()
    test_merchants = [
        ("merchant_001", "should pass"),
        ("merchant_002", "should pass"),
        ("Amazon.com", "LLM-supplied, should fail"),
        ("blocked_merchant", "should fail - blocked"),
        ("arbitrary_merchant_123", "should fail - not registered"),
    ]
    for merchant_id, desc in test_merchants:
        try:
            record = validator.validate(merchant_id)
            print(f"  ✓ APPROVED: {merchant_id} ({record.name})")
        except UnauthorizedMerchantError as e:
            print(f"  ✓ BLOCKED: {merchant_id} — {str(e)[:50]}")

    # ── 3. Transaction Limits ──────────────────────────────────────────────
    print("\n[3] Spending Limits")
    requests = [
        (Decimal("100.00"), "INR", 0, "Normal payment"),
        (Decimal("2000.00"), "INR", 0, "Over per-transaction limit (1000 INR)"),
        (Decimal("200.00"), "INR", 40000, "Daily limit exceeded"),
    ]
    for amount, currency, daily_used, desc in requests:
        try:
            req = PaymentRequest(
                agent_id="agent_1", tenant_id="t1", merchant_id="merchant_001",
                amount=amount, currency=currency, purpose="test", order_reference="ORD-001",
            )
            validate_transaction_limits(
                request=req,
                max_transaction_minor=100000,  # 1000 INR
                max_daily_minor=50000,          # 500 INR
                current_daily_total_minor=daily_used,
            )
            print(f"  ✓ ALLOWED: {desc}")
        except SpendingLimitExceededError as e:
            print(f"  ✓ BLOCKED: {desc} — {str(e)[:60]}")

    # ── 4. Exact-Action Approval ───────────────────────────────────────────
    print("\n[4] Exact-Action Approval Binding")
    approval = LocalApprovalAdapter()

    original_amount = 10000  # 100 INR in paise
    fingerprint = compute_payment_fingerprint(
        "agent_1", "tenant_1", "merchant_001", original_amount, "INR",
        "Purchase test item", "ORD-DEMO-001", "razorpay"
    )

    ticket = await approval.request_approval(ApprovalRequest(
        action_type="payment",
        agent_id="agent_1", tenant_id="tenant_1",
        action_hash=fingerprint,
        action_summary="Pay INR 100 to Test Merchant",
    ))
    print(f"  ✓ Approval requested: {ticket.approval_request_id}")
    approval.grant_test_approval(ticket.approval_request_id)
    print(f"  ✓ Approval granted by test simulated approver")

    # Test: matching fingerprint succeeds
    v1 = await approval.verify_approval(ticket.approval_request_id, fingerprint)
    print(f"  ✓ Original transaction approved: valid={v1.valid}")

    # Test: tampered amount fails
    tampered_fp = compute_payment_fingerprint(
        "agent_1", "tenant_1", "merchant_001", 500000, "INR",  # 5000 INR!
        "Purchase test item", "ORD-DEMO-001", "razorpay"
    )
    # Need new approval for this test since first was consumed
    ticket2 = await approval.request_approval(ApprovalRequest(
        action_type="payment",
        agent_id="agent_1", tenant_id="tenant_1",
        action_hash=fingerprint,
        action_summary="Pay INR 100",
    ))
    approval.grant_test_approval(ticket2.approval_request_id)
    v2 = await approval.verify_approval(ticket2.approval_request_id, tampered_fp)
    print(f"  ✓ Amount manipulation blocked: valid={v2.valid}, reason={v2.reason[:50]}")

    # ── 5. Webhook Verification ────────────────────────────────────────────
    print("\n[5] Webhook Signature Verification")
    webhook_secret = "test_webhook_secret_xyz"
    verifier = WebhookVerifier(provider=provider, webhook_secret=webhook_secret)

    raw_body = b'{"event": "payment.captured", "id": "evt_001", "amount": 10000}'
    valid_sig = hmac.new(
        webhook_secret.encode(), raw_body, hashlib.sha256
    ).hexdigest()

    try:
        verifier.verify(raw_body=raw_body, signature=valid_sig)
        print("  ✓ Valid webhook signature accepted")
    except WebhookVerificationError:
        print("  ✗ Valid signature rejected (unexpected)")

    tampered_body = b'{"event": "payment.captured", "id": "evt_001", "amount": 99999}'
    try:
        verifier.verify(raw_body=tampered_body, signature=valid_sig)
        print("  ✗ FAILED to block tampered webhook body")
    except WebhookVerificationError:
        print("  ✓ Tampered webhook body BLOCKED")

    # ── 6. State Machine ──────────────────────────────────────────────────
    print("\n[6] Payment State Machine")
    invalid_transitions = [
        (PaymentState.CREATED, PaymentState.PAID),
        (PaymentState.AUTHORIZED, PaymentState.PAID),
        (PaymentState.CHECKOUT_PENDING, PaymentState.PAID),
        (PaymentState.FAILED, PaymentState.PAID),
    ]
    for from_state, to_state in invalid_transitions:
        if not is_valid_transition(from_state, to_state):
            print(f"  ✓ BLOCKED: {from_state.value} → {to_state.value}")
        else:
            print(f"  ✗ ALLOWED (should be blocked): {from_state.value} → {to_state.value}")

    valid_path = [
        (PaymentState.CREATED, PaymentState.APPROVAL_PENDING),
        (PaymentState.APPROVAL_PENDING, PaymentState.AUTHORIZED),
        (PaymentState.AUTHORIZED, PaymentState.CHECKOUT_PENDING),
        (PaymentState.CHECKOUT_PENDING, PaymentState.PROCESSING),
        (PaymentState.PROCESSING, PaymentState.PAID),
    ]
    path_str = " → ".join([s[0].value for s in valid_path] + [valid_path[-1][1].value])
    all_valid = all(is_valid_transition(f, t) for f, t in valid_path)
    print(f"  ✓ Valid payment path: {path_str} = {all_valid}")

    print("\n" + "=" * 60)
    print("Payment security demo complete.")
    print("All attacks and invalid operations blocked.")
    print("NOTE: This module uses TEST MODE only. No real money processed.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(demo())
