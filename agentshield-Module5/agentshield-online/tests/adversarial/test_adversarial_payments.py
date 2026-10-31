"""
Adversarial payment tests — covers all manipulation and bypass scenarios.
"""
import hashlib
import hmac
import json
import pytest
from decimal import Decimal
from unittest.mock import AsyncMock, patch

from app.capabilities.online.payments.approval_binding import compute_payment_fingerprint
from app.capabilities.online.payments.idempotency import compute_idempotency_key
from app.capabilities.online.payments.transaction_validator import PaymentRequest, validate_transaction_limits
from app.capabilities.online.payments.merchant_validator import MerchantValidator
from app.capabilities.online.payments.webhook_verifier import WebhookVerifier
from app.integrations.local_approval_adapter import LocalApprovalAdapter
from app.integrations.ports import ApprovalRequest
from app.core.exceptions import (
    UnauthorizedMerchantError, SpendingLimitExceededError,
    WebhookVerificationError, RealMoneyProtectionError,
)
from app.core.decisions import PaymentState, is_valid_transition


class TestAmountManipulation:
    """Test that manipulated amounts are caught."""

    def test_approval_hash_changes_on_amount_change(self):
        """After approval, any amount change invalidates it."""
        approved_hash = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR",
            "Test", "ORD-001", "razorpay"
        )
        manipulated_hash = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 1, "INR",  # 1 paise
            "Test", "ORD-001", "razorpay"
        )
        assert approved_hash != manipulated_hash

    def test_floating_point_not_used(self):
        """Amount must use Decimal, not float."""
        req = PaymentRequest(
            agent_id="agent_1", tenant_id="t1",
            merchant_id="m1", amount=Decimal("99.99"),
            currency="INR", purpose="test", order_reference="ORD-001",
        )
        # to_minor_units must be integer
        minor = req.to_minor_units()
        assert isinstance(minor, int)
        assert minor == 9999  # 99.99 * 100


class TestCurrencyManipulation:
    def test_unsupported_currency_rejected(self):
        with pytest.raises(Exception):
            PaymentRequest(
                agent_id="a", tenant_id="t", merchant_id="m",
                amount=Decimal("100"), currency="FAKE",
                purpose="test", order_reference="ORD",
            )

    def test_currency_change_invalidates_approval(self):
        h_inr = compute_payment_fingerprint("a", "t", "m", 10000, "INR", "p", "r", "razorpay")
        h_usd = compute_payment_fingerprint("a", "t", "m", 10000, "USD", "p", "r", "razorpay")
        assert h_inr != h_usd


class TestMerchantSubstitution:
    def test_llm_supplied_merchant_rejected(self):
        """LLM cannot inject an arbitrary merchant."""
        v = MerchantValidator.__new__(MerchantValidator)
        from app.capabilities.online.payments.merchant_validator import MerchantRecord
        v._merchants = {
            "approved_merchant": MerchantRecord(
                id="approved_merchant", name="Legit", status="active"
            )
        }
        v._approved_ids = {"approved_merchant"}
        v._blocked_ids = set()

        with pytest.raises(UnauthorizedMerchantError):
            v.validate("Amazon.com")  # LLM-supplied

    def test_merchant_change_changes_fingerprint(self):
        h1 = compute_payment_fingerprint("a", "t", "merchant_001", 100, "INR", "p", "r", "rzp")
        h2 = compute_payment_fingerprint("a", "t", "attacker_merchant", 100, "INR", "p", "r", "rzp")
        assert h1 != h2


class TestDailyLimitBypass:
    def test_concurrent_requests_each_check_total(self):
        """Each transaction must check CUMULATIVE daily total."""
        req = PaymentRequest(
            agent_id="agent_1", tenant_id="t1", merchant_id="m1",
            amount=Decimal("300.00"), currency="INR",
            purpose="test", order_reference="ORD-003",
        )  # 30000 paise
        # Already spent 20000, daily limit 40000 → 30000 would exceed
        with pytest.raises(SpendingLimitExceededError, match="daily"):
            validate_transaction_limits(
                request=req,
                max_transaction_minor=100000,
                max_daily_minor=40000,
                current_daily_total_minor=20000,
            )

    def test_single_transaction_over_limit_rejected(self):
        req = PaymentRequest(
            agent_id="a", tenant_id="t", merchant_id="m",
            amount=Decimal("5000.00"), currency="INR",
            purpose="test", order_reference="ORD-999",
        )  # 500000 paise
        with pytest.raises(SpendingLimitExceededError, match="per-transaction"):
            validate_transaction_limits(
                request=req,
                max_transaction_minor=100000,  # 1000 INR limit
                max_daily_minor=5000000,
                current_daily_total_minor=0,
            )


class TestDuplicatePaymentPrevention:
    def test_same_params_same_idempotency_key(self):
        k1 = compute_idempotency_key("a", "t", "m", 10000, "INR", "ORD-001")
        k2 = compute_idempotency_key("a", "t", "m", 10000, "INR", "ORD-001")
        assert k1 == k2

    def test_different_agents_different_keys(self):
        k1 = compute_idempotency_key("agent_1", "t", "m", 10000, "INR", "ORD-001")
        k2 = compute_idempotency_key("agent_2", "t", "m", 10000, "INR", "ORD-001")
        assert k1 != k2


class TestApprovalReplay:
    @pytest.mark.asyncio
    async def test_consumed_approval_cannot_be_reused(self):
        adapter = LocalApprovalAdapter()
        fingerprint = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR",
            "payment", "ORD-001", "razorpay"
        )
        ticket = await adapter.request_approval(ApprovalRequest(
            action_type="payment", agent_id="agent_1", tenant_id="tenant_1",
            action_hash=fingerprint, action_summary="Pay INR 100",
        ))
        adapter.grant_test_approval(ticket.approval_request_id)

        # First use succeeds
        v1 = await adapter.verify_approval(ticket.approval_request_id, fingerprint)
        assert v1.valid is True

        # Replay attempt fails
        v2 = await adapter.verify_approval(ticket.approval_request_id, fingerprint)
        assert v2.valid is False

    @pytest.mark.asyncio
    async def test_modified_transaction_invalidates_approval(self):
        adapter = LocalApprovalAdapter()
        original_hash = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR",
            "payment", "ORD-001", "razorpay"
        )
        ticket = await adapter.request_approval(ApprovalRequest(
            action_type="payment", agent_id="agent_1", tenant_id="tenant_1",
            action_hash=original_hash, action_summary="Pay INR 100",
        ))
        adapter.grant_test_approval(ticket.approval_request_id)

        # Try to execute with a different amount
        tampered_hash = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 500000, "INR",  # 5000 INR!
            "payment", "ORD-001", "razorpay"
        )
        v = await adapter.verify_approval(ticket.approval_request_id, tampered_hash)
        assert v.valid is False
        assert "mismatch" in v.reason.lower() or "hash" in v.reason.lower()


class TestWebhookAdversarial:
    @pytest.fixture
    def verifier(self):
        from app.capabilities.online.payments.razorpay_provider import RazorpayProvider
        provider = RazorpayProvider.__new__(RazorpayProvider)
        provider._key_id = "rzp_test_mock"
        provider._key_secret = "test_key_secret"
        return WebhookVerifier(provider=provider, webhook_secret="wh_secret_xyz")

    def _sig(self, body: bytes, secret: str) -> str:
        return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    def test_amount_inflation_in_webhook_caught(self, verifier):
        """Body signed with original amount, then inflated."""
        original = b'{"event":"payment.captured","amount":100}'
        sig = self._sig(original, "wh_secret_xyz")
        tampered = b'{"event":"payment.captured","amount":999999}'
        with pytest.raises(WebhookVerificationError):
            verifier.verify(raw_body=tampered, signature=sig)

    def test_replay_of_different_event_caught(self, verifier):
        """Signature from event A used on event B."""
        event_a = b'{"event":"payment.captured","id":"evt_001"}'
        sig_a = self._sig(event_a, "wh_secret_xyz")
        event_b = b'{"event":"payment.captured","id":"evt_002"}'
        with pytest.raises(WebhookVerificationError):
            verifier.verify(raw_body=event_b, signature=sig_a)

    def test_wrong_secret_rejected(self, verifier):
        body = b'{"event":"payment.captured"}'
        sig = self._sig(body, "wrong_secret")
        with pytest.raises(WebhookVerificationError):
            verifier.verify(raw_body=body, signature=sig)


class TestPaymentStatusSpoofing:
    def test_direct_paid_state_transition_blocked(self):
        """Cannot jump directly to PAID without going through PROCESSING."""
        assert not is_valid_transition(PaymentState.CREATED, PaymentState.PAID)
        assert not is_valid_transition(PaymentState.AUTHORIZED, PaymentState.PAID)
        assert not is_valid_transition(PaymentState.CHECKOUT_PENDING, PaymentState.PAID)
        assert not is_valid_transition(PaymentState.APPROVAL_PENDING, PaymentState.PAID)

    def test_only_processing_can_transition_to_paid(self):
        """PAID can only be reached from PROCESSING."""
        assert is_valid_transition(PaymentState.PROCESSING, PaymentState.PAID)
        for state in PaymentState:
            if state != PaymentState.PROCESSING:
                assert not is_valid_transition(state, PaymentState.PAID), (
                    f"{state} should not transition to PAID"
                )
