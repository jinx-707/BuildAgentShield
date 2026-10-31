"""
Payment security tests — transaction validation, merchant checks,
spending limits, idempotency, approval binding, webhook verification.
"""
import hashlib
import hmac
import json
import pytest
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

from app.capabilities.online.payments.transaction_validator import (
    PaymentRequest, validate_transaction_limits,
)
from app.capabilities.online.payments.merchant_validator import MerchantValidator
from app.capabilities.online.payments.approval_binding import compute_payment_fingerprint
from app.capabilities.online.payments.webhook_verifier import WebhookVerifier
from app.core.exceptions import (
    PaymentError,
    UnauthorizedMerchantError,
    SpendingLimitExceededError,
    WebhookVerificationError,
    RealMoneyProtectionError,
)
from app.core.decisions import PaymentState, is_valid_transition


# ── Transaction Validator ────────────────────────────────────────────────────

class TestTransactionValidator:
    def _make_request(self, **kwargs):
        defaults = dict(
            agent_id="agent_1",
            tenant_id="tenant_1",
            merchant_id="merchant_001",
            amount=Decimal("100.00"),
            currency="INR",
            purpose="Test payment",
            order_reference="ORD-001",
        )
        defaults.update(kwargs)
        return PaymentRequest(**defaults)

    def test_valid_request_passes(self):
        req = self._make_request()
        assert req.amount == Decimal("100.00")
        assert req.currency == "INR"

    def test_zero_amount_rejected(self):
        with pytest.raises(Exception):
            self._make_request(amount=Decimal("0"))

    def test_negative_amount_rejected(self):
        with pytest.raises(Exception):
            self._make_request(amount=Decimal("-50.00"))

    def test_invalid_currency_rejected(self):
        with pytest.raises(Exception, match="Currency"):
            self._make_request(currency="XYZ")

    def test_to_minor_units_correct_inr(self):
        req = self._make_request(amount=Decimal("100.00"), currency="INR")
        assert req.to_minor_units() == 10000  # 100 INR = 10000 paise

    def test_to_minor_units_correct_usd(self):
        req = self._make_request(amount=Decimal("10.50"), currency="USD")
        assert req.to_minor_units() == 1050  # 10.50 USD = 1050 cents

    def test_order_reference_alphanumeric_only(self):
        with pytest.raises(Exception):
            self._make_request(order_reference="ORD 001 <script>")

    def test_transaction_limit_enforced(self):
        req = self._make_request(amount=Decimal("200.00"), currency="INR")  # 20000 paise
        with pytest.raises(SpendingLimitExceededError, match="per-transaction"):
            validate_transaction_limits(
                request=req,
                max_transaction_minor=10000,  # 100 INR limit
                max_daily_minor=100000,
                current_daily_total_minor=0,
            )

    def test_daily_limit_enforced(self):
        req = self._make_request(amount=Decimal("100.00"), currency="INR")  # 10000 paise
        with pytest.raises(SpendingLimitExceededError, match="daily"):
            validate_transaction_limits(
                request=req,
                max_transaction_minor=50000,
                max_daily_minor=9000,    # already nearly at limit
                current_daily_total_minor=8000,
            )

    def test_within_limits_passes(self):
        req = self._make_request(amount=Decimal("100.00"), currency="INR")
        # Should not raise
        validate_transaction_limits(
            request=req,
            max_transaction_minor=100000,
            max_daily_minor=500000,
            current_daily_total_minor=0,
        )


# ── Merchant Validator ────────────────────────────────────────────────────────

class TestMerchantValidator:
    @pytest.fixture
    def validator(self):
        v = MerchantValidator.__new__(MerchantValidator)
        from app.capabilities.online.payments.merchant_validator import MerchantRecord
        v._merchants = {
            "merchant_001": MerchantRecord(
                id="merchant_001", name="Test Merchant", status="active"
            ),
            "blocked_merchant": MerchantRecord(
                id="blocked_merchant", name="Bad Merchant", status="blocked"
            ),
        }
        v._approved_ids = {"merchant_001", "merchant_002"}
        v._blocked_ids = {"blocked_merchant"}
        return v

    def test_valid_merchant_passes(self, validator):
        record = validator.validate("merchant_001")
        assert record.name == "Test Merchant"

    def test_unknown_merchant_rejected(self, validator):
        with pytest.raises(UnauthorizedMerchantError, match="not in the approved"):
            validator.validate("unknown_merchant_llm_supplied")

    def test_blocked_merchant_rejected(self, validator):
        with pytest.raises(UnauthorizedMerchantError, match="blocked"):
            validator.validate("blocked_merchant")

    def test_arbitrary_llm_merchant_rejected(self, validator):
        # LLM tries to use an arbitrary merchant name
        with pytest.raises(UnauthorizedMerchantError):
            validator.validate("Amazon")

    def test_merchant_substitution_blocked(self, validator):
        # Attacker tries to substitute a legitimate-looking but unregistered merchant
        with pytest.raises(UnauthorizedMerchantError):
            validator.validate("merchant_001_fake")


# ── Approval Binding ──────────────────────────────────────────────────────────

class TestApprovalBinding:
    def test_same_params_same_fingerprint(self):
        h1 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR",
            "Test payment", "ORD-001", "razorpay"
        )
        h2 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR",
            "Test payment", "ORD-001", "razorpay"
        )
        assert h1 == h2

    def test_amount_change_changes_fingerprint(self):
        h1 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR",
            "Test payment", "ORD-001", "razorpay"
        )
        h2 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 20000, "INR",  # changed
            "Test payment", "ORD-001", "razorpay"
        )
        assert h1 != h2

    def test_merchant_change_changes_fingerprint(self):
        h1 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR",
            "Test", "ORD-001", "razorpay"
        )
        h2 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_002", 10000, "INR",  # changed
            "Test", "ORD-001", "razorpay"
        )
        assert h1 != h2

    def test_currency_change_changes_fingerprint(self):
        h1 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR", "T", "ORD", "razorpay"
        )
        h2 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "USD", "T", "ORD", "razorpay"
        )
        assert h1 != h2

    def test_agent_change_changes_fingerprint(self):
        h1 = compute_payment_fingerprint(
            "agent_1", "tenant_1", "merchant_001", 10000, "INR", "T", "ORD", "razorpay"
        )
        h2 = compute_payment_fingerprint(
            "agent_2", "tenant_1", "merchant_001", 10000, "INR", "T", "ORD", "razorpay"
        )
        assert h1 != h2


# ── Webhook Verifier ──────────────────────────────────────────────────────────

class TestWebhookVerifier:
    @pytest.fixture
    def provider_and_secret(self):
        from app.capabilities.online.payments.razorpay_provider import RazorpayProvider
        provider = RazorpayProvider.__new__(RazorpayProvider)
        provider._key_id = "rzp_test_mock"
        provider._key_secret = "test_secret_key"
        secret = "webhook_secret_123"
        return provider, secret

    @pytest.fixture
    def verifier(self, provider_and_secret):
        provider, secret = provider_and_secret
        return WebhookVerifier(provider=provider, webhook_secret=secret)

    def _make_signature(self, body: bytes, secret: str) -> str:
        return hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()

    def test_valid_signature_passes(self, verifier):
        body = b'{"event": "payment.captured", "id": "evt_001"}'
        sig = self._make_signature(body, "webhook_secret_123")
        # Should not raise
        verifier.verify(raw_body=body, signature=sig)

    def test_forged_signature_rejected(self, verifier):
        body = b'{"event": "payment.captured", "id": "evt_001"}'
        fake_sig = "deadbeef" * 8  # wrong signature
        with pytest.raises(WebhookVerificationError, match="Invalid"):
            verifier.verify(raw_body=body, signature=fake_sig)

    def test_empty_signature_rejected(self, verifier):
        body = b'{"event": "payment.captured"}'
        with pytest.raises(WebhookVerificationError, match="missing"):
            verifier.verify(raw_body=body, signature="")

    def test_modified_body_rejected(self, verifier):
        original_body = b'{"event": "payment.captured", "amount": 100}'
        sig = self._make_signature(original_body, "webhook_secret_123")
        # Attacker modifies body after signing
        tampered_body = b'{"event": "payment.captured", "amount": 99999}'
        with pytest.raises(WebhookVerificationError):
            verifier.verify(raw_body=tampered_body, signature=sig)

    def test_no_secret_configured_rejected(self):
        from app.capabilities.online.payments.razorpay_provider import RazorpayProvider
        provider = RazorpayProvider.__new__(RazorpayProvider)
        provider._key_id = "rzp_test_mock"
        provider._key_secret = ""
        verifier = WebhookVerifier(provider=provider, webhook_secret="")
        with pytest.raises(WebhookVerificationError, match="secret not configured"):
            verifier.verify(raw_body=b"body", signature="sig")


# ── Payment State Machine ─────────────────────────────────────────────────────

class TestPaymentStateMachine:
    def test_created_to_approval_pending_valid(self):
        assert is_valid_transition(PaymentState.CREATED, PaymentState.APPROVAL_PENDING)

    def test_created_to_paid_invalid(self):
        # Forbid direct jump to PAID
        assert not is_valid_transition(PaymentState.CREATED, PaymentState.PAID)

    def test_processing_to_paid_valid(self):
        assert is_valid_transition(PaymentState.PROCESSING, PaymentState.PAID)

    def test_paid_to_refunded_valid(self):
        assert is_valid_transition(PaymentState.PAID, PaymentState.REFUNDED)

    def test_failed_to_paid_invalid(self):
        assert not is_valid_transition(PaymentState.FAILED, PaymentState.PAID)

    def test_expired_to_paid_invalid(self):
        assert not is_valid_transition(PaymentState.EXPIRED, PaymentState.PAID)

    def test_cancelled_has_no_transitions(self):
        for state in PaymentState:
            assert not is_valid_transition(PaymentState.CANCELLED, state)


# ── Real Money Protection ─────────────────────────────────────────────────────

class TestRealMoneyProtection:
    def test_live_razorpay_key_rejected(self):
        from app.capabilities.online.payments.razorpay_provider import RazorpayProvider
        with pytest.raises(RealMoneyProtectionError):
            RazorpayProvider(key_id="rzp_live_XXXXXXXXXX", key_secret="secret")

    def test_live_stripe_key_rejected(self):
        from app.capabilities.online.payments.stripe_provider import StripeProvider
        with pytest.raises(RealMoneyProtectionError):
            StripeProvider(secret_key="sk_live_XXXXXXXXXX")

    def test_test_razorpay_key_accepted(self):
        from app.capabilities.online.payments.razorpay_provider import RazorpayProvider
        # Should not raise
        provider = RazorpayProvider(key_id="rzp_test_XXXXXXXXXX", key_secret="secret")
        assert provider.provider_name() == "razorpay"

    def test_test_stripe_key_accepted(self):
        from app.capabilities.online.payments.stripe_provider import StripeProvider
        provider = StripeProvider(secret_key="sk_test_XXXXXXXXXX")
        assert provider.provider_name() == "stripe"
