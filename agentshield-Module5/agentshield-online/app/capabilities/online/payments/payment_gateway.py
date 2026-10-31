"""
Payment Gateway — enforces the complete payment security lifecycle.

TEST MODE ONLY.

Pipeline:
  Validate → Merchant → Limits → Policy → Approval → Create Order →
  Webhook Verify → Server-side Status → State Machine → Audit
"""
from __future__ import annotations

import logging
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.ext.asyncio import AsyncSession

from app.capabilities.online.payments.approval_binding import compute_payment_fingerprint
from app.capabilities.online.payments.idempotency import IdempotencyStore, compute_idempotency_key
from app.capabilities.online.payments.merchant_validator import MerchantValidator
from app.capabilities.online.payments.payment_audit import PaymentAudit
from app.capabilities.online.payments.payment_provider import PaymentProvider
from app.capabilities.online.payments.spending_limits import SpendingLimitsEnforcer
from app.capabilities.online.payments.transaction_store import TransactionStore
from app.capabilities.online.payments.transaction_validator import PaymentRequest, validate_transaction_limits
from app.capabilities.online.payments.webhook_verifier import WebhookVerifier
from app.core.contracts import GatewayResponse, SecurityContext
from app.core.decisions import PaymentState, SecurityDecision
from app.core.exceptions import (
    ApprovalInvalidError,
    DuplicateTransactionError,
    InvalidTransactionStateError,
    PaymentError,
    PaymentProviderError,
    SpendingLimitExceededError,
    UnauthorizedMerchantError,
    WebhookVerificationError,
)
from app.integrations.ports import (
    ApprovalPort,
    ApprovalRequest,
    AuditPort,
    PolicyContext,
    PolicyPort,
)

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parents[5] / "configs" / "payment_policy.yaml"


class PaymentConfig:
    def __init__(self, config_path: str | Path | None = None) -> None:
        path = Path(config_path or _DEFAULT_CONFIG_PATH)
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            cfg = data.get("payments", {})
        except Exception as e:
            logger.warning("PaymentConfig: could not load %s: %s", path, e)
            cfg = {}

        self.max_transaction_paise: int = cfg.get("maximum_transaction_paise", 100000)
        self.daily_limit_paise: int = cfg.get("daily_limit_paise", 500000)
        self.approval_threshold_paise: int = cfg.get("approval_threshold_paise", 50000)
        self.require_approval: bool = cfg.get("require_approval", True)
        self.provider_mode: str = cfg.get("provider_mode", "test")
        self.approval_expires_seconds: int = cfg.get("approval_expires_seconds", 300)
        self.idempotency_ttl_hours: int = cfg.get("idempotency_key_ttl_hours", 24)
        self.order_expiry_minutes: int = cfg.get("order_expiry_minutes", 30)


class PaymentGateway:
    """
    Enforces the full payment security lifecycle.
    All amounts use integer minor units — no floating-point arithmetic.
    """

    def __init__(
        self,
        policy: PolicyPort,
        approval: ApprovalPort,
        audit: AuditPort,
        provider: PaymentProvider,
        webhook_secret: str,
        db_session_factory: Any,   # async session factory
        config_path: str | None = None,
    ) -> None:
        self._policy = policy
        self._approval = approval
        self._payment_audit = PaymentAudit(audit)
        self._provider = provider
        self._config = PaymentConfig(config_path)
        self._merchant_validator = MerchantValidator(config_path)
        self._spending_limits = SpendingLimitsEnforcer(
            max_transaction_minor=self._config.max_transaction_paise,
            daily_limit_minor=self._config.daily_limit_paise,
        )
        self._idempotency = IdempotencyStore(
            ttl_hours=self._config.idempotency_ttl_hours
        )
        self._txn_store = TransactionStore()
        self._webhook_verifier = WebhookVerifier(provider, webhook_secret)
        self._db = db_session_factory

        # Safety guard
        if self._config.provider_mode != "test":
            from app.core.exceptions import RealMoneyProtectionError
            raise RealMoneyProtectionError(
                "CRITICAL: payment_mode must be 'test'. "
                "Live processing is not allowed."
            )

    # ── Step 1: Validate ──────────────────────────────────────────────────────

    async def validate_payment(
        self,
        ctx: SecurityContext,
        request: PaymentRequest,
    ) -> GatewayResponse:
        """Validate a payment request without creating an order."""
        try:
            # Merchant check
            merchant = self._merchant_validator.validate(request.merchant_id)

            # Amount/currency validation
            amount_minor = request.to_minor_units()
            validate_transaction_limits(
                request=request,
                max_transaction_minor=self._config.max_transaction_paise,
                max_daily_minor=self._config.daily_limit_paise,
                current_daily_total_minor=0,  # estimate only
            )

            return GatewayResponse.allow(ctx, result={
                "valid": True,
                "merchant_name": merchant.name,
                "amount_minor": amount_minor,
                "currency": request.currency,
                "requires_approval": self._config.require_approval,
                "provider_mode": "test",
            })

        except (UnauthorizedMerchantError, PaymentError) as e:
            return GatewayResponse.deny(ctx, str(e), "PAYMENT-VALIDATE-001")

    # ── Step 2: Create Order ──────────────────────────────────────────────────

    async def create_order(
        self,
        ctx: SecurityContext,
        request: PaymentRequest,
        approval_id: str,
    ) -> GatewayResponse:
        """
        Full payment creation pipeline (steps 1-9 of lifecycle).
        Requires a pre-obtained approval_id.
        """
        # Policy check
        pd = await self._policy.authorize(
            PolicyContext(
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                capability="payments",
                operation="create_order",
                resource=request.merchant_id,
            )
        )
        if not pd.allowed:
            await self._payment_audit.record_payment_event(
                "CREATE_DENIED", "", ctx.agent_id, ctx.tenant_id,
                ctx.request_id, "DENY", "BLOCKED", pd.reason
            )
            return GatewayResponse.deny(ctx, pd.reason, pd.policy_id)

        async with self._db() as session:
            async with session.begin():
                try:
                    # Merchant validation
                    merchant = self._merchant_validator.validate(request.merchant_id)
                    amount_minor = request.to_minor_units()

                    # Compute fingerprint (exact-action binding)
                    action_hash = compute_payment_fingerprint(
                        agent_id=ctx.agent_id,
                        tenant_id=ctx.tenant_id,
                        merchant_id=request.merchant_id,
                        amount_minor=amount_minor,
                        currency=request.currency,
                        purpose=request.purpose,
                        order_reference=request.order_reference,
                        provider=self._provider.provider_name(),
                    )

                    # Verify approval (exact-action check)
                    verification = await self._approval.verify_approval(
                        approval_id=approval_id,
                        action_hash=action_hash,
                    )
                    if not verification.valid:
                        raise ApprovalInvalidError(
                            f"Payment approval invalid: {verification.reason}"
                        )

                    # Compute idempotency key
                    idem_key = request.idempotency_key or compute_idempotency_key(
                        agent_id=ctx.agent_id,
                        tenant_id=ctx.tenant_id,
                        merchant_id=request.merchant_id,
                        amount_minor=amount_minor,
                        currency=request.currency,
                        order_reference=request.order_reference,
                    )

                    # Per-transaction and daily limit check (atomic)
                    await self._spending_limits.check_and_reserve(
                        session=session,
                        agent_id=ctx.agent_id,
                        tenant_id=ctx.tenant_id,
                        amount_minor=amount_minor,
                        currency=request.currency,
                    )

                    # Create transaction record
                    payment_id = await self._txn_store.create(
                        session=session,
                        agent_id=ctx.agent_id,
                        tenant_id=ctx.tenant_id,
                        merchant_id=request.merchant_id,
                        amount_minor=amount_minor,
                        currency=request.currency,
                        purpose=request.purpose,
                        order_reference=request.order_reference,
                        provider=self._provider.provider_name(),
                        idempotency_key=idem_key,
                        action_hash=action_hash,
                    )

                    # Check idempotency (dedup)
                    is_new, existing_pid = await self._idempotency.check_and_insert(
                        session=session,
                        idempotency_key=idem_key,
                        agent_id=ctx.agent_id,
                        tenant_id=ctx.tenant_id,
                        request_fingerprint=action_hash,
                        payment_id=payment_id,
                    )

                    if not is_new:
                        # Duplicate request — return original
                        logger.info(
                            "Duplicate payment request: returning existing payment_id=%s",
                            existing_pid,
                        )
                        return GatewayResponse.allow(ctx, result={
                            "payment_id": existing_pid,
                            "duplicate": True,
                            "message": "Duplicate request — returning original payment",
                        })

                    # Transition to AUTHORIZED
                    await self._txn_store.transition(
                        session=session,
                        payment_id=payment_id,
                        new_state=PaymentState.AUTHORIZED,
                    )

                    # Create provider order
                    provider_order = await self._provider.create_order(
                        amount_minor=amount_minor,
                        currency=request.currency,
                        receipt=request.order_reference[:40],
                        notes={
                            "agent_id": ctx.agent_id,
                            "merchant_id": request.merchant_id,
                            "purpose": request.purpose[:50],
                        },
                        idempotency_key=idem_key,
                    )

                    provider_order_id = provider_order.get("id", "")

                    # Transition to CHECKOUT_PENDING
                    await self._txn_store.transition(
                        session=session,
                        payment_id=payment_id,
                        new_state=PaymentState.CHECKOUT_PENDING,
                        provider_order_id=provider_order_id,
                    )

                    await self._payment_audit.record_payment_event(
                        "ORDER_CREATED", payment_id, ctx.agent_id, ctx.tenant_id,
                        ctx.request_id, "ALLOW", "EXECUTED",
                        metadata={
                            "merchant_id": request.merchant_id,
                            "amount_minor": amount_minor,
                            "currency": request.currency,
                            "provider_order_id": provider_order_id,
                            "provider_mode": "test",
                        },
                    )

                    return GatewayResponse.allow(ctx, result={
                        "payment_id": payment_id,
                        "provider_order_id": provider_order_id,
                        "provider": self._provider.provider_name(),
                        "amount_minor": amount_minor,
                        "currency": request.currency,
                        "state": PaymentState.CHECKOUT_PENDING.value,
                        "provider_mode": "test",
                        "note": "Use hosted checkout. Do NOT send card data to this API.",
                    })

                except ApprovalInvalidError as e:
                    await self._payment_audit.record_payment_event(
                        "APPROVAL_INVALID", "", ctx.agent_id, ctx.tenant_id,
                        ctx.request_id, "DENY", "BLOCKED", str(e)
                    )
                    return GatewayResponse.deny(ctx, str(e), "PAYMENT-APPROVAL-001")

                except UnauthorizedMerchantError as e:
                    await self._payment_audit.record_payment_event(
                        "MERCHANT_DENIED", "", ctx.agent_id, ctx.tenant_id,
                        ctx.request_id, "DENY", "BLOCKED", str(e)
                    )
                    return GatewayResponse.deny(ctx, str(e), "PAYMENT-MERCHANT-001")

                except SpendingLimitExceededError as e:
                    await self._payment_audit.record_payment_event(
                        "LIMIT_EXCEEDED", "", ctx.agent_id, ctx.tenant_id,
                        ctx.request_id, "DENY", "BLOCKED", str(e)
                    )
                    return GatewayResponse.deny(ctx, str(e), "PAYMENT-LIMIT-001")

                except DuplicateTransactionError as e:
                    await self._payment_audit.record_payment_event(
                        "DUPLICATE", "", ctx.agent_id, ctx.tenant_id,
                        ctx.request_id, "DENY", "BLOCKED", str(e)
                    )
                    return GatewayResponse.deny(ctx, str(e), "PAYMENT-DUP-001")

                except PaymentProviderError as e:
                    await self._payment_audit.record_payment_event(
                        "PROVIDER_ERROR", "", ctx.agent_id, ctx.tenant_id,
                        ctx.request_id, "ALLOW", "FAILED", str(e)
                    )
                    return GatewayResponse(
                        request_id=ctx.request_id,
                        status="FAILED",
                        decision=SecurityDecision.ALLOW,
                        capability="payments",
                        operation="create_order",
                        reason=f"Payment provider error: {str(e)[:100]}",
                    )

    # ── Request approval ──────────────────────────────────────────────────────

    async def request_approval(
        self,
        ctx: SecurityContext,
        request: PaymentRequest,
    ) -> GatewayResponse:
        """Request human approval for a payment. Returns approval_request_id."""
        try:
            merchant = self._merchant_validator.validate(request.merchant_id)
            amount_minor = request.to_minor_units()

            action_hash = compute_payment_fingerprint(
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                merchant_id=request.merchant_id,
                amount_minor=amount_minor,
                currency=request.currency,
                purpose=request.purpose,
                order_reference=request.order_reference,
                provider=self._provider.provider_name(),
            )

            ticket = await self._approval.request_approval(
                ApprovalRequest(
                    action_type="payment",
                    agent_id=ctx.agent_id,
                    tenant_id=ctx.tenant_id,
                    action_hash=action_hash,
                    action_summary=(
                        f"Payment: {request.currency} {request.amount} "
                        f"to merchant {merchant.name} — {request.purpose}"
                    ),
                    action_details={
                        "merchant_id": request.merchant_id,
                        "merchant_name": merchant.name,
                        "amount": str(request.amount),
                        "amount_minor": amount_minor,
                        "currency": request.currency,
                        "purpose": request.purpose,
                        "order_reference": request.order_reference,
                        "provider": self._provider.provider_name(),
                        "provider_mode": "test",
                    },
                    expires_seconds=self._config.approval_expires_seconds,
                )
            )

            return GatewayResponse.pending_approval(
                ctx,
                approval_request_id=ticket.approval_request_id,
                reason=(
                    f"Payment of {request.currency} {request.amount} "
                    f"to {merchant.name} requires human approval"
                ),
            )

        except (UnauthorizedMerchantError, PaymentError) as e:
            return GatewayResponse.deny(ctx, str(e), "PAYMENT-VALIDATE-001")

    # ── Webhook ───────────────────────────────────────────────────────────────

    async def process_webhook(
        self,
        ctx: SecurityContext,
        raw_body: bytes,
        signature: str,
        event_data: dict[str, Any],
    ) -> GatewayResponse:
        """
        Process a provider webhook event.
        Verifies signature using raw_body before ANY processing.
        Prevents duplicate processing.
        """
        try:
            # Step 1: Verify signature (uses raw bytes)
            self._webhook_verifier.verify(raw_body=raw_body, signature=signature)
        except WebhookVerificationError as e:
            await self._payment_audit.record_payment_event(
                "WEBHOOK_REJECTED", "", ctx.agent_id, ctx.tenant_id,
                ctx.request_id, "DENY", "BLOCKED", str(e)
            )
            return GatewayResponse.deny(ctx, str(e), "PAYMENT-WEBHOOK-001")

        event_id = event_data.get("id", "")
        event_type = event_data.get("event", "") or event_data.get("type", "")
        order_id = (
            event_data.get("payload", {}).get("order", {}).get("entity", {}).get("id", "")
            or event_data.get("data", {}).get("object", {}).get("id", "")
        )

        async with self._db() as session:
            async with session.begin():
                # Check for duplicate webhook
                if await self._txn_store.is_webhook_processed(session, event_id):
                    logger.info("Duplicate webhook event: %s (ignored)", event_id)
                    return GatewayResponse.allow(ctx, result={
                        "event_id": event_id,
                        "duplicate": True,
                        "message": "Duplicate webhook event — already processed",
                    })

                # Find transaction by provider order ID
                result_row = await session.execute(
                    __import__("sqlalchemy").text(
                        "SELECT payment_id, state FROM payment_transactions "
                        "WHERE provider_order_id = :order_id"
                    ),
                    {"order_id": order_id},
                )
                row = result_row.fetchone()

                new_state = None
                if row:
                    payment_id, current_state_str = row

                    # Map provider event to payment state
                    if "payment.captured" in event_type or event_type == "payment_intent.succeeded":
                        new_state = PaymentState.PAID
                        # Transition through PROCESSING first
                        try:
                            await self._txn_store.transition(
                                session, payment_id, PaymentState.PROCESSING
                            )
                            await self._txn_store.transition(
                                session, payment_id, PaymentState.PAID
                            )
                        except InvalidTransactionStateError as e:
                            logger.warning(
                                "Webhook state transition failed: %s", e
                            )

                    elif "payment.failed" in event_type or event_type == "payment_intent.payment_failed":
                        new_state = PaymentState.FAILED
                        try:
                            await self._txn_store.transition(
                                session, payment_id, PaymentState.FAILED
                            )
                        except InvalidTransactionStateError:
                            pass

                    # Mark webhook as processed
                    await self._txn_store.mark_webhook_processed(
                        session, event_id, payment_id, event_type
                    )
                else:
                    payment_id = ""
                    await self._txn_store.mark_webhook_processed(
                        session, event_id, "", event_type
                    )

        await self._payment_audit.record_payment_event(
            "WEBHOOK_PROCESSED", payment_id, ctx.agent_id, ctx.tenant_id,
            ctx.request_id, "ALLOW", "EXECUTED",
            metadata={"event_type": event_type, "new_state": new_state.value if new_state else None},
        )

        return GatewayResponse.allow(ctx, result={
            "event_id": event_id,
            "event_type": event_type,
            "payment_id": payment_id,
            "new_state": new_state.value if new_state else None,
            "processed": True,
        })

    # ── Status ────────────────────────────────────────────────────────────────

    async def get_status(
        self,
        ctx: SecurityContext,
        payment_id: str,
    ) -> GatewayResponse:
        async with self._db() as session:
            txn = await self._txn_store.get(session, payment_id)

        if not txn:
            return GatewayResponse.deny(
                ctx, f"Payment '{payment_id}' not found", "PAYMENT-404"
            )

        # Verify requestor owns this transaction
        if txn["agent_id"] != ctx.agent_id or txn["tenant_id"] != ctx.tenant_id:
            return GatewayResponse.deny(
                ctx, "Access denied", "PAYMENT-AUTHZ-001"
            )

        return GatewayResponse.allow(ctx, result={
            "payment_id": payment_id,
            "state": txn["state"],
            "amount_minor": txn["amount_minor"],
            "currency": txn["currency"],
            "merchant_id": txn["merchant_id"],
            "provider": txn["provider"],
            "provider_order_id": txn["provider_order_id"],
            "provider_mode": "test",
        })
