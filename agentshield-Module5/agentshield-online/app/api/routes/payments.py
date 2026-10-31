"""Payment API routes. TEST MODE ONLY."""
from __future__ import annotations

from decimal import Decimal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.api.dependencies import AuthContext
from app.capabilities.online.payments.payment_gateway import PaymentGateway
from app.capabilities.online.payments.razorpay_provider import RazorpayProvider
from app.capabilities.online.payments.transaction_validator import PaymentRequest
from app.core.configuration import get_settings
from app.core.contracts import GatewayResponse
from app.core.runtime import runtime
from app.core.security_context import build_security_context
from app.db import get_session

router = APIRouter(prefix="/payments", tags=["payments"])


def _get_gateway() -> PaymentGateway:
    settings = get_settings()
    provider = RazorpayProvider(
        key_id=settings.razorpay_key_id,
        key_secret=settings.razorpay_key_secret,
    )
    return PaymentGateway(
        policy=runtime.policy,
        approval=runtime.approval,
        audit=runtime.audit,
        provider=provider,
        webhook_secret=settings.razorpay_webhook_secret,
        db_session_factory=get_session,
    )


class ValidatePaymentBody(BaseModel):
    merchant_id: str
    amount: Decimal
    currency: str = "INR"
    purpose: str
    order_reference: str


class CreateOrderBody(BaseModel):
    merchant_id: str
    amount: Decimal
    currency: str = "INR"
    purpose: str
    order_reference: str
    approval_id: str
    idempotency_key: str | None = None


class RequestApprovalBody(BaseModel):
    merchant_id: str
    amount: Decimal
    currency: str = "INR"
    purpose: str
    order_reference: str


@router.post("/validate", response_model=GatewayResponse)
async def validate_payment(body: ValidatePaymentBody, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="payments", operation="validate",
    )
    request = PaymentRequest(
        agent_id=auth.agent_id,
        tenant_id=auth.tenant_id,
        merchant_id=body.merchant_id,
        amount=body.amount,
        currency=body.currency,
        purpose=body.purpose,
        order_reference=body.order_reference,
    )
    return await _get_gateway().validate_payment(ctx=ctx, request=request)


@router.post("/request-approval", response_model=GatewayResponse)
async def request_approval(body: RequestApprovalBody, auth: AuthContext):
    """Request human approval before creating order."""
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="payments", operation="create_order",
    )
    request = PaymentRequest(
        agent_id=auth.agent_id,
        tenant_id=auth.tenant_id,
        merchant_id=body.merchant_id,
        amount=body.amount,
        currency=body.currency,
        purpose=body.purpose,
        order_reference=body.order_reference,
    )
    return await _get_gateway().request_approval(ctx=ctx, request=request)


@router.post("/create-order", response_model=GatewayResponse)
async def create_order(body: CreateOrderBody, auth: AuthContext):
    """Create payment order. Requires approval_id from /request-approval."""
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="payments", operation="create_order",
    )
    request = PaymentRequest(
        agent_id=auth.agent_id,
        tenant_id=auth.tenant_id,
        merchant_id=body.merchant_id,
        amount=body.amount,
        currency=body.currency,
        purpose=body.purpose,
        order_reference=body.order_reference,
        idempotency_key=body.idempotency_key,
    )
    return await _get_gateway().create_order(
        ctx=ctx, request=request, approval_id=body.approval_id
    )


@router.post("/webhook", response_model=GatewayResponse)
async def webhook(request: Request, auth: AuthContext):
    """
    Payment provider webhook.
    Signature is verified using the RAW request body.
    """
    raw_body = await request.body()
    signature = request.headers.get(
        "X-Razorpay-Signature",
        request.headers.get("Stripe-Signature", ""),
    )
    try:
        import json
        event_data = json.loads(raw_body)
    except Exception:
        event_data = {}

    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="payments", operation="webhook",
    )
    return await _get_gateway().process_webhook(
        ctx=ctx,
        raw_body=raw_body,
        signature=signature,
        event_data=event_data,
    )


@router.get("/{payment_id}/status", response_model=GatewayResponse)
async def payment_status(payment_id: str, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="payments", operation="status", resource=payment_id,
    )
    return await _get_gateway().get_status(ctx=ctx, payment_id=payment_id)
