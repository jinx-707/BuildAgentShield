"""
Browser Gateway — the single enforced entry point for all browser operations.
Validates URLs, enforces policy, inspects content, records audit events.
The LLM never reaches the Puppeteer worker directly.
"""
from __future__ import annotations

import logging
from typing import Any

from app.capabilities.online.browser.content_extractor import extract_and_inspect
from app.capabilities.online.browser.network_policy import BrowserNetworkPolicy
from app.capabilities.online.browser.puppeteer_manager import PuppeteerManager
from app.capabilities.online.browser.search_service import SearchProvider
from app.capabilities.online.browser.session_manager import SessionManager
from app.capabilities.online.browser.url_validator import validate_url
from app.core.contracts import GatewayResponse, SecurityContext
from app.core.decisions import SecurityDecision
from app.core.exceptions import (
    BrowserError,
    FormSubmissionDeniedError,
    SSRFAttemptError,
    URLValidationError,
)
from app.integrations.ports import (
    AuditEvent,
    AuditPort,
    ContentInspectionPort,
    PolicyContext,
    PolicyPort,
)

logger = logging.getLogger(__name__)


class BrowserGateway:
    """
    Enforces all security rules for browser operations.
    Every browser action passes through this gateway.
    """

    def __init__(
        self,
        policy: PolicyPort,
        content_inspector: ContentInspectionPort,
        audit: AuditPort,
        search_provider: SearchProvider,
        puppeteer: PuppeteerManager,
        session_manager: SessionManager,
        network_policy: BrowserNetworkPolicy | None = None,
    ) -> None:
        self._policy = policy
        self._inspector = content_inspector
        self._audit = audit
        self._search = search_provider
        self._puppeteer = puppeteer
        self._sessions = session_manager
        self._net_policy = network_policy or BrowserNetworkPolicy()

    # ── Search ────────────────────────────────────────────────────────────────

    async def search(
        self,
        ctx: SecurityContext,
        query: str,
        num_results: int = 10,
    ) -> GatewayResponse:
        # Policy check
        policy_decision = await self._policy.authorize(
            PolicyContext(
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                capability="browser",
                operation="search",
            )
        )
        if not policy_decision.allowed:
            await self._record_audit(ctx, "DENY", "BLOCKED", policy_decision.reason)
            return GatewayResponse.deny(ctx, policy_decision.reason, policy_decision.policy_id)

        # Execute search
        try:
            results = await self._search.search(query=query, num_results=num_results)
        except Exception as e:
            logger.error("Search error: %s", e)
            await self._record_audit(ctx, "ALLOW", "FAILED", str(e))
            return GatewayResponse(
                request_id=ctx.request_id,
                status="FAILED",
                decision=SecurityDecision.ALLOW,
                capability="browser",
                operation="search",
                reason=f"Search provider error: {type(e).__name__}",
            )

        await self._record_audit(ctx, "ALLOW", "EXECUTED")
        return GatewayResponse.allow(ctx, result=results.model_dump())

    # ── Navigate ──────────────────────────────────────────────────────────────

    async def navigate(
        self,
        ctx: SecurityContext,
        url: str,
        session_id: str | None = None,
    ) -> GatewayResponse:
        # Validate URL
        try:
            validate_url(
                url,
                allowed_schemes=self._net_policy.allowed_schemes,
                domain_allowlist=self._net_policy.domain_allowlist or None,
                domain_blocklist=self._net_policy.domain_blocklist,
                allowed_ports=self._net_policy.allowed_ports,
            )
        except (SSRFAttemptError, URLValidationError) as e:
            await self._record_audit(ctx, "DENY", "BLOCKED", str(e), resource=url)
            return GatewayResponse.deny(ctx, str(e), "BROWSER-URL-001")

        # Policy check
        policy_decision = await self._policy.authorize(
            PolicyContext(
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                capability="browser",
                operation="navigate",
                resource=url,
            )
        )
        if not policy_decision.allowed:
            await self._record_audit(ctx, "DENY", "BLOCKED", policy_decision.reason)
            return GatewayResponse.deny(ctx, policy_decision.reason, policy_decision.policy_id)

        # Get or create session
        try:
            if session_id:
                session = await self._sessions.get_session(session_id)
                if not session:
                    session = await self._sessions.create_session(ctx.agent_id)
            else:
                session = await self._sessions.create_session(ctx.agent_id)

            # Send to Puppeteer worker
            result = await self._puppeteer.navigate(
                url=url,
                session_id=session.session_id,
                timeout_ms=self._net_policy.navigation_timeout * 1000,
            )
            session.touch()
            session.page_count += 1
        except BrowserError as e:
            await self._record_audit(ctx, "ALLOW", "FAILED", str(e))
            return GatewayResponse(
                request_id=ctx.request_id,
                status="FAILED",
                decision=SecurityDecision.ALLOW,
                capability="browser",
                operation="navigate",
                reason=f"Browser worker error: {e.message}",
            )

        await self._record_audit(ctx, "ALLOW", "EXECUTED", resource=url)
        return GatewayResponse.allow(
            ctx,
            result={**result, "session_id": session.session_id},
        )

    # ── Extract ───────────────────────────────────────────────────────────────

    async def extract(
        self,
        ctx: SecurityContext,
        session_id: str,
        url: str,
        selector: str | None = None,
    ) -> GatewayResponse:
        session = await self._sessions.get_session(session_id)
        if not session:
            return GatewayResponse.deny(ctx, "Browser session not found or expired", "BROWSER-SESS-001")

        try:
            raw = await self._puppeteer.extract_text(session_id=session_id, selector=selector)
        except BrowserError as e:
            return GatewayResponse(
                request_id=ctx.request_id,
                status="FAILED",
                decision=SecurityDecision.ALLOW,
                capability="browser",
                operation="extract",
                reason=str(e),
            )

        # Inspect extracted content for prompt injection
        page_content, classification = await extract_and_inspect(
            raw_content=raw,
            url=url,
            inspector=self._inspector,
        )

        session.touch()
        await self._record_audit(ctx, "ALLOW", "EXECUTED", resource=url)

        result = page_content.model_dump()
        result["trust_classification"] = {
            "source": classification.source,
            "trust_level": classification.trust_level,
            "inspected": classification.inspected,
            "safe_to_return": classification.safe_to_return,
            "findings_count": len(classification.findings),
        }

        if not classification.safe_to_return:
            result["security_warning"] = (
                "Content inspection detected potentially malicious instructions. "
                "Content has been redacted."
            )

        return GatewayResponse.allow(ctx, result=result)

    # ── Browser action (click, form, etc.) ────────────────────────────────────

    async def browser_action(
        self,
        ctx: SecurityContext,
        action_type: str,
        session_id: str,
        params: dict[str, Any],
    ) -> GatewayResponse:
        action_policy = self._net_policy.get_action_policy(action_type)

        if action_policy == "block_direct":
            await self._record_audit(ctx, "DENY", "BLOCKED", f"Action {action_type} blocked")
            return GatewayResponse.deny(
                ctx,
                f"Browser action '{action_type}' is not permitted directly. "
                "Route through the appropriate gateway.",
                "BROWSER-ACTION-001",
            )

        if action_policy == "require_approval":
            return GatewayResponse.deny(
                ctx,
                f"Browser action '{action_type}' requires explicit approval.",
                "BROWSER-ACTION-002",
            )

        if action_policy in ("require_policy_check", "validate"):
            policy_decision = await self._policy.authorize(
                PolicyContext(
                    agent_id=ctx.agent_id,
                    tenant_id=ctx.tenant_id,
                    capability="browser",
                    operation=action_type,
                )
            )
            if not policy_decision.allowed:
                await self._record_audit(ctx, "DENY", "BLOCKED", policy_decision.reason)
                return GatewayResponse.deny(ctx, policy_decision.reason, policy_decision.policy_id)

        session = await self._sessions.get_session(session_id)
        if not session:
            return GatewayResponse.deny(ctx, "Browser session not found or expired", "BROWSER-SESS-001")

        if action_type == "click":
            selector = params.get("selector", "")
            if not selector:
                return GatewayResponse.deny(ctx, "Click action requires a selector", "BROWSER-ACTION-003")
            result = await self._puppeteer.click(session_id=session_id, selector=selector)
        else:
            result = {"action": action_type, "status": "unsupported"}

        session.touch()
        await self._record_audit(ctx, "ALLOW", "EXECUTED")
        return GatewayResponse.allow(ctx, result=result)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _record_audit(
        self,
        ctx: SecurityContext,
        decision: str,
        status: str,
        reason: str | None = None,
        resource: str | None = None,
    ) -> None:
        await self._audit.record(
            AuditEvent(
                event_type=f"BROWSER_{ctx.operation.upper()}",
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                capability="browser",
                operation=ctx.operation,
                decision=decision,
                status=status,
                request_id=ctx.request_id,
                resource=resource or ctx.resource,
                reason=reason,
            )
        )
