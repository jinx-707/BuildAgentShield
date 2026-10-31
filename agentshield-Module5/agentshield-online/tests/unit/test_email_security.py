"""
Email security tests — recipient validation, DLP, approval binding.
"""
import pytest
from app.capabilities.online.email.email_policy import EmailPolicy
from app.capabilities.online.email.recipient_validator import validate_recipients, validate_sender
from app.capabilities.online.email.email_sender import compute_email_hash
from app.core.exceptions import UnauthorizedRecipientError


class TestRecipientValidation:
    @pytest.fixture
    def policy(self):
        p = EmailPolicy.__new__(EmailPolicy)
        p._config = {
            "approved_recipients": ["admin@example.com", "test@example.com"],
            "approved_domains": ["example.com"],
            "blocked_addresses": ["blocked@example.com"],
            "allow_external_recipients": False,
        }
        return p

    def test_approved_recipient_passes(self, policy):
        result = validate_recipients(["admin@example.com"], [], [], policy)
        assert result.valid is True

    def test_approved_domain_passes(self, policy):
        result = validate_recipients(["anyone@example.com"], [], [], policy)
        assert result.valid is True

    def test_blocked_recipient_denied(self, policy):
        with pytest.raises(UnauthorizedRecipientError, match="Blocked"):
            validate_recipients(["blocked@example.com"], [], [], policy)

    def test_external_recipient_denied_when_not_allowed(self, policy):
        with pytest.raises(UnauthorizedRecipientError, match="External"):
            validate_recipients(["attacker@evil.com"], [], [], policy)

    def test_invalid_email_format_denied(self, policy):
        with pytest.raises(UnauthorizedRecipientError, match="Invalid"):
            validate_recipients(["not-an-email"], [], [], policy)

    def test_bcc_also_validated(self, policy):
        with pytest.raises(UnauthorizedRecipientError):
            validate_recipients([], [], ["external@evil.com"], policy)


class TestEmailApprovalBinding:
    def test_same_params_produce_same_hash(self):
        h1 = compute_email_hash(
            sender="agent@example.com",
            to=["admin@example.com"],
            cc=[],
            bcc=[],
            subject="Test Subject",
            body="Hello World",
            attachment_hashes=[],
        )
        h2 = compute_email_hash(
            sender="agent@example.com",
            to=["admin@example.com"],
            cc=[],
            bcc=[],
            subject="Test Subject",
            body="Hello World",
            attachment_hashes=[],
        )
        assert h1 == h2

    def test_changed_body_produces_different_hash(self):
        h1 = compute_email_hash("a@b.com", ["c@d.com"], [], [], "Subject", "Body 1", [])
        h2 = compute_email_hash("a@b.com", ["c@d.com"], [], [], "Subject", "Body 2", [])
        assert h1 != h2

    def test_changed_recipient_produces_different_hash(self):
        h1 = compute_email_hash("a@b.com", ["c@d.com"], [], [], "Subject", "Body", [])
        h2 = compute_email_hash("a@b.com", ["e@f.com"], [], [], "Subject", "Body", [])
        assert h1 != h2

    def test_changed_subject_produces_different_hash(self):
        h1 = compute_email_hash("a@b.com", ["c@d.com"], [], [], "Subject A", "Body", [])
        h2 = compute_email_hash("a@b.com", ["c@d.com"], [], [], "Subject B", "Body", [])
        assert h1 != h2

    def test_added_bcc_produces_different_hash(self):
        h1 = compute_email_hash("a@b.com", ["c@d.com"], [], [], "Sub", "Body", [])
        h2 = compute_email_hash("a@b.com", ["c@d.com"], [], ["bcc@d.com"], "Sub", "Body", [])
        assert h1 != h2


class TestApprovalAdapter:
    @pytest.mark.asyncio
    async def test_pending_approval_not_valid(self):
        from app.integrations.local_approval_adapter import LocalApprovalAdapter
        from app.integrations.ports import ApprovalRequest
        adapter = LocalApprovalAdapter()

        ticket = await adapter.request_approval(
            ApprovalRequest(
                action_type="email_send",
                agent_id="agent_1",
                tenant_id="tenant_1",
                action_hash="abc123",
                action_summary="Send email",
            )
        )
        # Not yet approved — should be invalid
        verification = await adapter.verify_approval(
            ticket.approval_request_id, "abc123"
        )
        assert verification.valid is False
        assert "pending" in verification.reason.lower() or "approved" in verification.reason.lower()

    @pytest.mark.asyncio
    async def test_approved_then_valid(self):
        from app.integrations.local_approval_adapter import LocalApprovalAdapter
        from app.integrations.ports import ApprovalRequest
        adapter = LocalApprovalAdapter()

        ticket = await adapter.request_approval(
            ApprovalRequest(
                action_type="email_send",
                agent_id="agent_1",
                tenant_id="tenant_1",
                action_hash="def456",
                action_summary="Send email",
            )
        )
        adapter.grant_test_approval(ticket.approval_request_id)

        verification = await adapter.verify_approval(
            ticket.approval_request_id, "def456"
        )
        assert verification.valid is True
        assert verification.consumed is True

    @pytest.mark.asyncio
    async def test_single_use_approval(self):
        from app.integrations.local_approval_adapter import LocalApprovalAdapter
        from app.integrations.ports import ApprovalRequest
        adapter = LocalApprovalAdapter()

        ticket = await adapter.request_approval(
            ApprovalRequest(
                action_type="email_send",
                agent_id="agent_1",
                tenant_id="tenant_1",
                action_hash="ghi789",
                action_summary="Send email",
            )
        )
        adapter.grant_test_approval(ticket.approval_request_id)

        # First use: valid
        v1 = await adapter.verify_approval(ticket.approval_request_id, "ghi789")
        assert v1.valid is True

        # Second use: rejected (single-use)
        v2 = await adapter.verify_approval(ticket.approval_request_id, "ghi789")
        assert v2.valid is False
        assert "consumed" in v2.reason.lower()

    @pytest.mark.asyncio
    async def test_hash_mismatch_rejected(self):
        from app.integrations.local_approval_adapter import LocalApprovalAdapter
        from app.integrations.ports import ApprovalRequest
        adapter = LocalApprovalAdapter()

        ticket = await adapter.request_approval(
            ApprovalRequest(
                action_type="email_send",
                agent_id="agent_1",
                tenant_id="tenant_1",
                action_hash="original_hash",
                action_summary="Send email",
            )
        )
        adapter.grant_test_approval(ticket.approval_request_id)

        # Different hash (transaction details changed)
        v = await adapter.verify_approval(
            ticket.approval_request_id, "tampered_hash"
        )
        assert v.valid is False
        assert "hash" in v.reason.lower() or "mismatch" in v.reason.lower()
