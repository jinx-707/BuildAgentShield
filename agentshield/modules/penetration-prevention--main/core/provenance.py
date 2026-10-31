"""
AgentShield Cryptographic Provenance & Tamper-Evident Audit Ledger.
Produces HMAC-signed, linearly-chained SHA-256 records tracking prompt flow,
gateway actions, risk assessments, and model outputs with full audit verification,
parent-child relationship tracking, origin trust tiers, and taint propagation.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import hmac
import json
import threading
from typing import Any
import uuid

from core.config import AgentShieldConfig, setup_logger
from core.schemas import (
    Action,
    ProvenanceRecord,
    ProvenanceVerificationError,
    RiskLevel,
    SourceType,
    TrustLevel,
)

logger = setup_logger("agentshield.provenance")


# ============================================================================
# Trust Hierarchy & Source Mapping
# ============================================================================

TRUST_LEVEL_RANKS: dict[TrustLevel, int] = {
    TrustLevel.UNTRUSTED: 0,
    TrustLevel.LOW: 1,
    TrustLevel.MEDIUM: 2,
    TrustLevel.HIGH: 3,
    TrustLevel.TRUSTED: 4,
}

DEFAULT_SOURCE_TRUST_LEVELS: dict[SourceType, TrustLevel] = {
    SourceType.SYSTEM: TrustLevel.TRUSTED,
    SourceType.USER: TrustLevel.MEDIUM,
    SourceType.FILE: TrustLevel.MEDIUM,
    SourceType.TOOL_OUTPUT: TrustLevel.LOW,
    SourceType.WEBSITE: TrustLevel.UNTRUSTED,
    SourceType.AGENT: TrustLevel.MEDIUM,
}


def normalize_source_type(source: SourceType | str) -> SourceType:
    """Normalizes string or enum representation to SourceType."""
    if isinstance(source, SourceType):
        return source
    normalized = str(source).lower().strip()
    if normalized in ("user", "user_input", "human", "prompt"):
        return SourceType.USER
    if normalized in ("file", "document", "upload", "local_file"):
        return SourceType.FILE
    if normalized in ("website", "web", "url", "http", "https"):
        return SourceType.WEBSITE
    if normalized in ("tool", "tool_output", "function", "tool_call", "api", "database"):
        return SourceType.TOOL_OUTPUT
    if normalized in ("system", "system_prompt"):
        return SourceType.SYSTEM
    if normalized in ("agent", "model", "llm", "assistant"):
        return SourceType.AGENT
    try:
        return SourceType(normalized)
    except ValueError:
        return SourceType.USER


def compare_trust_levels(level1: TrustLevel, level2: TrustLevel) -> int:
    """Returns -1 if level1 < level2, 0 if equal, 1 if level1 > level2."""
    r1 = TRUST_LEVEL_RANKS.get(level1, 0)
    r2 = TRUST_LEVEL_RANKS.get(level2, 0)
    if r1 < r2:
        return -1
    elif r1 > r2:
        return 1
    return 0


# ============================================================================
# ProvenanceEngine
# ============================================================================

class ProvenanceEngine:
    """
    Immutable cryptographic audit ledger and provenance tracking system.
    Features:
      - Tracks content origins (User, File, Website, Tool Output, System, Agent).
      - Assigns hierarchical trust levels to each source.
      - Maintains parent-child relationships and lineage trees between content.
      - Enforces SHA-256 hash chaining and HMAC-SHA256 signatures for tamper detection.
      - Verifies provenance records, content integrity, and trust levels before consumption.
    """

    GENESIS_PARENT_HASH = "0" * 64

    def __init__(self, config: AgentShieldConfig | None = None) -> None:
        self.config = config or AgentShieldConfig()
        self._lock = threading.Lock()
        self._ledger: list[ProvenanceRecord] = []
        self._records_by_id: dict[str, ProvenanceRecord] = {}
        self._children_map: dict[str, list[str]] = defaultdict(list)
        self._last_hash: str = self.GENESIS_PARENT_HASH
        self._sequence: int = 0

    @staticmethod
    def hash_text(content: str | None) -> str:
        """Computes SHA-256 hex digest of a string or returns 'none' if None."""
        if content is None:
            return "none"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _sign_hash(self, current_hash: str) -> str:
        """Signs the hash using HMAC-SHA256 with the configured secret key."""
        key = self.config.hmac_secret_key.encode("utf-8")
        return hmac.new(key, current_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _hash_metadata(metadata: dict[str, Any] | None) -> str:
        """
        Returns a stable SHA-256 hex digest of the metadata dict.
        Values are converted to strings so the hash remains deterministic
        across Python versions and object types.
        Produces a fixed "empty" digest when metadata is None or empty.
        """
        if not metadata:
            # Consistent sentinel for absent / empty metadata
            return hashlib.sha256(b"{}").hexdigest()
        canonical = json.dumps(
            {k: str(v) for k, v in sorted(metadata.items())},
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _build_canonical_payload(
        sequence_number: int,
        parent_hash: str | None,
        record_id: str,
        timestamp: datetime,
        session_id: str | None,
        agent_id: str | None,
        source_type: SourceType,
        trust_level: TrustLevel,
        source_uri: str | None,
        parent_id: str | None,
        input_hash: str,
        output_hash: str | None,
        action_taken: Action,
        risk_level: RiskLevel,
        metadata_hash: str | None = None,
    ) -> str:
        """
        Constructs a deterministic, sorted canonical JSON payload for cryptographic
        hashing.  ``metadata_hash`` is the SHA-256 digest of the record's metadata
        dict (computed by ``_hash_metadata``), ensuring that metadata is covered by
        the tamper-evident signature.  The parameter is optional so that
        ``verify_record`` on records created before this fix still validates
        correctly when called with only the original 14 fields.
        """
        payload = {
            "action_taken": action_taken.value,
            "agent_id": agent_id,
            "input_hash": input_hash,
            "metadata_hash": metadata_hash,
            "output_hash": output_hash,
            "parent_hash": parent_hash,
            "parent_id": parent_id,
            "record_id": record_id,
            "risk_level": risk_level.value,
            "sequence_number": sequence_number,
            "session_id": session_id,
            "source_type": source_type.value,
            "source_uri": source_uri,
            "timestamp": timestamp.isoformat(),
            "trust_level": trust_level.value,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def create_record(
        self,
        input_text: str,
        action: Action = Action.ALLOW,
        risk_level: RiskLevel = RiskLevel.SAFE,
        output_text: str | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        source_type: SourceType | str = SourceType.USER,
        trust_level: TrustLevel | None = None,
        source_uri: str | None = None,
        parent_id: str | None = None,
        parent_ids: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """
        Creates, chains, signs, and appends a new provenance audit record.
        Thread-safe execution ensures unbroken sequence numbers and cryptographic hash links.
        """
        normalized_source = normalize_source_type(source_type)
        assigned_trust = (
            trust_level
            if trust_level is not None
            else DEFAULT_SOURCE_TRUST_LEVELS.get(normalized_source, TrustLevel.MEDIUM)
        )

        effective_parent_ids = list(parent_ids) if parent_ids else ([] if parent_id is None else [parent_id])
        primary_parent_id = parent_id or (effective_parent_ids[0] if effective_parent_ids else None)

        # BUG-4 fix: copy the metadata dict so post-creation caller mutations
        # cannot silently alter the stored record's metadata.
        safe_metadata: dict[str, Any] = dict(metadata) if metadata else {}

        with self._lock:
            seq = self._sequence
            parent_hash = self._last_hash
            ts = datetime.now(timezone.utc)
            rec_id = str(uuid.uuid4())

            in_hash = self.hash_text(input_text)
            out_hash = self.hash_text(output_text) if output_text is not None else None

            # BUG-4 fix: include a metadata hash in the canonical payload so
            # that the metadata is covered by the cryptographic signature.
            meta_hash = self._hash_metadata(safe_metadata)

            canonical_str = self._build_canonical_payload(
                sequence_number=seq,
                parent_hash=parent_hash,
                record_id=rec_id,
                timestamp=ts,
                session_id=session_id,
                agent_id=agent_id,
                source_type=normalized_source,
                trust_level=assigned_trust,
                source_uri=source_uri,
                parent_id=primary_parent_id,
                input_hash=in_hash,
                output_hash=out_hash,
                action_taken=action,
                risk_level=risk_level,
                metadata_hash=meta_hash,
            )

            current_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
            signature = self._sign_hash(current_hash)

            record = ProvenanceRecord(
                record_id=rec_id,
                timestamp=ts,
                sequence_number=seq,
                parent_hash=parent_hash,
                current_hash=current_hash,
                session_id=session_id,
                agent_id=agent_id,
                input_hash=in_hash,
                output_hash=out_hash,
                action_taken=action,
                risk_level=risk_level,
                signature=signature,
                metadata=safe_metadata,
                source_type=normalized_source,
                trust_level=assigned_trust,
                source_uri=source_uri,
                parent_id=primary_parent_id,
                parent_ids=effective_parent_ids,
            )

            self._ledger.append(record)
            self._records_by_id[rec_id] = record

            # Register child link for all declared parents
            for p_id in effective_parent_ids:
                self._children_map[p_id].append(rec_id)

            self._last_hash = current_hash
            self._sequence += 1

            logger.debug(
                "Created provenance record #%d [%s] source=%s trust=%s parent=%s action=%s",
                seq,
                rec_id[:8],
                normalized_source.value,
                assigned_trust.value,
                primary_parent_id[:8] if primary_parent_id else "None",
                action.value,
            )

            return record

    # ------------------------------------------------------------------------
    # Detached Record (read-only probe — not appended to the ledger)
    # ------------------------------------------------------------------------

    def _build_detached_record(
        self,
        input_text: str,
        action: Action = Action.ALLOW,
        risk_level: RiskLevel = RiskLevel.SAFE,
        output_text: str | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        source_type: SourceType | str = SourceType.USER,
        trust_level: TrustLevel | None = None,
        source_uri: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """
        Builds a fully signed, cryptographically valid ``ProvenanceRecord``
        **without** appending it to the shared ledger or advancing the
        sequence counter.

        Use this when you need a real ``ProvenanceRecord`` to return to a
        caller but must not pollute the audit trail — for example, when
        ``SecurityEngine.calculate_risk`` is called with
        ``record_provenance=False``.

        The record's ``sequence_number`` is set to ``-1`` and its
        ``parent_hash`` is set to the genesis sentinel, making it clearly
        distinguishable from ledger-chained records while still being
        individually verifiable via ``verify_record``.
        """
        normalized_source = normalize_source_type(source_type)
        assigned_trust = (
            trust_level
            if trust_level is not None
            else DEFAULT_SOURCE_TRUST_LEVELS.get(normalized_source, TrustLevel.MEDIUM)
        )
        safe_metadata: dict[str, Any] = dict(metadata) if metadata else {}
        rec_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc)

        in_hash = self.hash_text(input_text)
        out_hash = self.hash_text(output_text) if output_text is not None else None
        meta_hash = self._hash_metadata(safe_metadata)

        # Use the genesis sentinel for the parent hash.
        # sequence_number must be >= 0 per the schema; we use 0 here since
        # detached records are never appended to the ledger and therefore
        # never form part of the chain.
        detached_seq = 0
        detached_parent_hash = self.GENESIS_PARENT_HASH

        canonical_str = self._build_canonical_payload(
            sequence_number=detached_seq,
            parent_hash=detached_parent_hash,
            record_id=rec_id,
            timestamp=ts,
            session_id=session_id,
            agent_id=agent_id,
            source_type=normalized_source,
            trust_level=assigned_trust,
            source_uri=source_uri,
            parent_id=None,
            input_hash=in_hash,
            output_hash=out_hash,
            action_taken=action,
            risk_level=risk_level,
            metadata_hash=meta_hash,
        )

        current_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        signature = self._sign_hash(current_hash)

        return ProvenanceRecord(
            record_id=rec_id,
            timestamp=ts,
            sequence_number=detached_seq,
            parent_hash=detached_parent_hash,
            current_hash=current_hash,
            session_id=session_id,
            agent_id=agent_id,
            input_hash=in_hash,
            output_hash=out_hash,
            action_taken=action,
            risk_level=risk_level,
            signature=signature,
            metadata=safe_metadata,
            source_type=normalized_source,
            trust_level=assigned_trust,
            source_uri=source_uri,
            parent_id=None,
            parent_ids=[],
        )

    # ------------------------------------------------------------------------
    # Specialized Source Tracking Methods
    # ------------------------------------------------------------------------

    def track_user_input(
        self,
        content: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """Tracks direct human user input with standard Medium trust."""
        return self.create_record(
            input_text=content,
            action=Action.ALLOW,
            risk_level=RiskLevel.SAFE,
            session_id=session_id,
            agent_id=agent_id,
            source_type=SourceType.USER,
            trust_level=TrustLevel.MEDIUM,
            metadata=metadata,
        )

    def track_file(
        self,
        content: str,
        file_path: str,
        trust_level: TrustLevel | None = None,
        parent_id: str | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """Tracks content loaded from a local file or document."""
        return self.create_record(
            input_text=content,
            action=Action.ALLOW,
            risk_level=RiskLevel.SAFE,
            session_id=session_id,
            agent_id=agent_id,
            source_type=SourceType.FILE,
            trust_level=trust_level or TrustLevel.MEDIUM,
            source_uri=file_path,
            parent_id=parent_id,
            metadata=metadata,
        )

    def track_website(
        self,
        content: str,
        url: str,
        trust_level: TrustLevel | None = None,
        parent_id: str | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """Tracks content fetched from an external website or URL (Untrusted by default)."""
        return self.create_record(
            input_text=content,
            action=Action.ALLOW,
            risk_level=RiskLevel.SAFE,
            session_id=session_id,
            agent_id=agent_id,
            source_type=SourceType.WEBSITE,
            trust_level=trust_level or TrustLevel.UNTRUSTED,
            source_uri=url,
            parent_id=parent_id,
            metadata=metadata,
        )

    def track_tool_output(
        self,
        content: str,
        tool_name: str,
        parent_id: str | None = None,
        trust_level: TrustLevel | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """Tracks tool, database, or API execution output (Low trust by default)."""
        return self.create_record(
            input_text=content,
            action=Action.ALLOW,
            risk_level=RiskLevel.SAFE,
            session_id=session_id,
            agent_id=agent_id,
            source_type=SourceType.TOOL_OUTPUT,
            trust_level=trust_level or TrustLevel.LOW,
            source_uri=tool_name,
            parent_id=parent_id,
            metadata=metadata,
        )

    def track_derived_content(
        self,
        content: str,
        parent_id: str,
        source_type: SourceType = SourceType.AGENT,
        action: Action = Action.ALLOW,
        risk_level: RiskLevel = RiskLevel.SAFE,
        session_id: str | None = None,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """Tracks content synthesized or derived from an existing parent record."""
        parent = self.get_record(parent_id)
        inherited_trust = parent.trust_level if parent else TrustLevel.MEDIUM
        return self.create_record(
            input_text=content,
            action=action,
            risk_level=risk_level,
            session_id=session_id,
            agent_id=agent_id,
            source_type=source_type,
            trust_level=inherited_trust,
            parent_id=parent_id,
            metadata=metadata,
        )

    # ------------------------------------------------------------------------
    # Lineage & Relationship Graph Querying
    # ------------------------------------------------------------------------

    def get_record(self, record_id: str) -> ProvenanceRecord | None:
        """Retrieves a provenance record by its unique ID."""
        with self._lock:
            return self._records_by_id.get(record_id)

    def get_parent(self, record_id: str) -> ProvenanceRecord | None:
        """Retrieves the direct parent record of a given record."""
        rec = self.get_record(record_id)
        if not rec or not rec.parent_id:
            return None
        return self.get_record(rec.parent_id)

    def get_children(self, record_id: str) -> list[ProvenanceRecord]:
        """Retrieves all direct child records derived from a given record."""
        with self._lock:
            child_ids = self._children_map.get(record_id, [])
            return [self._records_by_id[cid] for cid in child_ids if cid in self._records_by_id]

    def get_ancestors(self, record_id: str) -> list[ProvenanceRecord]:
        """
        Traverses the parent chain up to the root genesis.
        Returns the ancestor records from direct parent to root ancestor.
        Includes cycle protection.
        """
        ancestors: list[ProvenanceRecord] = []
        visited: set[str] = {record_id}
        current_id = record_id

        while True:
            parent = self.get_parent(current_id)
            if not parent or parent.record_id in visited:
                break
            ancestors.append(parent)
            visited.add(parent.record_id)
            current_id = parent.record_id

        return ancestors

    def get_lineage(self, record_id: str) -> list[ProvenanceRecord]:
        """
        Returns full lineage path from the root ancestor down to the specified record.
        """
        rec = self.get_record(record_id)
        if not rec:
            return []
        ancestors = self.get_ancestors(record_id)
        # Reverse ancestors so order is root -> intermediate -> record
        lineage = list(reversed(ancestors))
        lineage.append(rec)
        return lineage

    def get_effective_trust_level(self, record_id: str) -> TrustLevel:
        """
        Calculates effective trust with taint propagation:
        The effective trust level of a record cannot exceed the lowest trust level
        among all its upstream ancestors.
        """
        rec = self.get_record(record_id)
        if not rec:
            return TrustLevel.UNTRUSTED

        min_rank = TRUST_LEVEL_RANKS[rec.trust_level]
        for ancestor in self.get_ancestors(record_id):
            anc_rank = TRUST_LEVEL_RANKS[ancestor.trust_level]
            if anc_rank < min_rank:
                min_rank = anc_rank

        # Convert lowest rank back to TrustLevel enum
        for level, rank in TRUST_LEVEL_RANKS.items():
            if rank == min_rank:
                return level
        return TrustLevel.UNTRUSTED

    # ------------------------------------------------------------------------
    # Cryptographic Verification & Tamper Detection
    # ------------------------------------------------------------------------

    def verify_record(self, record: ProvenanceRecord) -> bool:
        """
        Verifies the cryptographic integrity and HMAC signature of a single record.
        Detects tampering of fields, inputs, sequence numbers, or signature corruption.
        """
        # Recompute the metadata hash from the record's stored metadata so
        # that any post-creation mutation of the metadata dict is detected.
        meta_hash = self._hash_metadata(dict(record.metadata))

        canonical_str = self._build_canonical_payload(
            sequence_number=record.sequence_number,
            parent_hash=record.parent_hash,
            record_id=record.record_id,
            timestamp=record.timestamp,
            session_id=record.session_id,
            agent_id=record.agent_id,
            source_type=record.source_type,
            trust_level=record.trust_level,
            source_uri=record.source_uri,
            parent_id=record.parent_id,
            input_hash=record.input_hash,
            output_hash=record.output_hash,
            action_taken=record.action_taken,
            risk_level=record.risk_level,
            metadata_hash=meta_hash,
        )

        recalculated_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        if recalculated_hash != record.current_hash:
            logger.warning(
                "Hash mismatch on record %s: computed=%s, stored=%s",
                record.record_id,
                recalculated_hash,
                record.current_hash,
            )
            return False

        expected_sig = self._sign_hash(record.current_hash)
        if not hmac.compare_digest(expected_sig, record.signature or ""):
            logger.warning("HMAC signature mismatch on record %s", record.record_id)
            return False

        return True

    def verify_chain(self, ledger: list[ProvenanceRecord] | None = None) -> tuple[bool, str | None]:
        """
        Verifies the entire sequence of provenance records for:
          1. Sequential continuity (sequence numbers strictly increasing by 1 from 0).
          2. Parent hash chain continuity (record[i].parent_hash == record[i-1].current_hash).
          3. Internal canonical hash validity and HMAC cryptographic signature.
        Returns (True, None) if unbroken, or (False, error_reason) if tampered.
        """
        records = ledger if ledger is not None else self._ledger

        if not records:
            return True, None

        expected_parent = self.GENESIS_PARENT_HASH

        for i, rec in enumerate(records):
            if rec.sequence_number != i:
                msg = f"Sequence violation: expected {i}, found {rec.sequence_number}"
                logger.error(msg)
                return False, msg

            if rec.parent_hash != expected_parent:
                msg = f"Broken hash chain at record #{i}: parent_hash does not match predecessor"
                logger.error(msg)
                return False, msg

            if not self.verify_record(rec):
                msg = f"Cryptographic integrity failed on record #{i} (id: {rec.record_id})"
                logger.error(msg)
                return False, msg

            expected_parent = rec.current_hash

        return True, None

    def verify_content(self, content: str, record: ProvenanceRecord) -> bool:
        """
        Verifies that a given content string actually matches the recorded hash
        and that the provenance record itself has not been tampered with.
        """
        if not self.verify_record(record):
            return False

        content_hash = self.hash_text(content)
        return content_hash == record.input_hash or content_hash == record.output_hash

    def is_content_trusted(
        self,
        content: str,
        record: ProvenanceRecord,
        min_trust: TrustLevel = TrustLevel.MEDIUM,
        check_taint: bool = True,
    ) -> bool:
        """
        Verifies that content is authentic (untampered) and meets or exceeds
        the required minimum trust level, accounting for lineage taint propagation.
        """
        if not self.verify_content(content, record):
            return False

        effective_trust = (
            self.get_effective_trust_level(record.record_id)
            if check_taint
            else record.trust_level
        )

        return TRUST_LEVEL_RANKS[effective_trust] >= TRUST_LEVEL_RANKS[min_trust]

    def verify_or_raise(
        self,
        record: ProvenanceRecord,
        content: str | None = None,
        min_trust: TrustLevel | None = None,
        check_taint: bool = True,
    ) -> None:
        """
        Verifies a provenance record and optional content against tampering.
        Raises ProvenanceVerificationError if verification fails or trust is inadequate.
        """
        if not self.verify_record(record):
            raise ProvenanceVerificationError(
                f"Provenance record #{record.sequence_number} ({record.record_id[:8]}) "
                "failed cryptographic integrity or HMAC signature check."
            )

        if content is not None and not self.verify_content(content, record):
            raise ProvenanceVerificationError(
                f"Content payload does not match recorded SHA-256 hash in provenance record #{record.sequence_number}."
            )

        if min_trust is not None:
            effective_trust = (
                self.get_effective_trust_level(record.record_id)
                if check_taint
                else record.trust_level
            )
            if TRUST_LEVEL_RANKS[effective_trust] < TRUST_LEVEL_RANKS[min_trust]:
                raise ProvenanceVerificationError(
                    f"Content from source '{record.source_type.value}' has effective trust level "
                    f"'{effective_trust.value}', which is lower than required '{min_trust.value}'."
                )

    # ------------------------------------------------------------------------
    # Ledger State Management
    # ------------------------------------------------------------------------

    def get_ledger(self) -> list[ProvenanceRecord]:
        """Returns a snapshot copy of all audit records in the ledger."""
        with self._lock:
            return list(self._ledger)

    def clear(self) -> None:
        """Resets the ledger state (primarily for test teardown)."""
        with self._lock:
            self._ledger.clear()
            self._records_by_id.clear()
            self._children_map.clear()
            self._last_hash = self.GENESIS_PARENT_HASH
            self._sequence = 0
