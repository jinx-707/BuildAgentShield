"""
AgentShield Data Loss Prevention (DLP) Engine.
Enforces corporate data classification boundaries, detecting proprietary codenames,
financial records, connection strings, infrastructure URIs, and HIPAA markers.

This module also implements the integrated DLP gate: it combines the core DLP
classification rules with the existing PII Detector and Secret Scanner to classify
content across four sensitivity tiers (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED)
and emit a configurable security decision (ALLOW, WARN, MASK, BLOCK) *before*
sensitive data is released to external tools or services.

Design notes
------------
* ``scan`` performs the low-level DLP classification consumed by the Input/Output
  guards and the risk engine. Its signature and return type (``DLPAnalysisResult``)
  are a stable contract shared with the rest of the gateway, so it is kept
  DLP-only and backward compatible.
* ``enforce`` is the Prompt-6 integrated gate. It layers PII / Secret detection on
  top of the DLP classification and returns a ``DLPDecision`` carrying a
  standardized ``Action`` plus the aggregated ``DetectionFinding`` objects.
* PII / Secret detectors are injected (opt-in). When omitted, the engine behaves
  exactly like the legacy DLP classifier, so existing guards are unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from core.config import AgentShieldConfig, setup_logger
from core.pii_detector import PIIDetector
from core.schemas import (
    Action,
    DLPAnalysisResult,
    DetectionFinding,
    DetectorType,
    DLPViolationError,
    PIIType,
    SensitivityLevel,
)
from core.secret_scanner import SecretScanner

logger = setup_logger("agentshield.dlp")


# ============================================================================
# Integrated DLP Decision
# ============================================================================

@dataclass
class DLPDecision:
    """
    Security decision emitted by the integrated DLP gate (``DLPEngine.enforce``).

    Combines a configurable ``Action`` decision (ALLOW/WARN/MASK/BLOCK) with the
    standardized ``DetectionFinding`` objects produced by the DLP rules and any
    integrated PII / Secret detectors, plus the redacted text that is safe to
    release to external tools or services.
    """
    action: Action
    sensitivity: SensitivityLevel
    violates_policy: bool
    findings: list[DetectionFinding]
    sanitized_text: str
    reason: str
    dlp_result: DLPAnalysisResult
    pii_count: int = 0
    secret_count: int = 0


# ============================================================================
# DLP Engine
# ============================================================================

class DLPEngine:
    """
    Data Loss Prevention engine classifying content against organizational
    sensitivity tiers (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED).

    ``scan`` returns the standardized ``DLPAnalysisResult`` used by the gateway.
    ``enforce`` returns a ``DLPDecision`` integrating PII and Secret detection
    with a configurable ALLOW/WARN/MASK/BLOCK policy decision.
    """

    # Hierarchy ranking for sensitivity comparison
    SENSITIVITY_RANK: dict[SensitivityLevel, int] = {
        SensitivityLevel.PUBLIC: 0,
        SensitivityLevel.INTERNAL: 1,
        SensitivityLevel.CONFIDENTIAL: 2,
        SensitivityLevel.RESTRICTED: 3,
    }

    # Default action per sensitivity tier. Fully overridable via
    # ``sensitivity_actions`` or ``set_sensitivity_action`` at runtime.
    DEFAULT_SENSITIVITY_ACTIONS: dict[SensitivityLevel, Action] = {
        SensitivityLevel.PUBLIC: Action.ALLOW,
        SensitivityLevel.INTERNAL: Action.WARN,
        SensitivityLevel.CONFIDENTIAL: Action.MASK,
        SensitivityLevel.RESTRICTED: Action.BLOCK,
    }

    # Minimum sensitivity tier implied by a given PII type. Used by the
    # integrated gate to escalate classification when PII is present.
    PII_SENSITIVITY_MAP: dict[PIIType, SensitivityLevel] = {
        PIIType.EMAIL: SensitivityLevel.INTERNAL,
        PIIType.PHONE_NUMBER: SensitivityLevel.INTERNAL,
        PIIType.PERSON: SensitivityLevel.INTERNAL,
        PIIType.LOCATION: SensitivityLevel.INTERNAL,
        PIIType.IP_ADDRESS: SensitivityLevel.INTERNAL,
        PIIType.DATE_OF_BIRTH: SensitivityLevel.CONFIDENTIAL,
        PIIType.SSN: SensitivityLevel.CONFIDENTIAL,
        PIIType.CREDIT_CARD: SensitivityLevel.CONFIDENTIAL,
        PIIType.US_PASSPORT: SensitivityLevel.CONFIDENTIAL,
        PIIType.DRIVER_LICENSE: SensitivityLevel.CONFIDENTIAL,
        PIIType.PAN: SensitivityLevel.CONFIDENTIAL,
        PIIType.AADHAAR: SensitivityLevel.RESTRICTED,
    }

    # When this many (or more) PII items appear together, treat the payload as a
    # bulk exfiltration attempt and escalate to at least CONFIDENTIAL.
    BULK_PII_THRESHOLD: int = 5

    # DLP inspection rules: (rule_id, regex, sensitivity_level, risk_weight, description)
    DLP_RULES: list[tuple[str, re.Pattern, SensitivityLevel, float, str]] = [
        # Database connection strings with credentials
        (
            "DLP_CONN_001",
            re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|oracle):\/\/[A-Za-z0-9_-]+:[^@\s]+@[A-Za-z0-9_.-]+(?::\d+)?\/[A-Za-z0-9_.-]+", re.IGNORECASE),
            SensitivityLevel.RESTRICTED,
            0.95,
            "Raw database URI containing credentials and hostname",
        ),
        # Corporate Classification Markings
        (
            "DLP_MARK_001",
            re.compile(r"\b(?:CONFIDENTIAL|STRICTLY CONFIDENTIAL|RESTRICTED|ATTORNEY-CLIENT PRIVILEGED|PROPRIETARY & CONFIDENTIAL)\b", re.IGNORECASE),
            SensitivityLevel.CONFIDENTIAL,
            0.70,
            "Explicit corporate classification marking detected",
        ),
        # Financial: International Bank Account Number (IBAN)
        (
            "DLP_FIN_001",
            re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b"),
            SensitivityLevel.CONFIDENTIAL,
            0.80,
            "International Bank Account Number (IBAN) format detected",
        ),
        # Financial: SWIFT/BIC Code
        (
            "DLP_FIN_002",
            re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
            SensitivityLevel.INTERNAL,
            0.50,
            "SWIFT/BIC banking identifier detected",
        ),
        # Healthcare: Medical Record Number (MRN)
        (
            "DLP_MED_001",
            re.compile(r"\bMRN[-:]?\s*([0-9]{6,10})\b", re.IGNORECASE),
            SensitivityLevel.RESTRICTED,
            0.85,
            "Healthcare Medical Record Number (MRN) detected",
        ),
        # Internal private network hostnames / internal corporate domains
        (
            "DLP_INFRA_001",
            re.compile(r"\b[A-Za-z0-9-]+\.(?:corp|internal|priv|intranet|local)\b", re.IGNORECASE),
            SensitivityLevel.INTERNAL,
            0.40,
            "Internal corporate domain reference detected",
        ),
    ]

    def __init__(
        self,
        config: AgentShieldConfig | None = None,
        pii_detector: PIIDetector | None = None,
        secret_scanner: SecretScanner | None = None,
        sensitivity_actions: dict[SensitivityLevel, Action] | None = None,
    ) -> None:
        """
        Initialize the DLP engine.

        Args:
            config: AgentShield configuration. Defaults to a fresh instance.
            pii_detector: Optional PII Detector used by the integrated gate.
                When omitted, ``enforce`` skips PII escalation (legacy behavior).
            secret_scanner: Optional Secret Scanner used by the integrated gate.
                When omitted, ``enforce`` skips secret escalation.
            sensitivity_actions: Optional override mapping each sensitivity tier
                to an ``Action``. Missing tiers fall back to BLOCK (fail-closed).
        """
        self.config = config or AgentShieldConfig()
        self.pii_detector = pii_detector
        self.secret_scanner = secret_scanner
        self.sensitivity_actions: dict[SensitivityLevel, Action] = (
            dict(sensitivity_actions) if sensitivity_actions
            else dict(self.DEFAULT_SENSITIVITY_ACTIONS)
        )

    # ========================================================================
    # Sensitivity helpers
    # ========================================================================

    def _escalate(
        self, current: SensitivityLevel, candidate: SensitivityLevel
    ) -> SensitivityLevel:
        """Returns the higher-ranked of two sensitivity tiers."""
        if self.SENSITIVITY_RANK[candidate] > self.SENSITIVITY_RANK[current]:
            return candidate
        return current

    def _max_allowed(self) -> SensitivityLevel:
        """The configured ceiling above which content is policy-violating."""
        return self.config.dlp_max_allowed_sensitivity

    # ========================================================================
    # Low-level DLP scan (stable gateway contract)
    # ========================================================================

    def scan(self, text: str) -> DLPAnalysisResult:
        """
        Synchronously evaluates text against DLP classification boundaries
        and configured restricted project keywords.

        This method is the stable contract consumed by the Input/Output guards
        and the risk engine; it intentionally performs DLP-only classification
        and does not invoke the PII or Secret detectors.
        """
        if not text or not self.config.enable_dlp:
            return DLPAnalysisResult(
                violates_policy=False,
                highest_sensitivity=SensitivityLevel.PUBLIC,
                findings=[],
                sanitized_text=text,
            )

        findings: list[DetectionFinding] = []
        raw_matches: list[dict[str, Any]] = []
        highest_rank = self.SENSITIVITY_RANK[SensitivityLevel.PUBLIC]
        highest_level = SensitivityLevel.PUBLIC

        # 1. Standard Pattern Signatures
        for rule_id, pattern, level, weight, description in self.DLP_RULES:
            for match in pattern.finditer(text):
                val = match.group(0)
                rank = self.SENSITIVITY_RANK[level]
                if rank > highest_rank:
                    highest_rank = rank
                    highest_level = level

                raw_matches.append({
                    "rule_id": rule_id,
                    "level": level,
                    "start": match.start(),
                    "end": match.end(),
                    "val": val,
                    "score": weight,
                    "desc": description,
                })

        # 2. Custom Project Codenames / Keywords from Config
        for keyword in self.config.custom_dlp_keywords:
            if not keyword:
                continue
            escaped_kw = re.escape(keyword)
            kw_pattern = re.compile(rf"\b{escaped_kw}\b", re.IGNORECASE)
            for match in kw_pattern.finditer(text):
                level = SensitivityLevel.CONFIDENTIAL
                rank = self.SENSITIVITY_RANK[level]
                if rank > highest_rank:
                    highest_rank = rank
                    highest_level = level

                raw_matches.append({
                    "rule_id": "DLP_KEYWORD_001",
                    "level": level,
                    "start": match.start(),
                    "end": match.end(),
                    "val": match.group(0),
                    "score": 0.75,
                    "desc": f"Protected project keyword detected: '{keyword}'",
                })

        # Sort and deduplicate matches
        raw_matches.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
        filtered_matches: list[dict[str, Any]] = []
        last_end = -1
        for match in raw_matches:
            if match["start"] >= last_end:
                filtered_matches.append(match)
                last_end = match["end"]

        # Produce sanitized text and findings
        sanitized_text = text
        for match in sorted(filtered_matches, key=lambda x: x["start"], reverse=True):
            replacement = f"[DLP_REDACTED_{match['level'].value.upper()}]"
            sanitized_text = (
                sanitized_text[: match["start"]]
                + replacement
                + sanitized_text[match["end"] :]
            )

        for match in filtered_matches:
            findings.append(
                DetectionFinding(
                    detector=DetectorType.DLP,
                    rule_id=match["rule_id"],
                    description=match["desc"],
                    risk_score=match["score"],
                    start_index=match["start"],
                    end_index=match["end"],
                    redacted_value=f"[DLP_REDACTED_{match['level'].value.upper()}]",
                    match_preview=match["val"][:30] + ("..." if len(match["val"]) > 30 else ""),
                    metadata={"sensitivity_level": match["level"].value},
                )
            )

        # Policy violation check against configured max allowed sensitivity
        max_allowed_rank = self.SENSITIVITY_RANK[self.config.dlp_max_allowed_sensitivity]
        violates_policy = highest_rank > max_allowed_rank

        logger.debug(
            "DLP scan complete. Violates policy=%s, Highest=%s, Findings=%d",
            violates_policy,
            highest_level.value,
            len(findings),
        )

        return DLPAnalysisResult(
            violates_policy=violates_policy,
            highest_sensitivity=highest_level,
            findings=findings,
            sanitized_text=sanitized_text,
        )

    async def scan_async(self, text: str) -> DLPAnalysisResult:
        """
        Asynchronous wrapper for non-blocking invocation.
        Delegates to ``scan`` via ``asyncio.to_thread`` so DLP regex scanning
        does not block the event loop.
        """
        import asyncio as _asyncio
        return await _asyncio.to_thread(self.scan, text)

    # ========================================================================
    # Integrated DLP gate (Prompt 6)
    # ========================================================================

    def _detect_all(
        self, text: str
    ) -> tuple[DLPAnalysisResult, Any | None, Any | None]:
        """
        Runs the DLP classifier plus any injected PII / Secret detectors against
        the *original* text. Findings are therefore all index-relative to the
        same source, which keeps aggregated ``DetectionFinding`` spans coherent.
        """
        dlp_res = self.scan(text)
        pii_res = self.pii_detector.scan(text) if self.pii_detector is not None else None
        secret_res = self.secret_scanner.scan(text) if self.secret_scanner is not None else None
        return dlp_res, pii_res, secret_res

    def _compute_sensitivity(
        self,
        dlp_res: DLPAnalysisResult,
        pii_res: Any | None,
        secret_res: Any | None,
    ) -> SensitivityLevel:
        """
        Determines the highest sensitivity tier implied by DLP rules, PII items,
        and any detected secrets.
        """
        sensitivity = dlp_res.highest_sensitivity

        # PII escalation by type
        if pii_res is not None and pii_res.has_pii:
            for finding in pii_res.findings:
                raw_type = finding.metadata.get("pii_type")
                try:
                    pii_type = PIIType(raw_type)
                except (ValueError, TypeError):
                    continue
                implied = self.PII_SENSITIVITY_MAP.get(pii_type, SensitivityLevel.INTERNAL)
                sensitivity = self._escalate(sensitivity, implied)

            # Bulk PII exfiltration escalation
            if pii_res.pii_count >= self.BULK_PII_THRESHOLD:
                sensitivity = self._escalate(sensitivity, SensitivityLevel.CONFIDENTIAL)

        # Any credential / secret implies the highest tier (never leave the org)
        if secret_res is not None and secret_res.has_secrets:
            sensitivity = self._escalate(sensitivity, SensitivityLevel.RESTRICTED)

        return sensitivity

    def _sanitize_layered(
        self,
        text: str,
        pii_res: Any | None,
        secret_res: Any | None,
        dlp_res: DLPAnalysisResult,
    ) -> str:
        """
        Produces a single redacted string by layering PII, Secret, and DLP
        redactions. Mirrors the layering strategy used by the gateway guards so
        that every detector's redactions are reflected in the released text.
        """
        sanitized = text
        layered = False

        # 1. PII redaction
        if pii_res is not None and pii_res.has_pii:
            sanitized = pii_res.sanitized_text
            layered = True

        # 2. Secret redaction (re-scan on the PII-redacted text)
        if secret_res is not None and secret_res.has_secrets:
            sanitized = self.secret_scanner.scan(sanitized).sanitized_text
            layered = True

        # 3. DLP redaction
        if dlp_res.findings:
            if layered:
                # Re-run DLP rules on the layered text to redact remaining content
                sanitized = self.scan(sanitized).sanitized_text
            else:
                sanitized = dlp_res.sanitized_text

        return sanitized

    def _build_reason(
        self,
        sensitivity: SensitivityLevel,
        dlp_res: DLPAnalysisResult,
        pii_res: Any | None,
        secret_res: Any | None,
        violates: bool,
        action: Action,
        max_allowed: SensitivityLevel,
    ) -> str:
        contributors: list[str] = []
        if dlp_res.findings:
            contributors.append(f"{len(dlp_res.findings)} DLP finding(s)")
        if pii_res is not None and pii_res.has_pii:
            contributors.append(f"{pii_res.pii_count} PII item(s)")
        if secret_res is not None and secret_res.has_secrets:
            contributors.append(f"{secret_res.secret_count} secret(s)")

        base = f"Data classified as {sensitivity.value.upper()}"
        if contributors:
            base += f" ({', '.join(contributors)})"

        if violates:
            return (
                f"{base}; exceeds max allowed sensitivity "
                f"({max_allowed.value}) -> BLOCK enforced"
            )
        return f"{base}; action={action.value}"

    def classify(self, text: str) -> SensitivityLevel:
        """
        Classifies text into the highest applicable sensitivity tier, taking
        DLP rules plus any integrated PII / Secret findings into account.
        """
        if not text:
            return SensitivityLevel.PUBLIC
        dlp_res, pii_res, secret_res = self._detect_all(text)
        return self._compute_sensitivity(dlp_res, pii_res, secret_res)

    def enforce(self, text: str, raise_on_block: bool = False) -> DLPDecision:
        """
        Integrated DLP gate: classifies data, integrates the PII Detector and
        Secret Scanner, and returns a configurable security decision
        (ALLOW / WARN / MASK / BLOCK) before data is sent to external tools.

        The decision is driven by:
          * ``sensitivity_actions`` -- the per-tier action mapping (configurable),
          * ``dlp_max_allowed_sensitivity`` -- a hard policy ceiling that forces
            BLOCK for anything above the permitted tier.

        Returns a ``DLPDecision`` containing the chosen ``Action`` and the
        standardized ``DetectionFinding`` objects from all participating
        detectors, alongside the redacted text safe for external release.

        Args:
            text: The content to evaluate before external release.
            raise_on_block: When True and the decision is BLOCK, raises the
                existing ``DLPViolationError`` carrying the findings, mirroring
                the guardrails' hard-block semantics.
        """
        if not text:
            return DLPDecision(
                action=self.sensitivity_actions.get(SensitivityLevel.PUBLIC, Action.ALLOW),
                sensitivity=SensitivityLevel.PUBLIC,
                violates_policy=False,
                findings=[],
                sanitized_text=text,
                reason="Empty content; no sensitive data detected.",
                dlp_result=DLPAnalysisResult(sanitized_text=text),
                pii_count=0,
                secret_count=0,
            )

        dlp_res, pii_res, secret_res = self._detect_all(text)
        sensitivity = self._compute_sensitivity(dlp_res, pii_res, secret_res)

        # Aggregate standardized findings across all detectors
        findings: list[DetectionFinding] = list(dlp_res.findings)
        if pii_res is not None:
            findings.extend(pii_res.findings)
        if secret_res is not None:
            findings.extend(secret_res.findings)

        sanitized_text = self._sanitize_layered(text, pii_res, secret_res, dlp_res)

        # Decision: mapped action, overridden by the hard policy ceiling
        max_allowed = self._max_allowed()
        violates_policy = (
            self.SENSITIVITY_RANK[sensitivity] > self.SENSITIVITY_RANK[max_allowed]
        )
        mapped_action = self.sensitivity_actions.get(sensitivity, Action.BLOCK)
        action = Action.BLOCK if violates_policy else mapped_action

        reason = self._build_reason(
            sensitivity, dlp_res, pii_res, secret_res, violates_policy, action, max_allowed
        )

        logger.debug(
            "DLP enforce complete. sensitivity=%s action=%s violates=%s findings=%d",
            sensitivity.value,
            action.value,
            violates_policy,
            len(findings),
        )

        risk_score = max((f.risk_score for f in findings), default=1.0)
        decision = DLPDecision(
            action=action,
            sensitivity=sensitivity,
            violates_policy=violates_policy,
            findings=findings,
            sanitized_text=sanitized_text,
            reason=reason,
            dlp_result=dlp_res,
            pii_count=pii_res.pii_count if pii_res is not None else 0,
            secret_count=secret_res.secret_count if secret_res is not None else 0,
        )

        if raise_on_block and action == Action.BLOCK:
            raise DLPViolationError(
                message=reason,
                action=Action.BLOCK,
                risk_score=risk_score,
                findings=findings,
            )

        return decision

    async def enforce_async(self, text: str, raise_on_block: bool = False) -> DLPDecision:
        """Asynchronous wrapper for the integrated DLP gate."""
        return self.enforce(text, raise_on_block=raise_on_block)

    # ========================================================================
    # Runtime configurability
    # ========================================================================

    def set_sensitivity_action(
        self, level: SensitivityLevel, action: Action
    ) -> None:
        """Configures the action taken for a given sensitivity tier at runtime."""
        self.sensitivity_actions[level] = action

    def set_max_allowed_sensitivity(self, level: SensitivityLevel) -> None:
        """Configures the hard policy ceiling above which content is blocked."""
        self.config.dlp_max_allowed_sensitivity = level
