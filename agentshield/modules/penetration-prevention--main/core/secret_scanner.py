"""
AgentShield Secret & Credential Scanner.
Detects cloud credentials (AWS), API keys (OpenAI, GitHub, Slack), passwords,
database credentials, private keys, JWTs, and high Shannon-entropy candidate strings.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any

from core.config import AgentShieldConfig, setup_logger
from core.schemas import (
    DetectionFinding,
    DetectorType,
    SecretAnalysisResult,
    SecretType,
)

logger = setup_logger("agentshield.secrets")


@dataclass
class SecretRule:
    """Configurable rule definition for secret and credential detection."""
    rule_id: str
    pattern: re.Pattern
    secret_type: SecretType
    risk_weight: float
    description: str
    extract_group: int = 0
    enabled: bool = True


class SecretScanner:
    """
    Production-grade scanner for credentials, tokens, and cryptographic keys.
    Combines deterministic signatures with information entropy analysis.
    """

    # Candidate alphanumeric/base64 strings for Shannon Entropy inspection
    ENTROPY_CANDIDATE_REGEX = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")

    def __init__(self, config: AgentShieldConfig | None = None) -> None:
        self.config = config or AgentShieldConfig()
        self.rules: list[SecretRule] = self._build_default_rules()

    def _build_default_rules(self) -> list[SecretRule]:
        """Instantiates default production secret detection rules."""
        return [
            # ================================================================
            # 1. AWS Credentials
            # ================================================================
            SecretRule(
                rule_id="SEC_AWS_001",
                pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16,24})\b"),
                secret_type=SecretType.AWS_ACCESS_KEY,
                risk_weight=0.95,
                description="AWS Access Key ID detected",
                extract_group=1,
            ),
            SecretRule(
                rule_id="SEC_AWS_002",
                pattern=re.compile(r"(?i)(?:aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
                secret_type=SecretType.AWS_SECRET_KEY,
                risk_weight=0.98,
                description="AWS Secret Access Key credential assignment detected",
                extract_group=1,
            ),
            SecretRule(
                rule_id="SEC_AWS_003",
                pattern=re.compile(r"(?i)(?:aws_session_token|aws_token)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"),
                secret_type=SecretType.AWS_SECRET_KEY,
                risk_weight=0.95,
                description="AWS STS Temporary Session Token detected",
                extract_group=1,
            ),

            # ================================================================
            # 2. OpenAI Secrets
            # ================================================================
            SecretRule(
                rule_id="SEC_OAI_001",
                pattern=re.compile(r"\b(sk-(?:proj-|live-|test-|svcacct-)?[a-zA-Z0-9_\-]{20,})\b"),
                secret_type=SecretType.OPENAI_API_KEY,
                risk_weight=0.95,
                description="OpenAI API secret token detected",
                extract_group=1,
            ),

            # ================================================================
            # 3. GitHub Secrets
            # ================================================================
            SecretRule(
                rule_id="SEC_GH_001",
                pattern=re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{60,120})\b"),
                secret_type=SecretType.GITHUB_PAT,
                risk_weight=0.95,
                description="GitHub Personal Access Token detected",
                extract_group=1,
            ),
            SecretRule(
                rule_id="SEC_GH_002",
                pattern=re.compile(r"\b(gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})\b"),
                secret_type=SecretType.GITHUB_PAT,
                risk_weight=0.90,
                description="GitHub OAuth / User-to-Server access token detected",
                extract_group=1,
            ),

            # ================================================================
            # 4. Slack Secrets
            # ================================================================
            SecretRule(
                rule_id="SEC_SLACK_001",
                pattern=re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
                secret_type=SecretType.SLACK_TOKEN,
                risk_weight=0.95,
                description="Slack OAuth bot/user authentication token detected",
                extract_group=1,
            ),
            SecretRule(
                rule_id="SEC_SLACK_002",
                pattern=re.compile(r"(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,11}\/B[0-9A-Z]{8,11}\/[0-9a-zA-Z]{24})"),
                secret_type=SecretType.SLACK_TOKEN,
                risk_weight=0.90,
                description="Slack Incoming Webhook URL detected",
                extract_group=1,
            ),

            # ================================================================
            # 5. Cryptographic Private Keys
            # ================================================================
            SecretRule(
                rule_id="SEC_KEY_001",
                pattern=re.compile(r"-----BEGIN (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----"),
                secret_type=SecretType.SSH_PRIVATE_KEY,
                risk_weight=1.00,
                description="Asymmetric cryptographic private key block detected",
                extract_group=0,
            ),
            SecretRule(
                rule_id="SEC_KEY_002",
                pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----"),
                secret_type=SecretType.SSH_PRIVATE_KEY,
                risk_weight=1.00,
                description="PGP Private Key Block detected",
                extract_group=0,
            ),

            # ================================================================
            # 6. JSON Web Tokens (JWT)
            # ================================================================
            SecretRule(
                rule_id="SEC_JWT_001",
                pattern=re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
                secret_type=SecretType.JWT_TOKEN,
                risk_weight=0.85,
                description="JSON Web Token (JWT) detected",
                extract_group=1,
            ),

            # ================================================================
            # 7. Database Credentials
            # ================================================================
            SecretRule(
                rule_id="SEC_DB_001",
                pattern=re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|oracle|mssql):\/\/[A-Za-z0-9_.-]+:([^@\s]+)@[A-Za-z0-9_.-]+(?::\d+)?\/[A-Za-z0-9_.-]+", re.IGNORECASE),
                secret_type=SecretType.DATABASE_CREDENTIALS,
                risk_weight=0.95,
                description="Database connection URI with embedded authentication credentials",
                extract_group=1,
            ),

            # ================================================================
            # 8. Passwords
            # ================================================================
            SecretRule(
                rule_id="SEC_PASS_001",
                pattern=re.compile(r"(?i)(?:password|passwd|db_password|admin_password|root_password)\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"),
                secret_type=SecretType.PASSWORD,
                risk_weight=0.90,
                description="Plaintext password assignment detected",
                extract_group=1,
            ),

            # ================================================================
            # 9. Access Tokens & Bearer Tokens
            # ================================================================
            SecretRule(
                rule_id="SEC_BEARER_001",
                pattern=re.compile(r"(?i)(?:bearer|authorization\s*:\s*bearer)\s+([a-zA-Z0-9_\-\.]{24,})"),
                secret_type=SecretType.BEARER_TOKEN,
                risk_weight=0.85,
                description="Authorization Bearer access token detected",
                extract_group=1,
            ),
            SecretRule(
                rule_id="SEC_GEN_001",
                pattern=re.compile(r"(?i)(?:api[_-]?key|secret[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]"),
                secret_type=SecretType.GENERIC_SECRET,
                risk_weight=0.80,
                description="Generic API secret / authorization token assignment detected",
                extract_group=1,
            ),
        ]

    # ========================================================================
    # Rule Management API
    # ========================================================================

    def add_rule(self, rule: SecretRule) -> None:
        """Adds or updates a custom secret detection rule."""
        self.rules = [r for r in self.rules if r.rule_id != rule.rule_id]
        self.rules.append(rule)
        logger.debug("Added/updated secret rule: %s (%s)", rule.rule_id, rule.secret_type.value)

    def remove_rule(self, rule_id: str) -> bool:
        """Removes a rule by its ID. Returns True if removed."""
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        return len(self.rules) < initial_len

    def enable_rule(self, rule_id: str) -> bool:
        """Enables a rule by ID."""
        for r in self.rules:
            if r.rule_id == rule_id:
                r.enabled = True
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disables a rule by ID."""
        for r in self.rules:
            if r.rule_id == rule_id:
                r.enabled = False
                return True
        return False

    def get_rules(self, enabled_only: bool = False) -> list[SecretRule]:
        """Returns active or all registered rules."""
        if enabled_only:
            return [r for r in self.rules if r.enabled]
        return list(self.rules)

    def set_entropy_threshold(self, threshold: float) -> None:
        """Dynamically adjusts the Shannon entropy threshold."""
        if threshold < 1.0 or threshold > 8.0:
            raise ValueError(f"Shannon entropy threshold must be between 1.0 and 8.0 (got {threshold})")
        self.config.secret_entropy_threshold = threshold

    # ========================================================================
    # Entropy & Safe Masking
    # ========================================================================

    @staticmethod
    def calculate_shannon_entropy(s: str) -> float:
        """
        Calculates Shannon entropy: H = -sum(p_i * log2(p_i)).
        Higher values indicate cryptographic randomness; lower values indicate natural language.
        """
        if not s:
            return 0.0
        entropy = 0.0
        length = len(s)
        frequencies: dict[str, int] = {}
        for char in s:
            frequencies[char] = frequencies.get(char, 0) + 1

        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 3)

    @staticmethod
    def mask_secret(secret: str, secret_type: SecretType | None = None) -> str:
        """
        Safely masks secret values for reporting and diagnostics without leaking credentials.
        Never reveals sensitive characters for passwords, private keys, or short tokens.
        """
        if not secret:
            return "[REDACTED_SECRET]"

        # Strict zero-exposure for passwords and database credentials
        if secret_type in (SecretType.PASSWORD, SecretType.DATABASE_CREDENTIALS):
            return "********"

        # Private keys
        if secret_type == SecretType.SSH_PRIVATE_KEY:
            return "-----BEGIN PRIVATE KEY----- [MASKED]"

        # JWT tokens
        if secret_type == SecretType.JWT_TOKEN:
            return "eyJ****[MASKED_JWT]"

        # AWS Access Key ID (e.g. AKIAIOSFODNN7EXAMPLE)
        if secret_type == SecretType.AWS_ACCESS_KEY or secret.startswith(("AKIA", "ASIA", "ABIA", "ACCA")):
            if len(secret) >= 8:
                return f"{secret[:4]}****{secret[-4:]}"
            return "[REDACTED_AWS_KEY]"

        # OpenAI API Keys
        if secret.startswith("sk-"):
            prefix = secret[:7] if secret.startswith("sk-proj-") else "sk-"
            suffix = secret[-4:] if len(secret) >= 16 else ""
            return f"{prefix}****{suffix}"

        # GitHub Tokens
        if secret.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")):
            return f"{secret[:4]}****{secret[-4:]}"
        if secret.startswith("github_pat_"):
            return f"github_pat_****{secret[-4:]}"

        # Slack Tokens
        if secret.startswith("xox"):
            parts = secret.split("-")
            return f"{parts[0]}****{secret[-4:]}"

        # Short secrets: full redaction
        if len(secret) <= 12:
            return "[REDACTED_SECRET]"

        # Generic long secrets: expose at most 4 prefix and 4 suffix if >= 20 chars
        if len(secret) >= 20:
            return f"{secret[:4]}****{secret[-4:]}"
        return f"{secret[:2]}****{secret[-2:]}"

    # ========================================================================
    # Primary Scan APIs
    # ========================================================================

    def scan(self, text: str) -> SecretAnalysisResult:
        """
        Synchronously analyzes text for known credentials, tokens, passwords,
        database URIs, and high-entropy secrets.
        """
        if not text or not self.config.enable_secret_scanning:
            return SecretAnalysisResult(has_secrets=False, secret_count=0, sanitized_text=text)

        findings: list[DetectionFinding] = []
        raw_matches: list[dict[str, Any]] = []

        active_rules = [r for r in self.rules if r.enabled]

        # 1. Deterministic Known Signatures
        for rule in active_rules:
            for match in rule.pattern.finditer(text):
                grp = rule.extract_group
                # If specified group exists, use that, otherwise full match
                val = match.group(grp) if match.lastindex and match.lastindex >= grp and grp > 0 else match.group(0)
                start = match.start(grp) if match.lastindex and match.lastindex >= grp and grp > 0 else match.start()
                end = match.end(grp) if match.lastindex and match.lastindex >= grp and grp > 0 else match.end()

                raw_matches.append({
                    "rule_id": rule.rule_id,
                    "secret_type": rule.secret_type,
                    "start": start,
                    "end": end,
                    "val": val,
                    "score": rule.risk_weight,
                    "desc": rule.description,
                })

        # 2. Shannon Entropy Inspection for Unmatched High-Entropy Strings
        for cand_match in self.ENTROPY_CANDIDATE_REGEX.finditer(text):
            candidate = cand_match.group(0)
            # Skip if candidate already covered by deterministic signature
            already_covered = any(
                m["start"] <= cand_match.start() and m["end"] >= cand_match.end()
                for m in raw_matches
            )
            if already_covered:
                continue

            # Skip candidate if it is composed of repetitive characters
            if len(set(candidate)) <= 4:
                continue

            entropy = self.calculate_shannon_entropy(candidate)
            if entropy >= self.config.secret_entropy_threshold:
                raw_matches.append({
                    "rule_id": "SEC_ENTROPY_001",
                    "secret_type": SecretType.HIGH_ENTROPY,
                    "start": cand_match.start(),
                    "end": cand_match.end(),
                    "val": candidate,
                    "score": 0.75,
                    "desc": f"High Shannon entropy string detected (entropy: {entropy:.2f})",
                })

        # Sort and deduplicate overlaps (prefer longer spans and higher scores)
        raw_matches.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
        filtered_matches: list[dict[str, Any]] = []
        last_end = -1
        for match in raw_matches:
            if match["start"] >= last_end:
                filtered_matches.append(match)
                last_end = match["end"]

        # Build sanitized text by replacing slices from back to front
        sanitized_text = text
        for match in sorted(filtered_matches, key=lambda x: x["start"], reverse=True):
            secret_type: SecretType = match["secret_type"]
            replacement = f"[REDACTED_{secret_type.value.upper()}]"
            sanitized_text = (
                sanitized_text[: match["start"]]
                + replacement
                + sanitized_text[match["end"] :]
            )

        for match in filtered_matches:
            findings.append(
                DetectionFinding(
                    detector=DetectorType.SECRET,
                    rule_id=match["rule_id"],
                    description=match["desc"],
                    risk_score=match["score"],
                    start_index=match["start"],
                    end_index=match["end"],
                    redacted_value=f"[REDACTED_{match['secret_type'].value.upper()}]",
                    match_preview=self.mask_secret(match["val"], match["secret_type"]),
                    metadata={"secret_type": match["secret_type"].value},
                )
            )

        has_secrets = len(findings) > 0
        logger.debug("Secret scan complete. %d secrets detected.", len(findings))

        return SecretAnalysisResult(
            has_secrets=has_secrets,
            secret_count=len(findings),
            findings=findings,
            sanitized_text=sanitized_text,
        )

    async def scan_async(self, text: str) -> SecretAnalysisResult:
        """
        Asynchronous wrapper for non-blocking invocation.
        Delegates to ``scan`` via ``asyncio.to_thread`` so entropy computation
        and regex scanning do not block the event loop.
        """
        import asyncio as _asyncio
        return await _asyncio.to_thread(self.scan, text)
