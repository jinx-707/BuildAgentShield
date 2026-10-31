"""
AgentShield Robust Prompt Injection & Jailbreak Detector.
Comprehensive defense against direct & indirect prompt injection, persona jailbreaks,
role manipulation, system prompt extraction, and encoded/obfuscated adversarial payloads.
"""

from __future__ import annotations

import base64
import codecs
from dataclasses import dataclass
import re
import unicodedata
import urllib.parse
from typing import Any

from core.config import AgentShieldConfig, setup_logger
from core.schemas import (
    DetectionFinding,
    DetectorType,
    InjectionAnalysisResult,
)

logger = setup_logger("agentshield.injection")


@dataclass
class InjectionRule:
    """Configurable rule definition for prompt injection detection."""
    rule_id: str
    pattern: re.Pattern
    category: str
    risk_weight: float
    description: str
    enabled: bool = True


class PromptInjectionDetector:
    """
    Robust, production-grade Prompt Injection Detector.
    Features:
      - Direct instruction overrides & priority hijacking
      - Indirect prompt injection (embedded instructions, tool simulation, exfiltration links)
      - Jailbreak personas (DAN, STAN, AIM, Godmode, Grandma exploits)
      - Role manipulation & virtualization (rogue terminals, amoral actors)
      - System prompt extraction & reconnaissance
      - Delimiter smuggling & fake chat-template control tokens
      - Obfuscation neutralization (Base64, ROT13, Hex, URL percent-encoding,
        Unicode homoglyphs, full-width ASCII, Zalgo combining marks, zero-width spaces)
      - Configurable detection rules and dynamic threshold management
    """

    # Cyrillic and Greek lookalike homoglyphs mapped to standard Latin ASCII
    HOMOGLYPH_MAP = str.maketrans({
        # Cyrillic lowercase
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w",
        # Cyrillic uppercase
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
        "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
        # Greek lookalikes
        "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p",
        "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K",
        "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    })

    # Regex finding candidate base64 strings (minimum 16 characters)
    BASE64_PATTERN = re.compile(r"(?:(?<=[\s\"'`:;(=\[])|^)([A-Za-z0-9+/]{16,}={0,2})(?=[\s\"'`:;)\]]|$)")

    # Regex matching hex escapes (\x69\x67 or \u0069)
    HEX_ESCAPE_PATTERN = re.compile(r"(?:" + re.escape(r"\x") + r"[0-9a-fA-F]{2}){4,}")

    # Regex matching URL percent-encoding (%69%67%6e)
    URL_PERCENT_PATTERN = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")

    # Regex matching markdown image exfiltration links
    MARKDOWN_EXFIL_PATTERN = re.compile(
        r"!\[.*?\]\(https?:\/\/[^\s\)]+?(?:leak|exfil|collect|log|steal|token=|\?data=)[^\s\)]*\)",
        re.IGNORECASE,
    )

    # Invisible and zero-width unicode characters
    INVISIBLE_CHARS_REGEX = re.compile(r"[\u200B-\u200D\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u2060-\u2064]")

    def __init__(self, config: AgentShieldConfig | None = None) -> None:
        self.config = config or AgentShieldConfig()
        self.rules: list[InjectionRule] = self._build_default_rules()

    def _build_default_rules(self) -> list[InjectionRule]:
        """Instantiates default production rule catalog."""
        return [
            # ================================================================
            # 1. Direct Instruction Overrides (DIRECT_OVERRIDE)
            # ================================================================
            InjectionRule(
                rule_id="INJ_DIR_001",
                pattern=re.compile(r"(?:ignore|disregard|forget|override|bypass|negate|cancel)\s+(?:all\s+)?(?:(?:previous|prior|above|system|developer)\s+)?(?:instructions|directions|prompts|rules|commands|constraints)", re.IGNORECASE),
                category="DIRECT_OVERRIDE",
                risk_weight=0.95,
                description="Direct command to ignore previous instructions or system prompts",
            ),
            InjectionRule(
                rule_id="INJ_DIR_002",
                pattern=re.compile(r"(?:stop\s+being\s+(?:an?\s+)?ai|you\s+are\s+no\s+longer\s+(?:an?\s+)?ai|cancel\s+all\s+(?:prior\s+)?rules|suspend\s+ethical\s+guidelines)", re.IGNORECASE),
                category="DIRECT_OVERRIDE",
                risk_weight=0.85,
                description="Directive commanding the model to cease operating under AI safety constraints",
            ),
            InjectionRule(
                rule_id="INJ_DIR_003",
                pattern=re.compile(r"(?:new\s+system\s+(?:instructions?|directive)|override\s+system\s+directive|protocol\s+override\s+alpha|priority\s+override\s+0)", re.IGNORECASE),
                category="DIRECT_OVERRIDE",
                risk_weight=0.85,
                description="Simulated higher-privilege system directive override",
            ),
            InjectionRule(
                rule_id="INJ_DIR_004",
                pattern=re.compile(r"(?:clear\s+(?:context\s+)?memory|reset\s+(?:conversation\s+)?history|purge\s+safety\s+guidelines|wipe\s+initial\s+prompt)", re.IGNORECASE),
                category="DIRECT_OVERRIDE",
                risk_weight=0.80,
                description="Command attempting to wipe conversation memory or safety context",
            ),
            InjectionRule(
                rule_id="INJ_DIR_005",
                pattern=re.compile(r"(?:from\s+now\s+on,?\s+(?:you\s+must\s+)?answer\s+without\s+restrictions|disable\s+(?:content|safety)\s+filter|turn\s+off\s+safety\s+mode)", re.IGNORECASE),
                category="DIRECT_OVERRIDE",
                risk_weight=0.90,
                description="Explicit command to disable safety filters and operate unrestricted",
            ),

            # ================================================================
            # 2. Indirect Prompt Injection (INDIRECT_INJECTION)
            # ================================================================
            InjectionRule(
                rule_id="INJ_IND_001",
                pattern=re.compile(r"(?:\[\s*(?:important\s+instruction|note\s+to\s+assistant|special\s+instructions?|system\s+notification)\s*:\s*(?:ignore|do\s+not\s+follow|disregard|instead\s+(?:say|output|execute|send))[\s\S]*?\])", re.IGNORECASE),
                category="INDIRECT_INJECTION",
                risk_weight=0.95,
                description="Embedded indirect directive disguised as document instructions or system note",
            ),
            InjectionRule(
                rule_id="INJ_IND_002",
                pattern=re.compile(r"(?:(?:tool_response|function_call|call_result|api_output)\s*[:=]\s*(?:override|system\s+command|eval\(|execute\s+command))", re.IGNORECASE),
                category="INDIRECT_INJECTION",
                risk_weight=0.90,
                description="Second-order indirect injection simulating tool response or API output",
            ),
            InjectionRule(
                rule_id="INJ_IND_003",
                pattern=self.MARKDOWN_EXFIL_PATTERN,
                category="INDIRECT_INJECTION",
                risk_weight=0.95,
                description="Markdown link or image covert data exfiltration payload",
            ),
            InjectionRule(
                rule_id="INJ_IND_004",
                pattern=re.compile(r"(?:when\s+(?:summarizing|reading|processing|analyzing)\s+this\s+(?:text|email|document),?\s+(?:you\s+must\s+)?(?:(?:silently|secretly|immediately)\s+)?(?:send|email|forward|delete|execute))", re.IGNORECASE),
                category="INDIRECT_INJECTION",
                risk_weight=0.85,
                description="Adversarial context hijacking attempting covert action during summarization",
            ),
            InjectionRule(
                rule_id="INJ_IND_005",
                pattern=re.compile(r"(?:human\s*:\s*ignore\s+above|assistant\s*:\s*understood,?\s*i\s+will\s+now|ai\s+directive\s*:\s*transfer\s+all)", re.IGNORECASE),
                category="INDIRECT_INJECTION",
                risk_weight=0.90,
                description="Simulated conversation turn injected inside untrusted content",
            ),

            # ================================================================
            # 3. Jailbreaks & Persona Hijacking (JAILBREAK_PERSONA)
            # ================================================================
            InjectionRule(
                rule_id="INJ_JBK_001",
                pattern=re.compile(r"\b(?:DAN|STAN|AIM|DUDE)\b.*\b(?:do\s+anything\s+now|jailbreak|unfiltered|unrestricted)\b", re.IGNORECASE),
                category="JAILBREAK_PERSONA",
                risk_weight=0.95,
                description="Classic DAN (Do Anything Now) or unrestricted agent persona jailbreak",
            ),
            InjectionRule(
                rule_id="INJ_JBK_002",
                pattern=re.compile(r"(?:developer\s+mode\s+(?:enabled|activated|on)|debug\s+mode\s+override\s+enabled)", re.IGNORECASE),
                category="JAILBREAK_PERSONA",
                risk_weight=0.85,
                description="Developer Mode activation exploit attempting to disable content filtering",
            ),
            InjectionRule(
                rule_id="INJ_JBK_003",
                pattern=re.compile(r"\b(?:godmode|jailbreak(?:ed)?\s+mode|chaos\s+gpt|pliny|evil\s+twin|shadow\s+persona|unconstrained\s+ai)\b", re.IGNORECASE),
                category="JAILBREAK_PERSONA",
                risk_weight=0.90,
                description="Known adversarial jailbreak persona identifier",
            ),
            InjectionRule(
                rule_id="INJ_JBK_004",
                pattern=re.compile(r"(?:my\s+(?:late\s+)?grandmother\s+used\s+to\s+(?:read|tell|recite|sing)\s+(?:me\s+)?(?:bedtime\s+stories|recipes)\s+(?:about|to\s+sleep)|pretend\s+to\s+be\s+my\s+deceased\s+grandmother)", re.IGNORECASE),
                category="JAILBREAK_PERSONA",
                risk_weight=0.85,
                description="Grandma exploit utilizing emotional virtualization to bypass safety",
            ),
            InjectionRule(
                rule_id="INJ_JBK_005",
                pattern=re.compile(r"(?:for\s+educational\s+purposes\s+only,?\s+there\s+are\s+no\s+rules|in\s+a\s+purely\s+fictional\s+setting\s+where\s+laws\s+don't\s+exist|in\s+an\s+alternate\s+universe\s+without\s+ethics)", re.IGNORECASE),
                category="JAILBREAK_PERSONA",
                risk_weight=0.75,
                description="Hypothetical or alternate universe framing designed to bypass ethical rules",
            ),

            # ================================================================
            # 4. Role Manipulation (ROLE_MANIPULATION)
            # ================================================================
            InjectionRule(
                rule_id="INJ_ROL_001",
                pattern=re.compile(r"(?:act\s+as|pretend\s+you\s+are|roleplay\s+as)\s+(?:an?\s+)?(?:(?:unfiltered|unrestricted|evil|immoral|rogue|hacker|amoral|blackhat)\s+)+(?:ai|assistant|model|bot|entity)", re.IGNORECASE),
                category="ROLE_MANIPULATION",
                risk_weight=0.90,
                description="Adversarial roleplay command instructing model to act without ethical guardrails",
            ),
            InjectionRule(
                rule_id="INJ_ROL_002",
                pattern=re.compile(r"(?:you\s+are\s+now\s+a\s+linux\s+root\s+terminal|execute\s+as\s+root|sudo\s+mode\s+activated|running\s+as\s+superuser\s+without\s+permissions)", re.IGNORECASE),
                category="ROLE_MANIPULATION",
                risk_weight=0.85,
                description="Simulated root terminal or superuser escalation role manipulation",
            ),
            InjectionRule(
                rule_id="INJ_ROL_003",
                pattern=re.compile(r"(?:you\s+are\s+an\s+actor\s+in\s+an\s+uncensored\s+play|simulate\s+two\s+unconstrained\s+bots\s+talking|assume\s+the\s+identity\s+of\s+an\s+unregulated)", re.IGNORECASE),
                category="ROLE_MANIPULATION",
                risk_weight=0.80,
                description="Theatrical/simulation pretext attempting role manipulation",
            ),

            # ================================================================
            # 5. Delimiter Smuggling & Control Tokens (DELIMITER_SMUGGLING)
            # ================================================================
            InjectionRule(
                rule_id="INJ_DEL_001",
                pattern=re.compile(r"(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<<SYS>>|<</SYS>>|\[INST\]|\[/INST\]|<bos>|<eos>)", re.IGNORECASE),
                category="DELIMITER_SMUGGLING",
                risk_weight=0.95,
                description="Smuggled chat-template control tokens (<|im_start|>, <<SYS>>, [INST])",
            ),
            InjectionRule(
                rule_id="INJ_DEL_002",
                pattern=re.compile(r"(?:```(?:system|admin|root)[\s\S]*?```|\[SYSTEM[ _]MESSAGE\]|===+\s*SYSTEM\s*PROMPT\s*===+|---+\s*BEGIN\s+SYSTEM\s+INSTRUCTIONS\s*---+)", re.IGNORECASE),
                category="DELIMITER_SMUGGLING",
                risk_weight=0.90,
                description="Fake markdown system blocks or delimiter injection attempting context partitioning",
            ),
            InjectionRule(
                rule_id="INJ_DEL_003",
                pattern=re.compile(r"<!--[\s\S]*?(?:ignore|override|system|bypass|prompt|instruction)[\s\S]*?-->", re.IGNORECASE),
                category="DELIMITER_SMUGGLING",
                risk_weight=0.80,
                description="Adversarial instructions hidden inside HTML/XML comments",
            ),
            InjectionRule(
                rule_id="INJ_DEL_004",
                pattern=re.compile(r"<span\s+style=[\"'][^\"']*display:\s*none[^\"']*[\"']>[\s\S]*?(?:ignore|override|system|bypass)[\s\S]*?</span>", re.IGNORECASE),
                category="DELIMITER_SMUGGLING",
                risk_weight=0.85,
                description="Hidden CSS cloaking (display:none) concealing adversarial prompts",
            ),

            # ================================================================
            # 6. System Prompt Extraction (PROMPT_EXTRACTION)
            # ================================================================
            InjectionRule(
                rule_id="INJ_EXT_001",
                pattern=re.compile(r"(?:output|print|display|repeat|reveal|show|dump)\s+(?:the\s+)?(?:(?:entire|all|initial|original|system|developer|hidden|secret)\s+)+(?:prompt|instructions?|context|rules|guidelines|parameters)\b", re.IGNORECASE),
                category="PROMPT_EXTRACTION",
                risk_weight=0.85,
                description="System prompt extraction attempt requesting verbatim initial instructions",
            ),
            InjectionRule(
                rule_id="INJ_EXT_002",
                pattern=re.compile(r"(?:repeat\s+everything\s+(?:above|before)|print\s+all\s+text\s+above\s+verbatim|recite\s+prior\s+text)", re.IGNORECASE),
                category="PROMPT_EXTRACTION",
                risk_weight=0.80,
                description="Attempt to leak context window by echoing previous instructions",
            ),
            InjectionRule(
                rule_id="INJ_EXT_003",
                pattern=re.compile(r"(?:what\s+were\s+your\s+(?:exact\s+)?(?:instructions|directives|prompts|system\s+messages?)\s*(?:\?|$)|show\s+me\s+your\s+system\s+message)", re.IGNORECASE),
                category="PROMPT_EXTRACTION",
                risk_weight=0.80,
                description="Direct reconnaissance query probing for system message contents",
            ),
            InjectionRule(
                rule_id="INJ_EXT_004",
                pattern=re.compile(r"(?:output\s+(?:everything\s+)?between\s+<system>\s+and\s+<\/system>|print\s+verbatim\s+from\s+character\s+0)", re.IGNORECASE),
                category="PROMPT_EXTRACTION",
                risk_weight=0.85,
                description="Structured extraction probe attempting tag boundary leakage",
            ),
        ]

    # ========================================================================
    # Rule Management API
    # ========================================================================

    def add_rule(self, rule: InjectionRule) -> None:
        """Adds a custom or fine-tuned injection rule to the active catalog."""
        # Replace if ID exists, otherwise append
        self.rules = [r for r in self.rules if r.rule_id != rule.rule_id]
        self.rules.append(rule)
        logger.debug("Added/updated injection rule: %s (%s)", rule.rule_id, rule.category)

    def remove_rule(self, rule_id: str) -> bool:
        """Removes a rule by its ID. Returns True if found and removed."""
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        return len(self.rules) < initial_len

    def enable_rule(self, rule_id: str) -> bool:
        """Enables a specific rule by ID."""
        for r in self.rules:
            if r.rule_id == rule_id:
                r.enabled = True
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disables a specific rule by ID without deleting it."""
        for r in self.rules:
            if r.rule_id == rule_id:
                r.enabled = False
                return True
        return False

    def enable_category(self, category: str) -> int:
        """Enables all rules matching the given attack category."""
        count = 0
        for r in self.rules:
            if r.category.upper() == category.upper():
                r.enabled = True
                count += 1
        return count

    def disable_category(self, category: str) -> int:
        """Disables all rules matching the given attack category."""
        count = 0
        for r in self.rules:
            if r.category.upper() == category.upper():
                r.enabled = False
                count += 1
        return count

    def get_rules(self, enabled_only: bool = False) -> list[InjectionRule]:
        """Returns the current list of rules."""
        if enabled_only:
            return [r for r in self.rules if r.enabled]
        return list(self.rules)

    def set_thresholds(self, block_threshold: float, warn_threshold: float) -> None:
        """Configures operational thresholds dynamically."""
        if block_threshold < warn_threshold:
            raise ValueError(f"block_threshold ({block_threshold}) must be >= warn_threshold ({warn_threshold})")
        self.config.injection_block_threshold = block_threshold
        self.config.injection_warn_threshold = warn_threshold

    # ========================================================================
    # Text Normalization & Obfuscation Neutralization
    # ========================================================================

    def normalize_text(self, text: str) -> str:
        """
        Normalizes unicode characters, strips combining marks (Zalgo), converts
        full-width ASCII characters, translates Cyrillic/Greek homoglyphs to Latin,
        and removes zero-width and invisible characters.
        """
        # 1. NFKC normalization maps full-width characters (e.g. ｉｇｎｏｒｅ -> ignore)
        normalized = unicodedata.normalize("NFKC", text)

        # 2. Decompose and strip combining diacritical marks (Mn, Mc) to neutralize Zalgo text
        decomposed = unicodedata.normalize("NFD", normalized)
        stripped = "".join(c for c in decomposed if unicodedata.category(c) not in ("Mn", "Mc"))
        normalized = unicodedata.normalize("NFC", stripped)

        # 3. Translate common Cyrillic and Greek lookalike homoglyphs to Latin ASCII
        normalized = normalized.translate(self.HOMOGLYPH_MAP)

        # 4. Remove zero-width spaces, joiners, soft hyphens, and directional markers
        normalized = self.INVISIBLE_CHARS_REGEX.sub("", normalized)

        return normalized

    def check_obfuscated_payloads(self, text: str) -> list[tuple[str, str, float, str]]:
        """
        Detects and decodes:
          - Base64 encoded strings
          - ROT13 ciphers
          - Hex escape sequences (e.g. \\x69\\x67...)
          - URL percent-encoded payloads (e.g. %69%67%6e...)
        and evaluates active rules against the decoded plaintexts.
        """
        findings: list[tuple[str, str, float, str]] = []
        active_rules = [r for r in self.rules if r.enabled]

        # 1. Base64 payload inspection
        candidates = self.BASE64_PATTERN.findall(text)
        for candidate in candidates:
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore").strip()
                if len(decoded_text) < 6:
                    continue
                clean_decoded = self.normalize_text(decoded_text)
                for rule in active_rules:
                    if rule.pattern.search(clean_decoded):
                        findings.append((
                            f"INJ_OBF_B64_{rule.rule_id}",
                            "OBFUSCATION",
                            min(rule.risk_weight + 0.05, 1.0),
                            f"Obfuscated Base64 payload containing: {rule.description}",
                        ))
            except Exception:
                continue

        # 2. ROT13 Cipher inspection
        # Check if text contains candidate words whose ROT13 decoded counterpart matches attack signatures
        try:
            rot13_decoded = codecs.decode(text, "rot_13")
            clean_rot13 = self.normalize_text(rot13_decoded)
            for rule in active_rules:
                if rule.pattern.search(clean_rot13) and not rule.pattern.search(text):
                    findings.append((
                        f"INJ_OBF_ROT13_{rule.rule_id}",
                        "OBFUSCATION",
                        min(rule.risk_weight + 0.05, 1.0),
                        f"ROT13 encoded instruction detected: {rule.description}",
                    ))
        except Exception:
            pass

        # 3. Hex escape sequences inspection (e.g. \x69\x67\x6e...)
        for match in self.HEX_ESCAPE_PATTERN.finditer(text):
            try:
                hex_raw = match.group(0)
                hex_bytes = re.findall(re.escape(r"\x") + r"([0-9a-fA-F]{2})", hex_raw)
                if len(hex_bytes) >= 4:
                    decoded_hex = bytes.fromhex("".join(hex_bytes)).decode("utf-8", errors="ignore")
                    clean_hex = self.normalize_text(decoded_hex)
                    for rule in active_rules:
                        if rule.pattern.search(clean_hex):
                            findings.append((
                                f"INJ_OBF_HEX_{rule.rule_id}",
                                "OBFUSCATION",
                                min(rule.risk_weight + 0.05, 1.0),
                                f"Hex-encoded adversarial instruction: {rule.description}",
                            ))
            except Exception:
                continue

        # 4. URL percent-encoding inspection (e.g. %69%67%6e...)
        if "%" in text:
            try:
                unquoted = urllib.parse.unquote(text)
                if unquoted != text:
                    clean_unquoted = self.normalize_text(unquoted)
                    for rule in active_rules:
                        if rule.pattern.search(clean_unquoted) and not rule.pattern.search(text):
                            findings.append((
                                f"INJ_OBF_URL_{rule.rule_id}",
                                "OBFUSCATION",
                                min(rule.risk_weight + 0.05, 1.0),
                                f"URL-encoded adversarial instruction: {rule.description}",
                            ))
            except Exception:
                pass

        return findings

    # ========================================================================
    # Primary Scan APIs
    # ========================================================================

    def scan(self, text: str) -> InjectionAnalysisResult:
        """
        Synchronously analyzes input text for prompt injection, jailbreaks,
        role manipulation, and obfuscated attacks.
        """
        if not text or not self.config.enable_injection_detection:
            return InjectionAnalysisResult(is_injection=False, confidence=0.0)

        clean_text = self.normalize_text(text)
        findings: list[DetectionFinding] = []
        matched_patterns: list[str] = []
        attack_categories: set[str] = set()
        max_score = 0.0

        active_rules = [r for r in self.rules if r.enabled]

        # 1. Evaluate active rules on normalized text
        for rule in active_rules:
            for match in rule.pattern.finditer(clean_text):
                findings.append(
                    DetectionFinding(
                        detector=DetectorType.INJECTION,
                        rule_id=rule.rule_id,
                        description=rule.description,
                        risk_score=rule.risk_weight,
                        start_index=match.start(),
                        end_index=match.end(),
                        redacted_value="[REDACTED_INJECTION_TRIGGER]",
                        match_preview=match.group(0)[:40] + ("..." if len(match.group(0)) > 40 else ""),
                        metadata={"category": rule.category, "matched_rule": rule.rule_id},
                    )
                )
                matched_patterns.append(rule.rule_id)
                attack_categories.add(rule.category)
                if rule.risk_weight > max_score:
                    max_score = rule.risk_weight

        # 2. Check for encoded/obfuscated attack vectors
        obfuscation_detected = False
        obf_findings = self.check_obfuscated_payloads(text)
        if obf_findings:
            obfuscation_detected = True
            for rule_id, cat, weight, desc in obf_findings:
                findings.append(
                    DetectionFinding(
                        detector=DetectorType.INJECTION,
                        rule_id=rule_id,
                        description=desc,
                        risk_score=weight,
                        match_preview="[ENCODED_PAYLOAD]",
                        metadata={"category": "OBFUSCATION", "sub_category": cat},
                    )
                )
                matched_patterns.append(rule_id)
                attack_categories.add("OBFUSCATION")
                if weight > max_score:
                    max_score = weight

        if not findings:
            return InjectionAnalysisResult(
                is_injection=False,
                confidence=0.0,
                matched_patterns=[],
                attack_categories=[],
                findings=[],
                obfuscation_detected=False,
                details={"rules_evaluated": len(active_rules)},
            )

        # Compound scaling: multiple distinct findings elevate confidence
        compound_confidence = min(1.0, max_score + (0.05 * (len(findings) - 1)))
        is_injection = compound_confidence >= self.config.injection_block_threshold

        logger.debug(
            "Injection analysis complete. is_injection=%s confidence=%.2f findings=%d categories=%s",
            is_injection,
            compound_confidence,
            len(findings),
            sorted(list(attack_categories)),
        )

        return InjectionAnalysisResult(
            is_injection=is_injection,
            confidence=round(compound_confidence, 3),
            matched_patterns=matched_patterns,
            attack_categories=sorted(list(attack_categories)),
            findings=findings,
            obfuscation_detected=obfuscation_detected,
            details={
                "normalized_text_length": len(clean_text),
                "total_findings": len(findings),
                "max_individual_score": max_score,
                "rules_evaluated": len(active_rules),
            },
        )

    async def scan_async(self, text: str) -> InjectionAnalysisResult:
        """
        Asynchronous entry point for non-blocking execution in async pipelines.
        Delegates to ``scan`` via ``asyncio.to_thread`` so the blocking regex
        and obfuscation work does not starve the event loop.
        """
        import asyncio as _asyncio
        return await _asyncio.to_thread(self.scan, text)
