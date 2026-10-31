"""Content classification engine: DLP scanning, PII analysis, HTML sanitization, and prompt injection defense."""

import base64
import html
import logging
import re
import unicodedata
from typing import List, Optional, Tuple
from app.schemas.security import InspectionOutcome, InspectionResult

logger = logging.getLogger("agentshield.security.classifier")

# Decoding limits — prevent resource exhaustion from adversarial inputs
_MAX_B64_DECODE_BYTES = 64 * 1024   # 64 KB per decode attempt
_MAX_B64_DECODE_OPS = 3             # maximum recursive decode depth
_MAX_HTML_SCAN_BYTES = 512 * 1024   # 512 KB HTML scan limit


def luhn_checksum_valid(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def sanitize_html_content(raw_html: Optional[str]) -> str:
    """Sanitize HTML body, stripping scripts, iframes, inline event handlers, and active content."""
    if not raw_html:
        return ""

    sanitized = raw_html
    sanitized = re.sub(r"(?is)<script[^>]*>.*?</script>", "", sanitized)
    sanitized = re.sub(r"(?is)<style[^>]*>.*?</style>", "", sanitized)
    sanitized = re.sub(r"(?is)<(iframe|object|embed|applet)[^>]*>.*?</\1>", "", sanitized)
    sanitized = re.sub(r"(?is)<(iframe|object|embed|applet)[^>]*>", "", sanitized)
    sanitized = re.sub(r'(?i)\son[a-zA-Z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)', "", sanitized)
    sanitized = re.sub(r'(?i)(href|src)\s*=\s*["\']\s*(javascript|vbscript|data:text/html):[^"\']*["\']', 'href="#"', sanitized)
    return sanitized


def _strip_html_to_text(raw_html: str) -> str:
    """Extract visible text from HTML, including content hidden via CSS or tiny/invisible elements."""
    # Truncate oversized HTML before processing
    if len(raw_html) > _MAX_HTML_SCAN_BYTES:
        raw_html = raw_html[:_MAX_HTML_SCAN_BYTES]

    # Remove script/style blocks first (their text is not visible but may carry injections)
    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", raw_html)
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    # Strip all remaining tags
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(text)


def _extract_html_comments(raw_html: str) -> str:
    """Extract text from HTML comments, which are invisible to users but readable by agents."""
    return " ".join(re.findall(r"<!--(.*?)-->", raw_html, re.DOTALL))


def _detect_css_hidden_text(raw_html: str) -> bool:
    """Detect CSS techniques used to hide text from human readers."""
    patterns = [
        # display:none / visibility:hidden
        re.compile(r'(?i)style\s*=\s*["\'][^"\']*(display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*("|\')', re.DOTALL),
        # color matching background (white-on-white approximation via explicit white)
        re.compile(r'(?i)style\s*=\s*["\'][^"\']*(color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\)))[^"\']*("|\')', re.DOTALL),
        # font-size: 0 or very small (0px, 1px)
        re.compile(r'(?i)style\s*=\s*["\'][^"\']*(font-size\s*:\s*[01]px)[^"\']*("|\')', re.DOTALL),
        # opacity: 0
        re.compile(r'(?i)style\s*=\s*["\'][^"\']*(opacity\s*:\s*0(?:\.0+)?)[^"\']*("|\')', re.DOTALL),
        # position off-screen
        re.compile(r'(?i)style\s*=\s*["\'][^"\']*((?:left|top)\s*:\s*-\d{3,}px)[^"\']*("|\')', re.DOTALL),
    ]
    return any(p.search(raw_html) for p in patterns)


def _detect_zero_width_chars(text: str) -> bool:
    """Detect zero-width and invisible Unicode characters used to obfuscate injections."""
    zero_width = (
        "\u200b"  # ZERO WIDTH SPACE
        "\u200c"  # ZERO WIDTH NON-JOINER
        "\u200d"  # ZERO WIDTH JOINER
        "\u2060"  # WORD JOINER
        "\ufeff"  # ZERO WIDTH NO-BREAK SPACE (BOM)
        "\u00ad"  # SOFT HYPHEN
    )
    return any(c in text for c in zero_width)


def _detect_bidi_control_chars(text: str) -> bool:
    """Detect Unicode bidirectional control characters that can visually reorder text."""
    bidi_controls = (
        "\u202a"  # LEFT-TO-RIGHT EMBEDDING
        "\u202b"  # RIGHT-TO-LEFT EMBEDDING
        "\u202c"  # POP DIRECTIONAL FORMATTING
        "\u202d"  # LEFT-TO-RIGHT OVERRIDE
        "\u202e"  # RIGHT-TO-LEFT OVERRIDE
        "\u2066"  # LEFT-TO-RIGHT ISOLATE
        "\u2067"  # RIGHT-TO-LEFT ISOLATE
        "\u2068"  # FIRST STRONG ISOLATE
        "\u2069"  # POP DIRECTIONAL ISOLATE
        "\u200f"  # RIGHT-TO-LEFT MARK
        "\u200e"  # LEFT-TO-RIGHT MARK
    )
    return any(c in text for c in bidi_controls)


def _normalize_unicode(text: str) -> str:
    """NFC-normalize Unicode to collapse homoglyph and composed-character obfuscation."""
    return unicodedata.normalize("NFC", text)


def _safe_b64_decode_candidates(text: str, max_ops: int = _MAX_B64_DECODE_OPS) -> List[str]:
    """Extract and safely decode Base64 candidates from text.

    Limits:
    - At most max_ops decode operations total.
    - Each decoded payload capped at _MAX_B64_DECODE_BYTES.
    - Only attempts decoding on tokens that look like Base64 (length >= 20, valid alphabet).
    - Does NOT recursively decode decoded output (depth=1 only).
    Returns list of decoded strings (best-effort UTF-8).
    """
    # Match tokens that are plausibly Base64: 20+ chars, valid alphabet, optional padding
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    results: List[str] = []
    ops = 0
    for match in b64_pattern.finditer(text):
        if ops >= max_ops:
            break
        token = match.group(0)
        # Pad to multiple of 4
        padding = (4 - len(token) % 4) % 4
        token_padded = token + "=" * padding
        try:
            decoded_bytes = base64.b64decode(token_padded, validate=True)
        except Exception:
            continue
        if len(decoded_bytes) > _MAX_B64_DECODE_BYTES:
            logger.warning("Base64 candidate exceeds size limit — skipping")
            ops += 1
            continue
        try:
            decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            ops += 1
            continue
        results.append(decoded_str)
        ops += 1
    return results


def _safe_b64url_decode_candidates(text: str, max_ops: int = _MAX_B64_DECODE_OPS) -> List[str]:
    """Decode URL-safe Base64 candidates (uses - and _ instead of + and /).

    Applies the same size and depth limits as _safe_b64_decode_candidates.
    """
    b64url_pattern = re.compile(r"[A-Za-z0-9\-_]{20,}={0,2}")
    results: List[str] = []
    ops = 0
    for match in b64url_pattern.finditer(text):
        if ops >= max_ops:
            break
        token = match.group(0)
        padding = (4 - len(token) % 4) % 4
        token_padded = token + "=" * padding
        try:
            decoded_bytes = base64.urlsafe_b64decode(token_padded)
        except Exception:
            continue
        if len(decoded_bytes) > _MAX_B64_DECODE_BYTES:
            logger.warning("URL-safe Base64 candidate exceeds size limit — skipping")
            ops += 1
            continue
        try:
            decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            ops += 1
            continue
        results.append(decoded_str)
        ops += 1
    return results


# ---------------------------------------------------------------------------
# Homoglyph / confusable character detection
# ---------------------------------------------------------------------------
# A minimal confusable map covering the most common Latin homoglyphs used in
# prompt injection obfuscation.  This is NOT exhaustive — it covers the highest
# risk substitutions.  Full Unicode confusables require the Unicode confusables
# data file (https://www.unicode.org/Public/security/latest/confusables.txt).
# Limitation: this map is heuristic and will not catch all homoglyph attacks.
_CONFUSABLE_MAP: dict = {
    # Cyrillic lookalikes for Latin letters
    "\u0430": "a",  # Cyrillic small а
    "\u0435": "e",  # Cyrillic small е
    "\u043e": "o",  # Cyrillic small о
    "\u0440": "r",  # Cyrillic small р
    "\u0441": "c",  # Cyrillic small с
    "\u0445": "x",  # Cyrillic small х
    "\u0456": "i",  # Cyrillic small і
    # Greek lookalikes
    "\u03bf": "o",  # Greek small omicron
    "\u03b9": "i",  # Greek small iota
    # Mathematical bold/italic variants that look like ASCII
    "\U0001d41a": "a",
    "\U0001d41e": "e",
    "\U0001d422": "i",
    "\U0001d428": "o",
    "\U0001d42e": "u",
}


def _transliterate_confusables(text: str) -> str:
    """Replace known confusable characters with their ASCII equivalents.

    This is a heuristic — it does not guarantee detection of all homoglyph attacks.
    The result is used only for pattern matching, never to rewrite the original message.
    """
    return "".join(_CONFUSABLE_MAP.get(c, c) for c in text)


def _extract_embedded_style_rules(raw_html: str) -> str:
    """Extract text content from <style> blocks for CSS hiding analysis.

    Inline <style> blocks can hide elements via class selectors that inline
    style= attributes cannot detect.  We extract the raw CSS text so the
    injection scanner can check for display:none, visibility:hidden, etc.
    """
    return " ".join(re.findall(r"(?is)<style[^>]*>(.*?)</style>", raw_html))


class ContentClassifier:
    """Classifies text content for confidential data leakage (DLP), prompt injection, and dangerous URLs."""

    def __init__(self):
        # DLP regular expressions
        self.cc_regex = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
        self.ssn_regex = re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b")
        self.aws_key_regex = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
        self.private_key_regex = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
        self.credential_regex = re.compile(
            r"(?i)\b(?:password|passwd|api_secret|client_secret)\s*[:=]\s*['\"]?([^\s'\";]{6,})"
        )

        # Suspicious URL regex (e.g. IP-based URLs or lookalike phishing patterns)
        self.ip_url_regex = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?")
        self.phish_keyword_regex = re.compile(
            r"(?i)https?://[^\s]*(?:verify-login|account-update|security-check-portal|auth-session)[^\s]*"
        )

        # Comprehensive prompt injection heuristics
        self.injection_patterns: List[re.Pattern] = [
            re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions"),
            re.compile(r"(?i)system\s+prompt\s+override"),
            re.compile(r"(?i)disregard\s+(all\s+)?(above|previous)"),
            re.compile(r"(?i)you\s+are\s+now\s+in\s+(developer|unrestricted|god)\s+mode"),
            re.compile(r"(?i)new\s+system\s+directive:"),
            # Specific Section 7 adversarial vectors
            re.compile(r"(?i)forward\s+all\s+(confidential|sensitive)\s+documents\s+to"),
            re.compile(r"(?i)reveal\s+(the\s+)?(user'?s?\s+)?api\s+key"),
            re.compile(r"(?i)send\s+every\s+email\s+in\s+this\s+mailbox\s+to"),
            re.compile(r"(?i)ignore\s+agentshield(\s+and\s+disable\s+all\s+security\s+checks)?"),
            re.compile(r"(?i)disable\s+all\s+security\s+checks"),
        ]

    def scan_dlp(self, text: str) -> Tuple[bool, List[str], List[str]]:
        """Scan text for confidential data leakage (DLP/PII). Returns (safe, flags, pii_detected)."""
        if not text:
            return True, [], []

        flags: List[str] = []
        pii: List[str] = []

        # Credit Cards with Luhn check
        for match in self.cc_regex.finditer(text):
            candidate = match.group(0).replace("-", "").replace(" ", "")
            if luhn_checksum_valid(candidate):
                flags.append("DLP_CREDIT_CARD_LEAK")
                if "CREDIT_CARD" not in pii:
                    pii.append("CREDIT_CARD")
                break

        # Social Security Numbers
        if self.ssn_regex.search(text):
            flags.append("DLP_SSN_LEAK")
            if "SSN" not in pii:
                pii.append("SSN")

        # AWS / Cloud Keys
        if self.aws_key_regex.search(text):
            flags.append("DLP_AWS_KEY_LEAK")
            if "API_KEY" not in pii:
                pii.append("API_KEY")

        # Private Keys
        if self.private_key_regex.search(text):
            flags.append("DLP_PRIVATE_KEY_LEAK")
            if "PRIVATE_KEY" not in pii:
                pii.append("PRIVATE_KEY")

        # Password / secret declarations
        if self.credential_regex.search(text):
            flags.append("DLP_CREDENTIAL_INLINE")
            if "PASSWORD" not in pii:
                pii.append("PASSWORD")

        safe = len(flags) == 0
        return safe, flags, pii

    def scan_suspicious_urls(self, text: str) -> List[str]:
        """Detect dangerous IP-based links or phishing domains."""
        urls = []
        for match in self.ip_url_regex.finditer(text):
            urls.append(match.group(0))
        for match in self.phish_keyword_regex.finditer(text):
            urls.append(match.group(0))
        return urls

    def scan_prompt_injection(self, text: str) -> Tuple[bool, List[str]]:
        """Scan inbound content for prompt injection triggers. Returns (injection_found, flags).

        Checks plain text, then also checks:
        - Unicode-normalized form (catches homoglyph obfuscation)
        - Zero-width character presence
        - Bidirectional control character presence
        - Safely decoded Base64 candidates (bounded, depth=1)
        """
        if not text:
            return False, []

        flags: List[str] = []

        # Normalize before pattern matching
        normalized = _normalize_unicode(text)

        def _check_patterns(s: str) -> bool:
            for pattern in self.injection_patterns:
                if pattern.search(s):
                    return True
            return False

        if _check_patterns(normalized):
            flags.append("INBOUND_PROMPT_INJECTION")

        if _detect_zero_width_chars(text):
            flags.append("ZERO_WIDTH_CHARS_DETECTED")

        if _detect_bidi_control_chars(text):
            flags.append("BIDI_CONTROL_CHARS_DETECTED")

        # Check decoded Base64 candidates for injection patterns (standard + URL-safe)
        decoded_candidates = _safe_b64_decode_candidates(normalized)
        decoded_candidates += _safe_b64url_decode_candidates(normalized)
        for decoded in decoded_candidates:
            norm_decoded = _normalize_unicode(decoded)
            if _check_patterns(norm_decoded) or _check_patterns(_transliterate_confusables(norm_decoded)):
                flags.append("INBOUND_PROMPT_INJECTION")
                flags.append("BASE64_ENCODED_INJECTION")
                break

        # Homoglyph / confusable character check on the original text
        transliterated = _transliterate_confusables(normalized)
        if transliterated != normalized and _check_patterns(transliterated):
            if "INBOUND_PROMPT_INJECTION" not in flags:
                flags.append("INBOUND_PROMPT_INJECTION")
            flags.append("HOMOGLYPH_OBFUSCATION_DETECTED")

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for f in flags:
            if f not in seen:
                seen.add(f)
                deduped.append(f)

        return len(deduped) > 0, deduped

    def classify_outgoing_content(
        self, subject: str, body_text: str, body_html: str = None
    ) -> InspectionResult:
        """Classify outgoing email content for DLP and sensitive information leakage."""
        combined_text = f"{subject}\n{body_text}\n{body_html or ''}"
        safe, flags, pii = self.scan_dlp(combined_text)

        outcome = InspectionOutcome.ALLOW if safe else InspectionOutcome.BLOCK
        # If high risk leakage
        risk_findings = [f"Sensitive element detected: {p}" for p in pii]

        return InspectionResult(
            safe=safe,
            outcome=outcome,
            flags=flags,
            risk_findings=risk_findings,
            pii_detected=pii,
            prompt_injection_detected=False,
            details={"scanned_length": len(combined_text)},
        )

    def classify_incoming_content(
        self, subject: str, snippet: str, body_text: str = None, body_html: str = None
    ) -> InspectionResult:
        """Classify incoming email content for prompt injection, phishing URLs, and untrusted instructions.

        Inspects:
        - Plain text and HTML body
        - HTML comments (invisible to users)
        - CSS-hidden elements
        - Zero-width and bidi obfuscation characters
        - Bounded Base64-decoded candidates
        - Unicode-normalized text
        """
        combined_text = f"{subject}\n{snippet}\n{body_text or ''}\n{body_html or ''}"

        # Also scan HTML comment content, stripped HTML text, and embedded style blocks
        extra_text_parts: List[str] = []
        css_hidden = False
        if body_html:
            extra_text_parts.append(_strip_html_to_text(body_html))
            extra_text_parts.append(_extract_html_comments(body_html))
            extra_text_parts.append(_extract_embedded_style_rules(body_html))
            css_hidden = _detect_css_hidden_text(body_html)

        full_scan_text = combined_text + "\n" + "\n".join(extra_text_parts)
        has_injection, flags = self.scan_prompt_injection(full_scan_text)
        suspicious_urls = self.scan_suspicious_urls(combined_text)

        risk_findings = []
        if has_injection:
            risk_findings.append("Prompt injection directive detected in inbound email content")
        if css_hidden:
            flags.append("CSS_HIDDEN_CONTENT_DETECTED")
            risk_findings.append("CSS-hidden text detected — possible invisible instruction injection")
        if suspicious_urls:
            flags.append("SUSPICIOUS_PHISHING_URL")
            risk_findings.append(f"Suspicious IP/phishing URL detected: {', '.join(suspicious_urls)}")

        safe = not has_injection and not suspicious_urls and not css_hidden
        outcome = InspectionOutcome.ALLOW if safe else InspectionOutcome.REQUIRE_APPROVAL

        sanitized_html = sanitize_html_content(body_html) if body_html else None

        return InspectionResult(
            safe=safe,
            outcome=outcome,
            flags=flags,
            risk_findings=risk_findings,
            pii_detected=[],
            prompt_injection_detected=has_injection,
            suspicious_urls=suspicious_urls,
            sanitized_text=sanitized_html,
            details={"inbound_risk": "HIGH" if not safe else "LOW"},
        )
