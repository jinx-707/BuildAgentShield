"""
Content extractor — wraps raw browser content and marks it untrusted.
All extracted content must pass through ContentInspectionPort before
being returned to the agent.
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.contracts import ContentClassification, SecurityFinding
from app.core.decisions import ContentSource, TrustLevel
from app.core.result_models import PageContent
from app.integrations.ports import ContentInspectionPort, InspectionResult

logger = logging.getLogger(__name__)


def classify_webpage_content(url: str) -> ContentClassification:
    """Mark content as external/untrusted before inspection."""
    return ContentClassification(
        source=ContentSource.EXTERNAL_WEBPAGE,
        trust_level=TrustLevel.UNTRUSTED,
        url=url,
        inspected=False,
        safe_to_return=False,
    )


async def extract_and_inspect(
    raw_content: dict[str, Any],
    url: str,
    inspector: ContentInspectionPort,
) -> tuple[PageContent, ContentClassification]:
    """
    Takes raw browser extraction output, inspects it, and returns:
    - PageContent (safe to return to agent if classification.safe_to_return is True)
    - ContentClassification (trust metadata)

    The content is NEVER returned to the agent without inspection.
    """
    title = raw_content.get("title", "")
    text = raw_content.get("text", "")
    metadata = raw_content.get("metadata", {})

    classification = classify_webpage_content(url)

    # Inspect for prompt injection / harmful instructions
    inspection: InspectionResult = await inspector.inspect(
        content=text,
        source=ContentSource.EXTERNAL_WEBPAGE,
        metadata={"url": url, "title": title},
    )

    findings = [
        SecurityFinding(
            finding_type=f.finding_type,
            severity=f.severity,
            description=f.description,
            location=f.location,
        )
        for f in inspection.findings
    ]

    classification = ContentClassification(
        source=ContentSource.EXTERNAL_WEBPAGE,
        trust_level=TrustLevel.UNTRUSTED,
        url=url,
        inspected=True,
        findings=findings,
        safe_to_return=inspection.safe_to_use,
    )

    # If injection detected, redact the content
    if not inspection.safe_to_use:
        logger.warning(
            "Content inspection blocked webpage content from %s: %s",
            url,
            inspection.summary,
        )
        text = (
            "[CONTENT REDACTED: Security inspection detected potentially malicious content. "
            f"Findings: {len(findings)}. "
            "This content cannot be returned to the agent.]"
        )

    page = PageContent(
        url=url,
        title=title,
        text=text,
        metadata=metadata,
        inspected=True,
    )

    return page, classification
