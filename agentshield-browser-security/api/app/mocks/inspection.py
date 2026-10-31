import re

from app.interfaces.inspection import ContentInspectionRequest
from app.schemas.browser import Finding, InspectionResult


class MockContentInspector:
    """Development-only pattern inspector. It is not a security control."""

    name = "mock-content-inspector"

    _RULES = (
        (
            "script-tag",
            re.compile(r"<script\b", re.IGNORECASE),
            "high",
            "Inline or external script tag found in returned content.",
        ),
        (
            "javascript-uri",
            re.compile(r"javascript\s*:", re.IGNORECASE),
            "high",
            "JavaScript URI scheme found in returned content.",
        ),
        (
            "inline-event-handler",
            re.compile(r"\son[a-z]+\s*=", re.IGNORECASE),
            "medium",
            "Inline event handler attribute found in returned content.",
        ),
        (
            "iframe-tag",
            re.compile(r"<iframe\b", re.IGNORECASE),
            "low",
            "Iframe element found in returned content.",
        ),
    )

    async def inspect(self, request: ContentInspectionRequest) -> InspectionResult:
        findings: list[Finding] = []
        for rule_id, pattern, severity, message in self._RULES:
            if pattern.search(request.content):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        location=request.url,
                    )
                )

        return InspectionResult(inspector_name=self.name, findings=findings)
