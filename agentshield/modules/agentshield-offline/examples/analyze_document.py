"""
AgentShield Offline — Document Analysis Demo Script.

Demonstrates how to analyze a document through the security pipeline.

Usage:
    python examples/analyze_document.py /path/to/document.pdf
    python examples/analyze_document.py /path/to/document.txt
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.capabilities.offline.documents.document_inspector import DocumentInspector
from app.capabilities.offline.documents.gateway import DocumentGateway
from app.capabilities.offline.documents.malware_scanner import ClamAVScanner
from app.capabilities.offline.documents.quarantine import QuarantineManager
from app.core.contracts import DocumentAnalysisRequest, SecurityDecision
from app.integrations.local_content_inspector import LocalDevelopmentContentInspector


async def analyze(file_path: str) -> None:
    # Build gateway with local development adapters
    inspector = DocumentInspector(
        LocalDevelopmentContentInspector(), fail_closed=False
    )
    scanner = ClamAVScanner()
    quarantine = QuarantineManager()

    gateway = DocumentGateway(
        inspector=inspector,
        scanner=scanner,
        quarantine=quarantine,
        fail_closed_on_scan_unavailable=False,  # Allow scanner-unavailable in demo
    )

    request = DocumentAnalysisRequest(
        agent_id="demo-agent",
        tool_name="analyze_document",
        operation="analyze",
        file_path=file_path,
        extract_text=True,
        extract_metadata=True,
        run_malware_scan=True,
    )

    print(f"\n{'='*60}")
    print(f"Analyzing: {file_path}")
    print("="*60)

    response = await gateway.analyze(request)

    print(f"Decision:     {response.decision.value}")
    print(f"Status:       {response.status.value}")
    print(f"Risk Level:   {response.risk_level.value}")

    if response.reason:
        print(f"Reason:       {response.reason}")

    if response.result:
        r = response.result
        print(f"\nDocument Details:")
        print(f"  Format:       {r.get('file_format', 'unknown')}")
        print(f"  Size:         {r.get('file_size', 0):,} bytes")
        print(f"  Hash (SHA256):{r.get('content_hash', '')[:16]}...")
        print(f"  Trust Level:  {r.get('trust_level', 'unknown')}")
        print(f"  Extraction:   {r.get('extraction_status', 'unknown')}")
        print(f"  Scan Status:  {r.get('malware_scan_status', 'unknown')}")
        print(f"  Inspection:   {r.get('inspection_status', 'unknown')}")
        if r.get("page_count"):
            print(f"  Pages:        {r['page_count']}")
        if r.get("extracted_text_length"):
            print(f"  Text Length:  {r['extracted_text_length']:,} chars")

    if response.security_findings:
        print(f"\nSecurity Findings ({len(response.security_findings)}):")
        for f in response.security_findings:
            print(f"  [{f.severity.value}] {f.category}: {f.description[:80]}")

    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Create a demo text file if no argument given
        demo_file = Path("/tmp/agentshield_demo.txt")
        demo_file.write_text(
            "This is a demo document.\n"
            "It contains normal text content.\n"
            "AgentShield will analyze it for security issues.\n"
        )
        asyncio.run(analyze(str(demo_file)))
    else:
        asyncio.run(analyze(sys.argv[1]))
