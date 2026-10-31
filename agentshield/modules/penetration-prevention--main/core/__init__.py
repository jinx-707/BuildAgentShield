"""
AgentShield: Unified Runtime Security Gateway for AI Agents.
Core Security Engine and Input/Output Guardrails.
"""

from core.config import AgentShieldConfig, setup_logger
from core.dlp_engine import DLPEngine
from core.injection_detector import InjectionRule, PromptInjectionDetector
from core.input_guard import InputGuard
from core.output_guard import OutputGuard
from core.pii_detector import PIIDetector
from core.provenance import ProvenanceEngine
from core.risk_engine import RiskEngine
from core.secret_scanner import SecretRule, SecretScanner
from core.schemas import (
    Action,
    AgentShieldError,
    ConfigurationError,
    DetectionFinding,
    DetectorType,
    DLPAnalysisResult,
    DLPViolationError,
    GuardrailContext,
    GuardrailInputRequest,
    GuardrailInputResponse,
    GuardrailOutputRequest,
    GuardrailOutputResponse,
    GuardrailViolationError,
    InjectionAnalysisResult,
    InjectionDetectedError,
    PIIAnalysisResult,
    PIIType,
    PIIViolationError,
    ProvenanceRecord,
    ProvenanceVerificationError,
    RedactionMode,
    RiskLevel,
    RiskScore,
    RiskThresholdExceededError,
    SecretAnalysisResult,
    SecretLeakError,
    SecretType,
    SensitivityLevel,
    SourceType,
    TrustLevel,
)

__version__ = "1.0.0"

__all__ = [
    # Main Guardrails
    "InputGuard",
    "OutputGuard",
    # Sub-Engines & Detectors
    "PromptInjectionDetector",
    "InjectionRule",
    "PIIDetector",
    "SecretScanner",
    "SecretRule",
    "DLPEngine",
    "RiskEngine",
    "ProvenanceEngine",
    # Configuration & Logging
    "AgentShieldConfig",
    "setup_logger",
    # Enums
    "Action",
    "RiskLevel",
    "DetectorType",
    "SensitivityLevel",
    "PIIType",
    "SecretType",
    "RedactionMode",
    "SourceType",
    "TrustLevel",
    # Models & Payloads
    "DetectionFinding",
    "InjectionAnalysisResult",
    "PIIAnalysisResult",
    "SecretAnalysisResult",
    "DLPAnalysisResult",
    "RiskScore",
    "ProvenanceRecord",
    "GuardrailContext",
    "GuardrailInputRequest",
    "GuardrailInputResponse",
    "GuardrailOutputRequest",
    "GuardrailOutputResponse",
    # Exceptions
    "AgentShieldError",
    "ConfigurationError",
    "GuardrailViolationError",
    "InjectionDetectedError",
    "SecretLeakError",
    "PIIViolationError",
    "DLPViolationError",
    "RiskThresholdExceededError",
    "ProvenanceVerificationError",
]
