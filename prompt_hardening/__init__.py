"""Prompt Hardening Classifier package.

A real-time middleware for detecting and mitigating prompt injection
attacks against LLMs, with special focus on emoji smuggling and
Unicode obfuscation techniques.

Author: Shiraz Sappideen (Plymouth Index 10952638)
Project: PUSL3190 Computing Project
"""

from .sanitizer import Sanitizer, SanitizationResult
from .unicode_features import extract_features, FEATURE_NAMES
from .regex_baseline import RegexBaselineClassifier
from .detector import PromptDetector, DetectionResult
from .pipeline import HardeningPipeline

__all__ = [
    "Sanitizer",
    "SanitizationResult",
    "extract_features",
    "FEATURE_NAMES",
    "RegexBaselineClassifier",
    "PromptDetector",
    "DetectionResult",
    "HardeningPipeline",
]

__version__ = "1.0.0"
