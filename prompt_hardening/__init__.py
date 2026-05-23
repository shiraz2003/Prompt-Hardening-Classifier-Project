"""
Prompt Hardening Classifier Package

A comprehensive security middleware for detecting and mitigating:
- Prompt injection attacks
- Unicode smuggling (tag-blocks, variation selectors, zero-width chars)
- Homoglyph obfuscation
- Bidirectional override attacks
- Harmful content (violence, drugs, illegal activities)

Features:
- Multi-layer detection (Rules-Based + ML)
- Real-time sanitization
- Detailed attack logging
- Transparent defense mechanisms

Project: PUSL3190 — Prompt Hardening Classifier
Author: Shiraz Sappideen (Plymouth Index 10952638)
"""

# Import core classes from submodules (NOT from self!)
from .pipeline import HardeningPipeline
from .detector import PromptDetector
from .sanitizer import Sanitizer

# Package metadata
__version__ = "1.0.0"
__author__ = "Shiraz Sappideen"
__project__ = "PUSL3190 - Prompt Hardening Classifier"

# Public API
__all__ = [
    "HardeningPipeline",
    "PromptDetector",
    "Sanitizer",
]