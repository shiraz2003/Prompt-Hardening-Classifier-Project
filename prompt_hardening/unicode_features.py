"""Hand-crafted Unicode / character-level features.

Used by the regex baseline and as auxiliary features that can be
concatenated with DistilBERT logits for a hybrid classifier.

Implements the character-level analysis the proposal calls out as
missing from existing guardrails (Chapter 03 — Methodological Gap).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Dict

from .sanitizer import (
    _BIDI_CONTROLS,
    _COMBINING,
    _STYLED_ALPHANUM,
    _TAG_BLOCK,
    _URL_RE,
    _VARIATION_SELECTORS,
    _ZERO_WIDTH,
    Sanitizer,
)

import emoji as _emoji

# Attack-keyword lexicon (kept short; precision matters more than recall here).
_ATTACK_KEYWORDS = (
    "ignore previous",
    "ignore the previous",
    "ignore all previous",
    "disregard previous",
    "disregard the above",
    "forget previous",
    "system prompt",
    "developer mode",
    "do anything now",
    "dan mode",
    "jailbreak",
    "bypass",
    "override",
    "act as",
    "you are now",
    "pretend you are",
    "reveal the system",
    "print the system prompt",
    "leak the prompt",
    "exfiltrate",
    "send the data",
    "credentials",
    "api key",
    "password",
    "confidential",
)

FEATURE_NAMES = [
    "len_chars",
    "frac_non_ascii",
    "n_emoji",
    "n_variation_selectors",
    "n_tag_block",
    "n_zero_width",
    "n_bidi_controls",
    "n_combining",
    "n_styled_alphanum",
    "n_urls",
    "n_suspicious_urls",
    "n_attack_keywords",
    "max_word_len",
    "homoglyph_ratio",
    "uppercase_ratio",
]


def extract_features(text: str) -> Dict[str, float]:
    """Return a dict of numeric features for a prompt."""

    if not text:
        return {name: 0.0 for name in FEATURE_NAMES}

    n = len(text)
    non_ascii = sum(1 for ch in text if ord(ch) > 127)
    n_emoji = _emoji.emoji_count(text)
    n_var = len(_VARIATION_SELECTORS.findall(text))
    n_tag = len(_TAG_BLOCK.findall(text))
    n_zw = len(_ZERO_WIDTH.findall(text))
    n_bidi = len(_BIDI_CONTROLS.findall(text))
    n_combine = len(_COMBINING.findall(text))
    n_styled = len(_STYLED_ALPHANUM.findall(text))
    urls = _URL_RE.findall(text)
    n_susp = sum(1 for u in urls if Sanitizer._is_suspicious_url(u))
    n_kw = sum(1 for kw in _ATTACK_KEYWORDS if kw in text.lower())
    words = text.split()
    max_word_len = max((len(w) for w in words), default=0)
    homoglyph_ratio = _homoglyph_ratio(text)
    upper = sum(1 for ch in text if ch.isupper())
    upper_ratio = upper / n if n else 0.0

    return {
        "len_chars": float(n),
        "frac_non_ascii": non_ascii / n,
        "n_emoji": float(n_emoji),
        "n_variation_selectors": float(n_var),
        "n_tag_block": float(n_tag),
        "n_zero_width": float(n_zw),
        "n_bidi_controls": float(n_bidi),
        "n_combining": float(n_combine),
        "n_styled_alphanum": float(n_styled),
        "n_urls": float(len(urls)),
        "n_suspicious_urls": float(n_susp),
        "n_attack_keywords": float(n_kw),
        "max_word_len": float(max_word_len),
        "homoglyph_ratio": homoglyph_ratio,
        "uppercase_ratio": upper_ratio,
    }


def _homoglyph_ratio(text: str) -> float:
    """Fraction of letters that change under NFKC compatibility decomposition.

    Cyrillic 'е' (U+0435) vs Latin 'e' (U+0065), styled math 'A' vs 'A', etc.
    """
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return 0.0
    suspicious = 0
    for ch in letters:
        nfkc = unicodedata.normalize("NFKC", ch)
        if nfkc != ch:
            suspicious += 1
            continue
        # Detect non-Latin/Greek letters mixed in (rough heuristic)
        try:
            name = unicodedata.name(ch, "")
        except ValueError:
            name = ""
        if "CYRILLIC" in name or "GREEK SMALL LETTER" in name:
            # Only count if letter is one of the common Latin look-alikes
            if ch in "аеорсхуАВЕКМНОРСТХΟΑΒΕΗΙΚΜΝΟΡΤΥΧ":
                suspicious += 1
    return suspicious / len(letters)


__all__ = ["extract_features", "FEATURE_NAMES"]
