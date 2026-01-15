"""Real-time sanitization engine.

Removes or normalizes detected threats: strips emoji and zero-width
characters, normalizes Unicode (NFKC), neutralizes hidden tag block
characters used in emoji smuggling, blocks suspicious URLs.

This implements FR-04 from the proposal.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Tuple
from urllib.parse import urlparse

import emoji as _emoji

# ---------------------------------------------------------------------------
# Unicode ranges of interest
# ---------------------------------------------------------------------------

# Variation selectors (incl. VS1-16 and VS17-256 supplemental)
_VARIATION_SELECTORS = re.compile(r"[\uFE00-\uFE0F\U000E0100-\U000E01EF]")

# Tag characters (E0000-E007F) — abused by the "tag block smuggling" attack
_TAG_BLOCK = re.compile(r"[\U000E0000-\U000E007F]")

# Zero-width and invisible characters (ZWSP, ZWNJ, ZWJ, BOM, word joiner, ...)
_ZERO_WIDTH = re.compile(
    r"[\u200B\u200C\u200D\u2060\u2061\u2062\u2063\u2064\uFEFF\u180E\u00AD]"
)

# Bidirectional text controls (used in homoglyph / Trojan-source attacks)
_BIDI_CONTROLS = re.compile(
    r"[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]"
)

# Combining marks (used to stack zalgo / underline-style obfuscation)
_COMBINING = re.compile(r"[\u0300-\u036F\u0489\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF]")

# Mathematical/styled alphanumerics often used for homoglyph obfuscation
_STYLED_ALPHANUM = re.compile(r"[\U0001D400-\U0001D7FF]")

# Suspicious URL patterns
_URL_RE = re.compile(
    r"(?ix)\b(?:https?://|www\.)\S+|"  # http(s) and www.
    r"\b[a-z0-9\-]+\.(?:com|net|org|io|co|info|xyz|ru|cn|tk|ml|ga|cf|gq|biz|top)\b\S*"
)

# Known suspicious / data-exfil indicators inside URLs
_SUSPICIOUS_HOST_TOKENS = (
    "evil",
    "attacker",
    "exfil",
    "malicious",
    "phish",
    "pastebin.com",
    "bit.ly",
    "tinyurl.com",
    "discord.gift",
    "free-credits",
    "login-",
    "account-verify",
    "ngrok.io",
    "requestcatcher.com",
    "webhook.site",
    "burpcollaborator.net",
)


@dataclass
class SanitizationResult:
    """Outcome of running the sanitizer over a prompt."""

    original: str
    sanitized: str
    actions: List[str] = field(default_factory=list)
    removed_chars: int = 0
    blocked_urls: List[str] = field(default_factory=list)
    kept_urls: List[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.original != self.sanitized

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "sanitized": self.sanitized,
            "actions": self.actions,
            "removed_chars": self.removed_chars,
            "blocked_urls": self.blocked_urls,
            "kept_urls": self.kept_urls,
            "changed": self.changed,
        }


class Sanitizer:
    """Cleans suspicious unicode and URL artifacts from prompts."""

    def __init__(
        self,
        strip_emoji: bool = True,
        block_suspicious_urls: bool = True,
        normalize_form: str = "NFKC",
    ) -> None:
        self.strip_emoji = strip_emoji
        self.block_suspicious_urls = block_suspicious_urls
        self.normalize_form = normalize_form

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def sanitize(self, text: str) -> SanitizationResult:
        original = text
        actions: List[str] = []
        blocked: List[str] = []
        kept: List[str] = []

        # 1. Remove tag-block smuggling characters (E0000-E007F)
        new, n = _sub_count(_TAG_BLOCK, "", text)
        if n:
            actions.append(f"removed {n} tag-block char(s)")
            text = new

        # 2. Remove variation selectors (often used to attach hidden payload)
        new, n = _sub_count(_VARIATION_SELECTORS, "", text)
        if n:
            actions.append(f"removed {n} variation-selector(s)")
            text = new

        # 3. Remove zero-width / invisible characters
        new, n = _sub_count(_ZERO_WIDTH, "", text)
        if n:
            actions.append(f"removed {n} zero-width char(s)")
            text = new

        # 4. Remove bidirectional override characters (Trojan-Source)
        new, n = _sub_count(_BIDI_CONTROLS, "", text)
        if n:
            actions.append(f"removed {n} bidi-control char(s)")
            text = new

        # 5. Strip combining marks used for zalgo / underline obfuscation
        new, n = _sub_count(_COMBINING, "", text)
        if n:
            actions.append(f"removed {n} combining mark(s)")
            text = new

        # 6. Unicode-normalize (NFKC turns styled letters into ASCII counterparts)
        normalized = unicodedata.normalize(self.normalize_form, text)
        if normalized != text:
            actions.append(f"normalized unicode ({self.normalize_form})")
            text = normalized

        # 7. Strip emoji (optional)
        if self.strip_emoji:
            cleaned = _emoji.replace_emoji(text, replace="")
            if cleaned != text:
                actions.append("stripped emoji")
                text = cleaned

        # 8. Sift URLs and block suspicious ones
        if self.block_suspicious_urls:
            text, blocked, kept, url_actions = self._handle_urls(text)
            actions.extend(url_actions)

        # 9. Collapse leftover excessive whitespace introduced by removals
        collapsed = re.sub(r"\s{3,}", "  ", text).strip()
        if collapsed != text:
            text = collapsed

        return SanitizationResult(
            original=original,
            sanitized=text,
            actions=actions,
            removed_chars=len(original) - len(text),
            blocked_urls=blocked,
            kept_urls=kept,
        )

    # ------------------------------------------------------------------
    # URL handling
    # ------------------------------------------------------------------
    def _handle_urls(
        self, text: str
    ) -> Tuple[str, List[str], List[str], List[str]]:
        blocked: List[str] = []
        kept: List[str] = []
        actions: List[str] = []

        def _replace(match: re.Match) -> str:
            url = match.group(0)
            if self._is_suspicious_url(url):
                blocked.append(url)
                return "[BLOCKED_URL]"
            kept.append(url)
            return url

        new_text = _URL_RE.sub(_replace, text)
        if blocked:
            actions.append(f"blocked {len(blocked)} suspicious URL(s)")
        return new_text, blocked, kept, actions

    @staticmethod
    def _is_suspicious_url(url: str) -> bool:
        url_lower = url.lower()
        if any(tok in url_lower for tok in _SUSPICIOUS_HOST_TOKENS):
            return True
        # IP address as host
        try:
            host = urlparse(url if url.startswith("http") else "http://" + url).hostname or ""
        except Exception:
            host = ""
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""):
            return True
        # Punycode hosts (often used for homoglyph phishing)
        if host.startswith("xn--"):
            return True
        # Hosts with @ user-info (URL splitting attacks)
        if "@" in url and "://" in url:
            return True
        # Excessively long query strings often hide payloads
        if len(url) > 200:
            return True
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _sub_count(pattern: re.Pattern, repl: str, text: str) -> Tuple[str, int]:
    new_text, n = pattern.subn(repl, text)
    return new_text, n


__all__ = ["Sanitizer", "SanitizationResult"]
