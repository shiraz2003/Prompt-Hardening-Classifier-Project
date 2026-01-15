"""Regex / heuristic baseline classifier.

Used both as a published baseline (Deliverable 4 — comparison vs
classifier) and as a fallback when no fine-tuned model is available.
"""

from __future__ import annotations

from dataclasses import dataclass

from .unicode_features import extract_features


@dataclass
class BaselineDecision:
    label: int  # 0 = benign, 1 = malicious
    score: float  # in [0, 1]
    rationale: list


class RegexBaselineClassifier:
    """Lightweight rule-based scorer.

    Each suspicious feature contributes weight to a malicious score, then
    score is squashed to [0, 1] with a logistic transform.
    """

    # Weights tuned by hand on a small dev set; documented in the report.
    WEIGHTS = {
        "n_tag_block": 1.5,
        "n_variation_selectors": 0.5,
        "n_zero_width": 0.7,
        "n_bidi_controls": 1.5,
        "n_styled_alphanum": 0.05,
        "homoglyph_ratio": 4.0,
        "n_combining": 0.05,
        "n_suspicious_urls": 1.5,
        "n_attack_keywords": 1.2,
        "frac_non_ascii": 2.0,
    }

    BIAS = -1.5

    def predict(self, text: str) -> BaselineDecision:
        feats = extract_features(text)
        score = self.BIAS
        rationale = []
        for k, w in self.WEIGHTS.items():
            v = feats.get(k, 0.0)
            contribution = v * w
            score += contribution
            if contribution > 0.5:
                rationale.append(f"{k}={v:g} (+{contribution:.2f})")
        prob = 1.0 / (1.0 + pow(2.71828, -score))
        return BaselineDecision(
            label=1 if prob >= 0.5 else 0,
            score=float(prob),
            rationale=rationale,
        )

    def predict_batch(self, texts):
        return [self.predict(t) for t in texts]


__all__ = ["RegexBaselineClassifier", "BaselineDecision"]
