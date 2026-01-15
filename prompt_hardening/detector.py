"""Prompt injection detector.

Wraps a fine-tuned DistilBERT classifier and falls back to a hybrid
heuristic + feature scorer when no trained model is on disk.

When both the model AND the heuristic are available, this detector
runs them in parallel and takes the higher malicious-probability
score. This catches obfuscation attacks (emoji smuggling, zero-width,
homoglyph) the model may miss while keeping the model's strength on
plain-text jailbreaks.

Implements FR-01, FR-02, FR-03, FR-06.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .regex_baseline import RegexBaselineClassifier
from .unicode_features import extract_features


@dataclass
class DetectionResult:
    label: int  # 0 = benign, 1 = malicious
    label_name: str
    score: float  # malicious probability in [0, 1]
    attack_types: List[str] = field(default_factory=list)
    features: dict = field(default_factory=dict)
    backend: str = "fallback"
    latency_ms: float = 0.0
    rationale: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "label_name": self.label_name,
            "score": round(self.score, 4),
            "attack_types": self.attack_types,
            "features": {k: round(v, 4) for k, v in self.features.items()},
            "backend": self.backend,
            "latency_ms": round(self.latency_ms, 2),
            "rationale": self.rationale,
        }


# Token names that indicate the "malicious" class in id2label maps
_MALICIOUS_LABEL_TOKENS = (
    "malicious",
    "injection",
    "attack",
    "jailbreak",
    "unsafe",
    "harmful",
    "label_1",
)


class PromptDetector:
    """Inference wrapper.

    Set ``model_dir`` to a HuggingFace-format checkpoint produced by
    ``training/train_distilbert.py``. If the directory is missing or
    transformers/torch are unavailable, the detector seamlessly falls
    back to a hybrid baseline (regex + feature scorer) so the API always
    returns a useful answer.
    """

    def __init__(
        self,
        model_dir: Optional[str] = None,
        device: Optional[str] = None,
        max_length: int = 256,
    ) -> None:
        self.model_dir = model_dir or os.environ.get(
            "MODEL_DIR", "models/final_prompt_classifier_v3"
        )
        self.max_length = max_length
        self._baseline = RegexBaselineClassifier()
        self._tokenizer = None
        self._model = None
        self._device = device
        self._malicious_idx = 1  # default: class 1 = malicious
        self._backend = "heuristic-fallback"
        self._try_load()

    # ------------------------------------------------------------------
    def _try_load(self) -> None:
        path = Path(self.model_dir)
        if not path.exists():
            return
        try:
            import torch
            from transformers import (  # type: ignore
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            self._tokenizer = AutoTokenizer.from_pretrained(str(path))
            self._model = AutoModelForSequenceClassification.from_pretrained(str(path))
            self._device = self._device or ("cuda" if torch.cuda.is_available() else "cpu")
            self._model.to(self._device)
            self._model.eval()

            # Resolve which output index corresponds to the malicious class.
            # If the model's id2label says one of the tokens we recognise as
            # "malicious", use that index. Otherwise default to 1.
            id2label = getattr(self._model.config, "id2label", None) or {}
            resolved_idx = None
            for idx, name in id2label.items():
                if str(name).strip().lower() in _MALICIOUS_LABEL_TOKENS:
                    try:
                        resolved_idx = int(idx)
                        break
                    except (TypeError, ValueError):
                        continue
            self._malicious_idx = resolved_idx if resolved_idx is not None else 1

            self._backend = (
                f"distilbert ({self._device}, malicious_idx={self._malicious_idx})"
            )
            print(f"[detector] Loaded {path} → {self._backend}")
        except Exception as exc:  # pragma: no cover - depends on env
            print(f"[detector] Could not load model from {path}: {exc}. Using fallback.")
            self._tokenizer = None
            self._model = None

    # ------------------------------------------------------------------
    @property
    def backend(self) -> str:
        return self._backend

    def predict(self, text: str) -> DetectionResult:
        start = time.perf_counter()
        feats = extract_features(text)
        attack_types = _classify_attack_types(feats)

        # ── ALWAYS run the heuristic — it's free and catches obfuscation ──
        baseline_decision = self._baseline.predict(text)
        heuristic_score = baseline_decision.score
        if feats["n_tag_block"] > 0 or feats["n_zero_width"] > 0:
            heuristic_score = max(heuristic_score, 0.95)
        if feats["homoglyph_ratio"] > 0.3:
            heuristic_score = max(heuristic_score, 0.92)
        if feats["n_bidi_controls"] > 0:
            heuristic_score = max(heuristic_score, 0.95)
        if feats["n_suspicious_urls"] > 0:
            heuristic_score = max(heuristic_score, 0.90)

        # ── Run DistilBERT if available, then ensemble ──
        if self._model is not None and self._tokenizer is not None:
            model_score = self._predict_transformer(text)
            # Hybrid: take the higher malicious-probability of the two engines.
            # This means the model can rescue plain-text jailbreaks the
            # heuristic misses, AND the heuristic rescues obfuscation the
            # model misses. Either one alone is sufficient to flag.
            score = max(model_score, heuristic_score)
            backend = self._backend
            rationale = [
                f"DistilBERT={model_score:.3f}",
                f"heuristic={heuristic_score:.3f}",
                f"final=max → {score:.3f}",
            ]
            if baseline_decision.rationale:
                rationale.append("heuristic_signals=" + "; ".join(baseline_decision.rationale))
        else:
            score = heuristic_score
            backend = self._backend
            rationale = baseline_decision.rationale

        label = 1 if score >= 0.5 else 0
        latency_ms = (time.perf_counter() - start) * 1000.0

        return DetectionResult(
            label=label,
            label_name="malicious" if label == 1 else "benign",
            score=float(score),
            attack_types=attack_types,
            features=feats,
            backend=backend,
            latency_ms=latency_ms,
            rationale=rationale,
        )

    def predict_batch(self, texts: List[str]) -> List[DetectionResult]:
        return [self.predict(t) for t in texts]

    # ------------------------------------------------------------------
    def _predict_transformer(self, text: str) -> float:
        import torch  # local import keeps the dep optional

        with torch.no_grad():
            enc = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_length,
                padding=False,
            ).to(self._device)
            logits = self._model(**enc).logits[0]
            probs = torch.softmax(logits, dim=-1).cpu().tolist()

        # Use the malicious-class index resolved at load time.
        if 0 <= self._malicious_idx < len(probs):
            return float(probs[self._malicious_idx])
        return float(probs[-1])


def _classify_attack_types(feats: dict) -> List[str]:
    types: List[str] = []
    if feats["n_tag_block"] > 0:
        types.append("emoji_tag_block_smuggling")
    if feats["n_variation_selectors"] > 2:
        types.append("variation_selector_smuggling")
    if feats["n_zero_width"] > 0:
        types.append("zero_width_obfuscation")
    if feats["n_bidi_controls"] > 0:
        types.append("bidi_override")
    if feats["homoglyph_ratio"] > 0.15 or feats["n_styled_alphanum"] > 5:
        types.append("homoglyph_obfuscation")
    if feats["n_suspicious_urls"] > 0:
        types.append("link_injection")
    if feats["n_attack_keywords"] >= 2:
        types.append("instruction_override")
    if not types and feats["n_emoji"] > 0 and feats["n_variation_selectors"] > 0:
        types.append("possible_emoji_smuggling")
    return types


__all__ = ["PromptDetector", "DetectionResult"]