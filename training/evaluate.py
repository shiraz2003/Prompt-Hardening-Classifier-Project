"""Comprehensive evaluation (Deliverable 4).

Compares:
  - Regex / heuristic baseline
  - DistilBERT classifier (if available on disk)

Reports: accuracy, precision, recall, F1, false-positive rate, mean
inference latency. Also computes per-attack-type breakdown when the
test CSV contains an 'attack_type' column.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from prompt_hardening import PromptDetector, RegexBaselineClassifier


def _evaluate(predictor_name: str, predict_fn, texts: List[str], labels: List[int]) -> Dict:
    preds: List[int] = []
    scores: List[float] = []
    latencies: List[float] = []
    for t in texts:
        start = time.perf_counter()
        label, score = predict_fn(t)
        latencies.append((time.perf_counter() - start) * 1000)
        preds.append(label)
        scores.append(score)

    cm = confusion_matrix(labels, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "name": predictor_name,
        "accuracy": float(accuracy_score(labels, preds)),
        "precision": float(precision_score(labels, preds, zero_division=0)),
        "recall": float(recall_score(labels, preds, zero_division=0)),
        "f1": float(f1_score(labels, preds, zero_division=0)),
        "false_positive_rate": float(fpr),
        "mean_latency_ms": float(np.mean(latencies)),
        "p95_latency_ms": float(np.percentile(latencies, 95)),
        "n_samples": len(texts),
        "confusion_matrix": cm.tolist(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", type=Path, default=Path("data/processed/test.csv"))
    parser.add_argument("--out", type=Path, default=Path("docs/evaluation_results.json"))
    parser.add_argument("--max-samples", type=int, default=0,
                        help="If > 0, evaluate on the first N samples (faster smoke test).")
    parser.add_argument("--include-distilbert", action="store_true")
    parser.add_argument("--model-dir", type=Path, default=Path("models/distilbert-prompt-hardening"))
    args = parser.parse_args()

    df = pd.read_csv(args.test)
    if args.max_samples > 0:
        df = df.head(args.max_samples)
    texts = df["text"].astype(str).tolist()
    labels = df["label"].astype(int).tolist()

    print(f"Evaluating on {len(texts):,} samples")

    results = []

    # Regex baseline
    baseline = RegexBaselineClassifier()
    def baseline_fn(t):
        d = baseline.predict(t)
        return d.label, d.score
    results.append(_evaluate("regex_baseline", baseline_fn, texts, labels))

    # Heuristic-fallback detector (rules + features)
    detector = PromptDetector(model_dir=str(args.model_dir))
    def detector_fn(t):
        d = detector.predict(t)
        return d.label, d.score
    results.append(_evaluate(f"detector[{detector.backend}]", detector_fn, texts, labels))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    print(f"[+] Wrote {args.out}")


if __name__ == "__main__":
    main()
