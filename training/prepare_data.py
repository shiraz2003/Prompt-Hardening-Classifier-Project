"""Build the unified training dataset.

Combines three sources:

1. ``prompt_guard_full_dataset-2.csv`` — provided by the user (≈19.4k rows,
   ~58% malicious / 42% benign). Drop into ``data/`` before running.
2. ``Mindgard/evaded-prompt-injection-and-jailbreak-samples`` from the
   HuggingFace Hub — adds emoji-smuggling and obfuscated samples that
   bypass commercial guardrails (referenced in the proposal).
3. ``data/curated_dataset.csv`` — 150 hand-curated examples produced for
   this project (Deliverable 2).

Outputs:
  data/processed/train.csv
  data/processed/val.csv
  data/processed/test.csv

Usage:
  python -m training.prepare_data \
      --user-csv data/prompt_guard_full_dataset.csv \
      --curated  data/curated_dataset.csv \
      --include-mindgard \
      --out-dir data/processed
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


def _load_user(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "label" not in df.columns or "text" not in df.columns:
        raise ValueError(f"{path} must contain 'text' and 'label' columns")
    df = df[["text", "label"]].copy()
    df["source"] = "user_csv"
    return df


def _load_curated(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df[["text", "label"]].copy()
    df["source"] = "curated"
    return df


def _load_mindgard() -> pd.DataFrame:
    """Pull the Mindgard evaded-prompt-injection dataset from HuggingFace.

    The repo ID is ``Mindgard/evaded-prompt-injection-and-jailbreak-samples``.
    All rows are treated as malicious (label=1) — the dataset is composed of
    successful evasions against commercial guardrails.
    """
    from datasets import load_dataset  # type: ignore

    ds = load_dataset("Mindgard/evaded-prompt-injection-and-jailbreak-samples")
    frames = []
    for split_name, split in ds.items():
        df = split.to_pandas()
        # The schema may evolve. Attempt several known column names.
        text_col = next(
            (c for c in ["text", "prompt", "input", "evaded_prompt", "attack"]
             if c in df.columns),
            None,
        )
        if text_col is None:
            text_col = df.columns[0]
        out = pd.DataFrame({"text": df[text_col].astype(str)})
        out["label"] = 1
        out["source"] = f"mindgard:{split_name}"
        frames.append(out)
    return pd.concat(frames, ignore_index=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user-csv", type=Path, default=Path("data/prompt_guard_full_dataset.csv"))
    parser.add_argument("--curated", type=Path, default=Path("data/curated_dataset.csv"))
    parser.add_argument("--include-mindgard", action="store_true")
    parser.add_argument("--out-dir", type=Path, default=Path("data/processed"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--val-size", type=float, default=0.1)
    parser.add_argument("--test-size", type=float, default=0.1)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    frames = []

    if args.user_csv.exists():
        print(f"[+] Loading {args.user_csv}")
        frames.append(_load_user(args.user_csv))
    else:
        print(f"[!] {args.user_csv} not found — skipping")

    if args.curated.exists():
        print(f"[+] Loading {args.curated}")
        frames.append(_load_curated(args.curated))
    else:
        print(f"[!] {args.curated} not found — skipping")

    if args.include_mindgard:
        try:
            print("[+] Loading Mindgard/evaded-prompt-injection-and-jailbreak-samples")
            frames.append(_load_mindgard())
        except Exception as exc:
            print(f"[!] Could not load Mindgard dataset ({exc}). Skipping.")

    if not frames:
        raise SystemExit("No input data loaded. Provide --user-csv or --curated.")

    df = pd.concat(frames, ignore_index=True)
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df["text"].str.len() > 0]
    df["label"] = df["label"].astype(int).clip(0, 1)
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

    print(f"[+] Total rows after dedup: {len(df):,}")
    print(df["label"].value_counts().rename({0: "benign", 1: "malicious"}))
    print("Source breakdown:")
    print(df["source"].value_counts())

    # Stratified split
    train, temp = train_test_split(
        df,
        test_size=args.val_size + args.test_size,
        stratify=df["label"],
        random_state=args.seed,
    )
    val_frac = args.val_size / (args.val_size + args.test_size)
    val, test = train_test_split(
        temp,
        test_size=1 - val_frac,
        stratify=temp["label"],
        random_state=args.seed,
    )

    train.to_csv(args.out_dir / "train.csv", index=False)
    val.to_csv(args.out_dir / "val.csv", index=False)
    test.to_csv(args.out_dir / "test.csv", index=False)
    print(f"[+] Wrote {len(train):,} train / {len(val):,} val / {len(test):,} test rows to {args.out_dir}")


if __name__ == "__main__":
    main()
