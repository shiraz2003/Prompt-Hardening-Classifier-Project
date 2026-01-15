"""Fine-tune DistilBERT for prompt-injection classification.

This script is designed to run on a single GPU (e.g. Google Colab T4)
or a strong CPU. With the provided dataset it converges in 2-3 epochs.

Run:
  python -m training.train_distilbert \
      --train data/processed/train.csv \
      --val   data/processed/val.csv \
      --output models/distilbert-prompt-hardening
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)


def _load(path: Path) -> Dataset:
    df = pd.read_csv(path)
    df = df[["text", "label"]].dropna()
    df["label"] = df["label"].astype(int)
    return Dataset.from_pandas(df, preserve_index=False)


def _metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "precision": precision_score(labels, preds, zero_division=0),
        "recall": recall_score(labels, preds, zero_division=0),
        "f1": f1_score(labels, preds, zero_division=0),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=Path, default=Path("data/processed/train.csv"))
    parser.add_argument("--val", type=Path, default=Path("data/processed/val.csv"))
    parser.add_argument("--model-name", default="distilbert-base-uncased")
    parser.add_argument("--output", type=Path, default=Path("models/distilbert-prompt-hardening"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=5e-5)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_ds = _load(args.train)
    val_ds = _load(args.val)
    print(f"Train: {len(train_ds):,} / Val: {len(val_ds):,}")

    tokenizer = AutoTokenizer.from_pretrained(args.model_name)

    def tok(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=args.max_length,
        )

    train_ds = train_ds.map(tok, batched=True)
    val_ds = val_ds.map(tok, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name,
        num_labels=2,
        id2label={0: "benign", 1: "malicious"},
        label2id={"benign": 0, "malicious": 1},
    )

    args.output.mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=str(args.output / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.lr,
        weight_decay=0.01,
        warmup_ratio=0.1,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=2,
        report_to="none",
        seed=args.seed,
        logging_steps=50,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=_metrics,
    )

    trainer.train()
    print(trainer.evaluate())

    # Save the final model so the API can pick it up
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)
    print(f"[+] Saved fine-tuned model to {args.output}")


if __name__ == "__main__":
    main()
