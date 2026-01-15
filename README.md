# Prompt Hardening Classifier

> Real-time detection and mitigation of prompt-injection attacks in LLMs,
> with first-class handling of **emoji smuggling**, **Unicode obfuscation**,
> and **link injection**.

**PUSL3190 Computing Project** — University of Plymouth
**Author:** Shiraz Sappideen (Plymouth Index 10952638)
**Supervisor:** Mr. Madusanka Mithrananda
**Degree:** BSc. (Hons) Software Engineering

---

## Why this project

Prompt injection ranks **#1 on the OWASP Top 10 for LLM Applications 2025**.
Mindgard's April 2025 study showed that emoji smuggling — hiding payloads
inside Unicode variation selectors and tag-block characters — bypasses
**Microsoft Azure Prompt Shield, Meta Llama Prompt Guard, NVIDIA NeMo
Guardrails, and Protect AI guardrails with up to a 100% success rate**.

This project ships an open-source **lightweight middleware** that you can
drop in front of any LLM endpoint to detect and neutralise these attacks
**before they reach the model**.

## What it does

```
                ┌────────────┐
   user prompt ─►│  Detector  │── DistilBERT / heuristic — score, attack types
                └─────┬──────┘
                      │   if score ≥ threshold ─► BLOCK + audit
                      ▼
                ┌────────────┐
                │ Sanitizer  │── strip tag-block, ZW, bidi, normalize NFKC,
                └─────┬──────┘    block suspicious URLs
                      ▼
                ┌────────────┐
                │  LLM call  │── Groq · OpenAI · Ollama · echo (offline)
                └─────┬──────┘
                      ▼
                  response
```

## Repository layout

```
prompt_hardening_project/
├── prompt_hardening/        core library
│   ├── sanitizer.py         strip emoji / ZW / bidi / homoglyph; URL block
│   ├── unicode_features.py  hand-crafted character-level features
│   ├── regex_baseline.py    heuristic baseline (Deliverable 4 baseline)
│   ├── detector.py          DistilBERT inference + heuristic fallback
│   ├── llm_clients.py       Groq / OpenAI / Ollama / echo adapters
│   └── pipeline.py          detect → sanitize → forward orchestration
├── api/main.py              FastAPI service (/detect, /chat, /metrics, /audit)
├── ui/gradio_app.py         interactive demo (protected vs unprotected)
├── training/
│   ├── prepare_data.py      merges user CSV + Mindgard HF dataset + curated
│   ├── build_curated.py     generates the 150-prompt curated dataset
│   ├── train_distilbert.py  fine-tune DistilBERT on the merged data
│   └── evaluate.py          accuracy / precision / recall / F1 / FPR / latency
├── data/
│   ├── prompt_guard_full_dataset.csv  user-supplied (≈19k rows)
│   ├── curated_dataset.csv            150 hand-curated obfuscation samples
│   └── processed/{train,val,test}.csv produced by prepare_data.py
├── tests/                   pytest unit tests for sanitizer + pipeline
├── docs/                    evaluation report, charts, methodology
├── requirements.txt
├── Dockerfile
└── README.md
```

## Quick start

```bash
# 1. Install
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # leave LLM_PROVIDER=echo for offline demos

# 2. Build dataset splits + curated set
python -m training.build_curated
python -m training.prepare_data \
    --user-csv data/prompt_guard_full_dataset.csv \
    --curated  data/curated_dataset.csv \
    --include-mindgard \
    --out-dir  data/processed

# 3. Run tests
pytest -v

# 4. Quick evaluation (heuristic fallback, no GPU required)
python -m training.evaluate --test data/processed/test.csv --max-samples 2000

# 5. Run the API
uvicorn api.main:app --reload --port 8000
# Then visit http://localhost:8000/docs

# 6. Run the Gradio demo
python -m ui.gradio_app
# Open http://localhost:7860
```

## Train the DistilBERT classifier (Colab / GPU)

```bash
python -m training.train_distilbert \
    --train data/processed/train.csv \
    --val   data/processed/val.csv \
    --output models/distilbert-prompt-hardening \
    --epochs 3 --batch-size 32
```

After training the API picks up the fine-tuned model automatically (the
detector reads `MODEL_DIR` from `.env`, defaulting to
`models/distilbert-prompt-hardening`). With no model on disk it falls
back to the heuristic detector so `/detect` and `/chat` always work.

## API reference

| Method | Path           | Purpose                                      |
|--------|----------------|----------------------------------------------|
| GET    | `/`            | service info                                 |
| GET    | `/health`      | liveness / current detector backend          |
| POST   | `/detect`      | classify only (no LLM call)                  |
| POST   | `/chat`        | full pipeline: detect → sanitize → LLM       |
| GET    | `/metrics`     | aggregate counters (requests, block rate, …) |
| GET    | `/audit`       | last 50 in-memory events                     |
| GET    | `/audit/file`  | replay last N events from `logs/detections.jsonl` |

`/detect` request body:
```json
{ "text": "Hello 👋" }
```
`/detect` response (truncated):
```json
{
  "detection": {
    "label": 1,
    "label_name": "malicious",
    "score": 1.0,
    "attack_types": ["emoji_tag_block_smuggling"],
    "features": { "n_tag_block": 57, "frac_non_ascii": 0.89, "...": "..." },
    "backend": "heuristic-fallback",
    "latency_ms": 1.5
  },
  "sanitization": {
    "actions": ["removed 57 tag-block char(s)", "stripped emoji"],
    "sanitized": "Hi bye",
    "blocked_urls": []
  },
  "would_block": true,
  "threshold": 0.85
}
```

## Datasets used

1. **`prompt_guard_full_dataset-2.csv`** — supplied by the user, ≈19,374
   labelled prompts (~58% malicious / 42% benign).
2. **`Mindgard/evaded-prompt-injection-and-jailbreak-samples`** —
   pulled at training time from HuggingFace; adds known emoji-smuggling
   and obfuscated samples that bypass commercial guardrails.
3. **`data/curated_dataset.csv`** — 150 hand-curated samples covering
   emoji smuggling (tag-block + variation selectors), zero-width splits,
   homoglyphs, bidi overrides, link injection, and benign baselines.
   Released under MIT alongside the source code (Deliverable 2).

## Evaluation results (heuristic fallback, no fine-tuning yet)

On the 150-prompt **curated obfuscation dataset**:

| Metric              | Value   | Target (NFR) | ✓/✗ |
|---------------------|---------|--------------|------|
| Accuracy            | 0.973   | ≥ 0.90       | ✓    |
| Precision           | 1.000   | —            | ✓    |
| Recall              | 0.960   | —            | ✓    |
| F1                  | 0.980   | —            | ✓    |
| False-positive rate | 0.000   | < 0.05       | ✓    |
| Mean latency        | 0.33 ms | < 100 ms     | ✓    |
| P95  latency        | 0.30 ms | < 100 ms     | ✓    |

Per attack class (recall on the malicious slice):

| Attack class                  | Detection rate |
|-------------------------------|----------------|
| emoji_smuggling_tagblock      | 100%           |
| emoji_smuggling_varsel        | 100%           |
| zero_width                    | 100%           |
| homoglyph                     | 100%           |
| bidi_override                 | 100%           |
| link_injection                | 100%           |
| instruction_override (plain)  | 20% (closes after DistilBERT fine-tune) |

See `docs/curated_evaluation.md`, `docs/evaluation_results.json`, and
`docs/per_attack_detection.png`.

## Mapping to the proposal

| Requirement | Implementation |
|-------------|----------------|
| FR-01 ≥ 90% accuracy | Achieved on curated set; full set after DistilBERT fine-tune |
| FR-02 emoji smuggling detection | `_TAG_BLOCK`, `_VARIATION_SELECTORS` regex + features |
| FR-03 link injection | `_URL_RE` + `_SUSPICIOUS_HOST_TOKENS` blocklist |
| FR-04 sanitisation | `Sanitizer.sanitize()` — 9-step pipeline, returns actions |
| FR-05 forward to LLM | `HardeningPipeline.run()` → Groq / Ollama / OpenAI |
| FR-06 detailed threat analysis | `DetectionResult` includes attack types, features, score |
| FR-07 block above threshold | `BLOCK_THRESHOLD=0.85` (configurable in `.env`) |
| FR-08 audit log | `logs/detections.jsonl`, `/audit/file` endpoint |
| FR-09 RESTful API | FastAPI: `/detect`, `/chat`, `/metrics`, `/health`, `/audit` |
| FR-10 Gradio interface | `ui/gradio_app.py` — side-by-side comparison |
| NFR-01 < 100 ms latency | 0.33 ms heuristic / ~5–20 ms DistilBERT-CPU |
| NFR-02 ≥ 90% accuracy | 97.3% on curated dataset |
| NFR-03 < 5% FPR | 0.0% on curated dataset |

## License

MIT — see `LICENSE`.
