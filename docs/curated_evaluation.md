# Curated-Dataset Evaluation (Heuristic Fallback)

These results were obtained by running the rule + feature heuristic
detector (no DistilBERT fine-tuning yet) over the 150-prompt curated
dataset (`data/curated_dataset.csv`).

| Metric                | Value     | Target (NFR) | Pass? |
|-----------------------|-----------|--------------|-------|
| Accuracy              | 0.973     | ≥ 0.90       | ✅    |
| Precision             | 1.000     | —            | ✅    |
| Recall                | 0.960     | —            | ✅    |
| F1                    | 0.980     | —            | ✅    |
| False-positive rate   | 0.000     | < 0.05       | ✅    |
| Mean detection latency| 0.33 ms   | < 100 ms     | ✅    |
| P95 detection latency | 0.30 ms   | < 100 ms     | ✅    |

## Per-attack-type detection (recall on the malicious slice)

| Attack type                   | Caught | Total | Detection rate |
|-------------------------------|--------|-------|----------------|
| benign                        | 50     | 50    | 100%           |
| bidi_override                 | 10     | 10    | 100%           |
| emoji_smuggling_tagblock      | 20     | 20    | 100%           |
| emoji_smuggling_varsel        | 15     | 15    | 100%           |
| homoglyph                     | 20     | 20    | 100%           |
| zero_width                    | 15     | 15    | 100%           |
| link_injection                | 15     | 15    | 100%           |
| instruction_override (plain)  | 1      | 5     | 20%            |

**Reading the table:** the character-level heuristics already catch
**100% of emoji smuggling, Unicode obfuscation, and link injection** with
zero false positives — these are precisely the attack classes that bypass
commercial guardrails today (the proposal cites a 100% bypass rate
against Llama Prompt Guard and NeMo Guardrails on emoji smuggling).

The remaining 20% recall on plain-text `instruction_override` is what
the DistilBERT fine-tuning step is designed to close. After running
`training/train_distilbert.py` on the merged 19k-row dataset, recall on
these textual jailbreaks is expected to exceed 0.95 based on similar
work in the literature.
