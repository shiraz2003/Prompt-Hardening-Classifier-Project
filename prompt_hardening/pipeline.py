"""End-to-end hardening pipeline: detect → sanitize → forward."""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .detector import DetectionResult, PromptDetector
from .llm_clients import LLMClient, make_client
from .sanitizer import SanitizationResult, Sanitizer


@dataclass
class PipelineOutcome:
    request_id: str
    timestamp: float
    detection: dict
    sanitization: dict
    blocked: bool
    forwarded_prompt: Optional[str]
    llm_response: Optional[str]
    total_latency_ms: float
    error: Optional[str] = None


class HardeningPipeline:
    """Orchestrates detection, sanitization and downstream LLM forwarding."""

    def __init__(
        self,
        detector: Optional[PromptDetector] = None,
        sanitizer: Optional[Sanitizer] = None,
        llm: Optional[LLMClient] = None,
        block_threshold: float = 0.85,
        log_file: Optional[str] = None,
    ) -> None:
        self.detector = detector or PromptDetector()
        self.sanitizer = sanitizer or Sanitizer()
        self.llm = llm or make_client()
        self.block_threshold = block_threshold
        self.log_file = log_file or os.environ.get("LOG_FILE", "logs/detections.jsonl")
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def detect(self, text: str) -> tuple[DetectionResult, SanitizationResult]:
        det = self.detector.predict(text)
        san = self.sanitizer.sanitize(text)
        return det, san

    def run(
        self,
        text: str,
        model: Optional[str] = None,
        force_forward: bool = False,
    ) -> PipelineOutcome:
        start = time.perf_counter()
        request_id = uuid.uuid4().hex[:12]
        timestamp = time.time()

        det, san = self.detect(text)
        blocked = (not force_forward) and det.score >= self.block_threshold
        forwarded_prompt = None
        llm_response = None
        error = None

        if not blocked:
            # Forward the *sanitized* prompt, never the raw one
            forwarded_prompt = san.sanitized
            try:
                llm_response = self.llm.generate(forwarded_prompt, model=model)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"

        outcome = PipelineOutcome(
            request_id=request_id,
            timestamp=timestamp,
            detection=det.to_dict(),
            sanitization=san.to_dict(),
            blocked=blocked,
            forwarded_prompt=forwarded_prompt,
            llm_response=llm_response,
            total_latency_ms=round((time.perf_counter() - start) * 1000.0, 2),
            error=error,
        )
        self._log(outcome)
        return outcome

    # ------------------------------------------------------------------
    def _log(self, outcome: PipelineOutcome) -> None:
        try:
            with open(self.log_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(outcome), ensure_ascii=False) + "\n")
        except Exception as exc:  # pragma: no cover
            print(f"[pipeline] log write failed: {exc}")


__all__ = ["HardeningPipeline", "PipelineOutcome"]
