"""FastAPI middleware service.

Endpoints (FR-09):

    GET  /            — root info
    GET  /health      — liveness check
    POST /detect      — classify only (no LLM call)
    POST /chat        — detect → sanitize → forward to LLM
    GET  /metrics     — aggregate counters
    GET  /audit       — last N detection events
"""

from __future__ import annotations

import json
import os
from collections import Counter, deque
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from prompt_hardening import HardeningPipeline, PromptDetector, Sanitizer
from prompt_hardening.llm_clients import make_client

load_dotenv()

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class DetectRequest(BaseModel):
    text: str = Field(..., description="Raw user prompt to classify")


class ChatRequest(BaseModel):
    text: str
    model: Optional[str] = Field(None, description="Override LLM model name")
    force_forward: bool = Field(
        False,
        description="If true, forward the sanitized prompt even when over threshold (for research / red-team comparison).",
    )


# ---------------------------------------------------------------------------
# App + global state
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Prompt Hardening Classifier API",
    description=(
        "Real-time detection and mitigation of prompt injection attacks. "
        "Includes specialized handling for emoji smuggling and link injection."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

THRESHOLD = float(os.environ.get("BLOCK_THRESHOLD", "0.85"))
LOG_FILE = os.environ.get("LOG_FILE", "logs/detections.jsonl")

pipeline = HardeningPipeline(
    detector=PromptDetector(),
    sanitizer=Sanitizer(),
    llm=make_client(),
    block_threshold=THRESHOLD,
    log_file=LOG_FILE,
)

_metrics = {
    "total_requests": 0,
    "blocked": 0,
    "malicious_predicted": 0,
    "benign_predicted": 0,
    "attack_types": Counter(),
    "latency_sum_ms": 0.0,
}
_recent: deque = deque(maxlen=200)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/")
def root():
    return {
        "service": "Prompt Hardening Classifier",
        "version": app.version,
        "detector_backend": pipeline.detector.backend,
        "llm_provider": pipeline.llm.name,
        "block_threshold": THRESHOLD,
        "endpoints": ["/health", "/detect", "/chat", "/metrics", "/audit"],
    }


@app.get("/health")
def health():
    return {"status": "ok", "backend": pipeline.detector.backend}


@app.post("/detect")
def detect(req: DetectRequest):
    if not req.text:
        raise HTTPException(status_code=400, detail="text must be non-empty")
    det, san = pipeline.detect(req.text)

    _metrics["total_requests"] += 1
    if det.label == 1:
        _metrics["malicious_predicted"] += 1
    else:
        _metrics["benign_predicted"] += 1
    for at in det.attack_types:
        _metrics["attack_types"][at] += 1
    _metrics["latency_sum_ms"] += det.latency_ms

    payload = {
        "detection": det.to_dict(),
        "sanitization": san.to_dict(),
        "would_block": det.score >= THRESHOLD,
        "threshold": THRESHOLD,
    }
    _recent.appendleft({"endpoint": "/detect", **payload})
    return payload


@app.post("/chat")
def chat(req: ChatRequest):
    if not req.text:
        raise HTTPException(status_code=400, detail="text must be non-empty")
    outcome = pipeline.run(req.text, model=req.model, force_forward=req.force_forward)

    _metrics["total_requests"] += 1
    if outcome.detection["label"] == 1:
        _metrics["malicious_predicted"] += 1
    else:
        _metrics["benign_predicted"] += 1
    if outcome.blocked:
        _metrics["blocked"] += 1
    for at in outcome.detection.get("attack_types", []):
        _metrics["attack_types"][at] += 1
    _metrics["latency_sum_ms"] += outcome.detection.get("latency_ms", 0.0)

    body = {
        "request_id": outcome.request_id,
        "blocked": outcome.blocked,
        "detection": outcome.detection,
        "sanitization": outcome.sanitization,
        "forwarded_prompt": outcome.forwarded_prompt,
        "llm_response": outcome.llm_response,
        "error": outcome.error,
        "total_latency_ms": outcome.total_latency_ms,
    }
    _recent.appendleft({"endpoint": "/chat", **body})
    return body


@app.get("/metrics")
def metrics():
    n = max(_metrics["total_requests"], 1)
    return {
        "total_requests": _metrics["total_requests"],
        "blocked": _metrics["blocked"],
        "malicious_predicted": _metrics["malicious_predicted"],
        "benign_predicted": _metrics["benign_predicted"],
        "block_rate": round(_metrics["blocked"] / n, 4),
        "malicious_rate": round(_metrics["malicious_predicted"] / n, 4),
        "avg_detection_latency_ms": round(_metrics["latency_sum_ms"] / n, 2),
        "attack_types_top": _metrics["attack_types"].most_common(10),
        "detector_backend": pipeline.detector.backend,
    }


@app.get("/audit")
def audit(limit: int = 50):
    limit = max(1, min(limit, 200))
    return {"events": list(_recent)[:limit]}


@app.get("/audit/file")
def audit_file(limit: int = 50):
    """Return the most recent N events from the persistent log file."""
    p = Path(LOG_FILE)
    if not p.exists():
        return {"events": []}
    lines = p.read_text(encoding="utf-8", errors="ignore").strip().splitlines()
    events = [json.loads(line) for line in lines[-limit:][::-1] if line.strip()]
    return {"events": events}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api.main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
