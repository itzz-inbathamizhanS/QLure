"""Logistic regression written out in plain Python, so every score can be explained.

No library, no randomness: the same labelled sessions always give the same model file. The
model learns from sessions an investigator labelled malicious or benign, and its score is
shown beside the rule verdict. It never changes a verdict or a score.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qlure.correlate.model import Session
from qlure.ml.features import FEATURES, extract

MIN_SESSIONS = 10
MIN_PER_CLASS = 3
DEFAULT_PATH = Path("data/model.json")
VERSION = 1


class NotEnoughData(Exception):
    pass


def model_path() -> Path:
    return Path(os.environ.get("QLURE_MODEL", str(DEFAULT_PATH)))


def _sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-max(-30.0, min(30.0, z))))


@dataclass
class Model:
    mean: list[float]
    scale: list[float]
    weights: list[float]
    bias: float
    meta: dict[str, Any]

    def _z(self, vector: list[float]) -> list[float]:
        return [(v - m) / s for v, m, s in zip(vector, self.mean, self.scale, strict=True)]

    def probability(self, session: Session) -> float:
        z = self._z(extract(session))
        return _sigmoid(self.bias + sum(w * x for w, x in zip(self.weights, z, strict=True)))

    def explain(self, session: Session, top: int = 3) -> str:
        vector = extract(session)
        z = self._z(vector)
        parts = sorted(
            (
                (w * x, name, raw)
                for w, x, name, raw in zip(self.weights, z, FEATURES, vector, strict=True)
            ),
            key=lambda p: -abs(p[0]),
        )[:top]
        pieces = [
            f"{name.replace('_', ' ')} = {raw:.2f} pushes toward "
            f"{'malicious' if push > 0 else 'benign'}"
            for push, name, raw in parts
            if abs(push) > 0.05
        ]
        p = self.probability(session)
        lead = (
            f"Model: {p:.0%} chance this behaviour matches the malicious sessions it learned from."
        )
        return lead + (" Biggest factors: " + "; ".join(pieces) + "." if pieces else "")

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": VERSION,
                "features": FEATURES,
                "mean": self.mean,
                "scale": self.scale,
                "weights": self.weights,
                "bias": self.bias,
                "meta": self.meta,
            },
            indent=2,
        )


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _fits(data: Any) -> bool:
    """True only for a file this code can score with: right version, features and shapes."""
    if not isinstance(data, dict) or data.get("version") != VERSION:
        return False
    if data.get("features") != FEATURES or not isinstance(data.get("meta"), dict):
        return False
    size = len(FEATURES)
    for key in ("mean", "scale", "weights"):
        values = data.get(key)
        if not isinstance(values, list) or len(values) != size:
            return False
        if not all(_is_number(v) for v in values):
            return False
    if not all(v > 0 for v in data["scale"]):  # a zero scale would divide by zero
        return False
    return _is_number(data.get("bias"))


def load(path: Path | None = None) -> Model | None:
    """The trained model, or None when none exists or it does not fit this code."""
    try:
        data = json.loads((path or model_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not _fits(data):
        return None
    return Model(data["mean"], data["scale"], data["weights"], data["bias"], data["meta"])


def train(
    sessions: list[Session],
    labels: list[int],
    run_ids: list[str],
    *,
    l2: float = 0.1,
    rate: float = 0.3,
    steps: int = 800,
) -> Model:
    """Fit on labelled sessions (1 = malicious). Refuses data too small or one-sided."""
    positives = sum(labels)
    negatives = len(labels) - positives
    if len(labels) < MIN_SESSIONS or min(positives, negatives) < MIN_PER_CLASS:
        raise NotEnoughData(
            f"need at least {MIN_SESSIONS} labelled sessions with {MIN_PER_CLASS} of each kind; "
            f"got {positives} malicious and {negatives} benign"
        )
    rows = [extract(s) for s in sessions]
    n, k = len(rows), len(FEATURES)
    mean = [sum(r[j] for r in rows) / n for j in range(k)]
    scale = [math.sqrt(sum((r[j] - mean[j]) ** 2 for r in rows) / n) or 1.0 for j in range(k)]
    z = [[(r[j] - mean[j]) / scale[j] for j in range(k)] for r in rows]
    # Balanced class weights, so a few attacks among many benign visits still count.
    weight = {1: n / (2 * positives), 0: n / (2 * negatives)}
    w, b = [0.0] * k, 0.0
    for _ in range(steps):
        grad, grad_b = [0.0] * k, 0.0
        for x, y in zip(z, labels, strict=True):
            err = (_sigmoid(b + sum(wi * xi for wi, xi in zip(w, x, strict=True))) - y) * weight[y]
            grad_b += err
            for j in range(k):
                grad[j] += err * x[j]
        w = [wi - rate * (g / n + l2 * wi) for wi, g in zip(w, grad, strict=True)]
        b -= rate * grad_b / n
    meta = {
        "trained_at": datetime.now(UTC).isoformat(),
        "sessions": n,
        "malicious": positives,
        "benign": negatives,
        "run_ids": sorted(set(run_ids)),
    }
    return Model(mean, scale, w, b, meta)
