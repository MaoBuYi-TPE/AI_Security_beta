"""跨重複的統計與評估的 JSON（純函式；SECURITY_AND_TESTING.md §7.1）。

- 每格（組別, 靶場, 版本）列出 n、中位數、最小值與最大值；IQR 只在可用的值有 4 個以上時才算，
  小樣本不宣稱有統計上的優勢。N/A 的次數另外列出，不當成 0。
- 每個案例的偵測頻率是 x/n（n 是這一格中把它列入評估的 scan 數）。
- smoke 的輸出標明「不是實驗結果」。
"""

import statistics
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from benchmarks.evaluate import Evaluation, ScanScore
from benchmarks.metrics import NotAvailable, Ratio, Score, metric_json, value_of

MIN_IQR_SAMPLES = 4
SMOKE_NOTICE = "smoke 只驗證 harness 本身：數字不是實驗結果，不寫進任何指標。"
DRAFT_NOTICE = "ground truth 不是凍結版：偵測指標只供校準，不是正式結果。"


@dataclass(frozen=True, slots=True)
class Summary:
    n: int
    available: int
    median: float | None
    minimum: float | None
    maximum: float | None
    iqr: tuple[float, float] | None


def summarize(values: Sequence[float | None]) -> Summary:
    present = sorted(value for value in values if value is not None)
    if not present:
        return Summary(len(values), 0, None, None, None, None)
    iqr = None
    if len(present) >= MIN_IQR_SAMPLES:
        quartiles = statistics.quantiles(present, n=4, method="inclusive")
        iqr = (quartiles[0], quartiles[2])
    return Summary(
        n=len(values),
        available=len(present),
        median=statistics.median(present),
        minimum=present[0],
        maximum=present[-1],
        iqr=iqr,
    )


_METRICS: Mapping[str, Callable[[ScanScore], float | None]] = {
    "recall": lambda s: value_of(s.detection.recall) if s.detection else None,
    "precision": lambda s: value_of(s.detection.precision) if s.detection else None,
    "f1": lambda s: value_of(s.detection.f1) if s.detection else None,
    "requests_sent": lambda s: _number(s.resources.requests_sent),
    "traffic_seconds": lambda s: _number(s.resources.traffic_seconds),
    "wall_seconds": lambda s: s.resources.wall_seconds,
    "findings": lambda s: float(s.dedup.findings),
    "compression": lambda s: value_of(s.dedup.compression),
}


def cells(evaluation: Evaluation) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[ScanScore]] = defaultdict(list)
    for score in evaluation.scans:
        grouped[(score.group, score.target, score.variant)].append(score)
    return [
        {
            "group": group,
            "target": target,
            "variant": variant,
            "n": len(scores),
            "statuses": _counts(score.status for score in scores),
            "metrics": {
                name: asdict(summarize([pick(score) for score in scores]))
                for name, pick in _METRICS.items()
            },
            "detection_frequency": _frequency(scores),
        }
        for (group, target, variant), scores in sorted(grouped.items())
    ]


def evaluation_json(evaluation: Evaluation, *, purpose: str) -> dict[str, Any]:
    notices = [SMOKE_NOTICE] if purpose == "smoke" else []
    if any(status != "frozen" for status in evaluation.ground_truth.values()):
        notices.append(DRAFT_NOTICE)
    return {
        "purpose": purpose,
        "notices": notices,
        "ground_truth": dict(evaluation.ground_truth),
        "include_holdout": evaluation.include_holdout,
        "cells": cells(evaluation),
        "scans": [_plain(score) for score in evaluation.scans],
        "rescans": [_plain(score) for score in evaluation.rescans],
    }


def _frequency(scores: Sequence[ScanScore]) -> dict[str, dict[str, int]]:
    evaluated: dict[str, int] = defaultdict(int)
    detected: dict[str, int] = defaultdict(int)
    for score in scores:
        if score.detection is None:
            continue
        for case in score.detection.evaluated_cases:
            evaluated[case] += 1
        for case in score.detection.detected_cases:
            detected[case] += 1
    return {case: {"detected": detected[case], "n": n} for case, n in sorted(evaluated.items())}


def _counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for value in values:
        counts[value] += 1
    return dict(sorted(counts.items()))


def _number(value: int | None) -> float | None:
    return None if value is None else float(value)


def _plain(value: Any) -> Any:
    """dataclass 與指標 → JSON 可以表示的值（指標帶分子、分母或 N/A 的原因）。"""
    if isinstance(value, Ratio | Score | NotAvailable):
        return metric_json(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {name: _plain(getattr(value, name)) for name in value.__dataclass_fields__}
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(item) for item in value]
    return value
