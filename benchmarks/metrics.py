"""指標的值：比例或 N/A（SECURITY_AND_TESTING.md §7.1：分母為 0 時顯示 N/A，不填 100%）。"""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Ratio:
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if self.denominator <= 0 or not 0 <= self.numerator <= self.denominator:
            raise ValueError("比例必須是 0 ≤ 分子 ≤ 分母，且分母為正")

    @property
    def value(self) -> float:
        return self.numerator / self.denominator


@dataclass(frozen=True, slots=True)
class Score:
    """不是兩個計數的比例的值（F1）。"""

    value: float


@dataclass(frozen=True, slots=True)
class NotAvailable:
    reason: str


Metric = Ratio | NotAvailable
Derived = Score | NotAvailable


def ratio(numerator: int, denominator: int, *, empty: str) -> Metric:
    """分母為 0 → N/A（以 empty 說明原因）。"""
    if denominator == 0:
        return NotAvailable(empty)
    return Ratio(numerator, denominator)


def f1(precision: Metric, recall: Metric) -> Derived:
    if isinstance(precision, NotAvailable):
        return NotAvailable(f"precision: {precision.reason}")
    if isinstance(recall, NotAvailable):
        return NotAvailable(f"recall: {recall.reason}")
    total = precision.value + recall.value
    if total == 0:
        return NotAvailable("precision_and_recall_zero")
    return Score(2 * precision.value * recall.value / total)


def value_of(metric: Metric | Derived) -> float | None:
    return None if isinstance(metric, NotAvailable) else metric.value


def metric_json(metric: Metric | Derived) -> dict[str, Any]:
    if isinstance(metric, NotAvailable):
        return {"value": None, "not_available": metric.reason}
    if isinstance(metric, Ratio):
        return {
            "value": metric.value,
            "numerator": metric.numerator,
            "denominator": metric.denominator,
        }
    return {"value": metric.value}
