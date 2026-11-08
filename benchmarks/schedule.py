"""執行順序（SECURITY_AND_TESTING.md §6：隨機化）：由種子決定，相同的種子得到相同的順序。

單位是一次獨立的 scan（cell 的一次重複）或一個比較區塊（baseline 與 current 兩個 scan，順序固定、
整塊移動）。順序以 sha256(種子, 單位) 排序：不用 random 模組，結果不受 Python 版本影響，可以
從 manifest 重現。
"""

import hashlib
from dataclasses import dataclass
from typing import Literal

from benchmarks.spec import ExperimentSpec, Variant

Role = Literal["baseline", "current"]


@dataclass(frozen=True, slots=True)
class ScheduledScan:
    """position 從 1 開始；repetition 只屬於 cell，comparison 與 role 只屬於比較區塊。"""

    position: int
    unit: str
    group: str
    target: str
    variant: Variant
    repetition: int | None = None
    comparison: str | None = None
    role: Role | None = None


@dataclass(frozen=True, slots=True)
class _Planned:
    group: str
    target: str
    variant: Variant
    repetition: int | None = None
    comparison: str | None = None
    role: Role | None = None


def build_schedule(spec: ExperimentSpec) -> tuple[ScheduledScan, ...]:
    units: list[tuple[str, tuple[_Planned, ...]]] = []
    for cell in spec.cells:
        for repetition in range(1, cell.repetitions + 1):
            key = f"cell/{cell.group}/{cell.target}/{cell.variant.value}/{repetition}"
            units.append((key, (_Planned(cell.group, cell.target, cell.variant, repetition),)))
    for block in spec.comparisons:
        scans = (
            _Planned(
                block.group, block.target, block.baseline, comparison=block.id, role="baseline"
            ),
            _Planned(block.group, block.target, block.current, comparison=block.id, role="current"),
        )
        units.append((f"comparison/{block.id}", scans))
    # 單位不會重複：規格已檢查 cells 與比較區塊的 id 各自唯一。
    ordered = sorted(units, key=lambda unit: _rank(spec.seed, unit[0]))
    flat = [(key, planned) for key, scans in ordered for planned in scans]
    return tuple(
        ScheduledScan(
            position=position,
            unit=key,
            group=planned.group,
            target=planned.target,
            variant=planned.variant,
            repetition=planned.repetition,
            comparison=planned.comparison,
            role=planned.role,
        )
        for position, (key, planned) in enumerate(flat, 1)
    )


def _rank(seed: int, key: str) -> bytes:
    return hashlib.sha256(f"{seed}\0{key}".encode()).digest()
