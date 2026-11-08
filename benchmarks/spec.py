"""實驗規格（docs/DECISIONS.md §29、SECURITY_AND_TESTING.md §6）：嚴格的 schema 與檢查。

- 靶場只能是 fixture、juice_shop、vampi 三種：位址由 tests/live/lab_support.py 固定在 live 的 lab
  網段，規格不接受任意 URL 或 IP（平台的 LAB_CIDR 與 grant 再擋一次）。
- 所有組別共用同一份總預算（§6：相同總請求數與牆鐘時間上限）。多引擎的組別以 engine_budgets
  凍結各引擎的份額；正式實驗（experiment）必須凍結，而且份額合計等於總額。
- 份額的規則和平台相同（最小時間窗、合計不超過總額）：make bench 在啟動 stack 之前先檢查，
  不合就停止。常數和平台的 scans/domain/allocation.py 相同，由測試核對。
"""

import hashlib
import re
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)

from benchmarks.strict_yaml import StrictYamlError, load_strict_yaml

NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
ID_PATTERN = r"^[A-Za-z0-9_-]{1,32}$"
ZAP_MIN_SECONDS = 120
ZAP_MIN_REQUEST_SECONDS = 120
NUCLEI_MIN_SECONDS = 60
# 平台的 quota：每個 target 在 24 小時內最多 50 個 scan（scans/service.py）。
MAX_SCANS_PER_TARGET = 50
MIN_EXPERIMENT_REPETITIONS = 3
MAX_REPETITIONS = 10
MAX_SEED = 2**32 - 1

EngineName = Literal["zap", "nuclei"]


class SpecError(ValueError):
    """實驗規格不合規則；訊息說明規則。"""


class Purpose(StrEnum):
    # smoke 驗證 harness 本身，數字不是實驗結果；experiment 是正式的實驗（T28）。
    SMOKE = "smoke"
    EXPERIMENT = "experiment"


class TargetKind(StrEnum):
    FIXTURE = "fixture"
    JUICE_SHOP = "juice_shop"
    VAMPI = "vampi"


class Variant(StrEnum):
    INSECURE = "insecure"
    SECURE = "secure"


# 各靶場可以啟動的版本（lab_support 的 start_*）：Juice Shop 沒有修補版。
VARIANTS: dict[TargetKind, frozenset[Variant]] = {
    TargetKind.FIXTURE: frozenset(Variant),
    TargetKind.JUICE_SHOP: frozenset({Variant.INSECURE}),
    TargetKind.VAMPI: frozenset(Variant),
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Budget(_Strict):
    requests_per_second: StrictInt = Field(ge=1)
    max_requests: StrictInt = Field(ge=1)
    max_duration_seconds: StrictInt = Field(ge=1)


class EngineShare(_Strict):
    engine: EngineName
    max_requests: StrictInt = Field(ge=1)
    max_duration_seconds: StrictInt = Field(ge=1)


class Group(_Strict):
    id: StrictStr = Field(pattern=ID_PATTERN)
    engines: tuple[EngineName, ...] = Field(min_length=1, max_length=2)
    engine_budgets: tuple[EngineShare, ...] | None = None


class TargetSpec(_Strict):
    id: StrictStr = Field(pattern=ID_PATTERN)
    kind: TargetKind


class Cell(_Strict):
    """一個組別在一個靶場的一個版本，重複 repetitions 次（每次是獨立的 scan）。"""

    group: StrictStr
    target: StrictStr
    variant: Variant
    repetitions: StrictInt = Field(ge=1, le=MAX_REPETITIONS)


class ComparisonBlock(_Strict):
    """同一個組別與靶場：先 baseline、再 current，兩個 scan 整塊移動，之後建立比較快照。"""

    id: StrictStr = Field(pattern=ID_PATTERN)
    group: StrictStr
    target: StrictStr
    baseline: Variant
    current: Variant


class ExperimentSpec(_Strict):
    name: StrictStr = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    purpose: Purpose
    seed: StrictInt = Field(ge=0, le=MAX_SEED)
    profile: Literal["web_active_lab"]
    budget: Budget
    groups: tuple[Group, ...] = Field(min_length=1)
    targets: tuple[TargetSpec, ...] = Field(min_length=1)
    cells: tuple[Cell, ...] = ()
    comparisons: tuple[ComparisonBlock, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        _unique("groups", [group.id for group in self.groups])
        _unique("targets", [target.id for target in self.targets])
        _unique("comparisons", [block.id for block in self.comparisons])
        _unique("cells", [f"{c.group}/{c.target}/{c.variant.value}" for c in self.cells])
        for group in self.groups:
            _check_group(group, self.budget, self.purpose)
        kinds = {target.id: target.kind for target in self.targets}
        groups = {group.id for group in self.groups}
        for cell in self.cells:
            _check_reference(cell.group, cell.target, groups, kinds)
            _check_variant(kinds[cell.target], cell.variant)
            if self.purpose is Purpose.EXPERIMENT and cell.repetitions < MIN_EXPERIMENT_REPETITIONS:
                raise SpecError(f"experiment 每格至少重複 {MIN_EXPERIMENT_REPETITIONS} 次")
        for block in self.comparisons:
            _check_reference(block.group, block.target, groups, kinds)
            _check_variant(kinds[block.target], block.baseline)
            _check_variant(kinds[block.target], block.current)
        if not self.cells and not self.comparisons:
            raise SpecError("規格至少要有一個 scan（cells 或 comparisons）")
        _check_quota(self)
        return self

    def group(self, group_id: str) -> Group:
        return next(group for group in self.groups if group.id == group_id)

    def target(self, target_id: str) -> TargetSpec:
        return next(target for target in self.targets if target.id == target_id)


def load_spec(path: Path) -> tuple[ExperimentSpec, str]:
    """讀規格檔；回傳規格與檔案位元組的 sha256（manifest 記錄）。"""
    content = path.read_bytes()
    return parse_spec(content), hashlib.sha256(content).hexdigest()


def parse_spec(content: bytes) -> ExperimentSpec:
    """規格的位元組 → ExperimentSpec；任何不合規則都是 SpecError（訊息不回顯輸入的值）。"""
    try:
        document = load_strict_yaml(content)
    except StrictYamlError as error:
        raise SpecError(str(error)) from None
    if not isinstance(document, dict):
        raise SpecError("規格必須是 YAML 的 mapping")
    try:
        return ExperimentSpec.model_validate(document)
    except ValidationError as error:
        raise SpecError(validation_summary(error)) from None


def validation_summary(error: ValidationError) -> str:
    """欄位位置與規則（不含輸入的值）。"""
    problems = []
    for item in error.errors(include_input=False, include_url=False):
        location = ".".join(str(part) for part in item["loc"]) or "(root)"
        problems.append(f"{location}: {item['msg']}")
    return "；".join(problems)


def check_name(name: str) -> str:
    """結果目錄的名稱：只收英數字、- 與 _（不接受路徑）。"""
    if NAME_PATTERN.fullmatch(name) is None:
        raise SpecError("BENCH_NAME 只能是 1 到 64 個英數字、- 或 _")
    return name


def _unique(field: str, values: list[str]) -> None:
    if len(set(values)) != len(values):
        raise SpecError(f"{field} 的 id 不可重複")


def _check_reference(
    group: str, target: str, groups: set[str], kinds: dict[str, TargetKind]
) -> None:
    if group not in groups:
        raise SpecError("引用了不存在的組別")
    if target not in kinds:
        raise SpecError("引用了不存在的靶場")


def _check_variant(kind: TargetKind, variant: Variant) -> None:
    if variant not in VARIANTS[kind]:
        raise SpecError(f"{kind.value} 沒有 {variant.value} 版")


def _check_group(group: Group, budget: Budget, purpose: Purpose) -> None:
    if len(set(group.engines)) != len(group.engines):
        raise SpecError("組別的引擎不可重複")
    shares = group.engine_budgets
    if len(group.engines) < 2:
        if shares is not None:
            raise SpecError("engine_budgets 只能用於兩個以上引擎的組別")
        return
    if shares is None:
        if purpose is Purpose.EXPERIMENT:
            raise SpecError("experiment 的多引擎組別必須凍結 engine_budgets（§6）")
        return
    listed = [share.engine for share in shares]
    if len(set(listed)) != len(listed) or set(listed) != set(group.engines):
        raise SpecError("engine_budgets 必須為組別的每個引擎各列一次")
    _check_shares(shares, budget, exact=purpose is Purpose.EXPERIMENT)


def _check_shares(shares: tuple[EngineShare, ...], budget: Budget, *, exact: bool) -> None:
    requests = sum(share.max_requests for share in shares)
    seconds = sum(share.max_duration_seconds for share in shares)
    if requests > budget.max_requests or seconds > budget.max_duration_seconds:
        raise SpecError("engine_budgets 的合計不能超過總預算")
    if exact and (requests, seconds) != (budget.max_requests, budget.max_duration_seconds):
        raise SpecError("experiment 的 engine_budgets 合計必須等於總預算（§6）")
    for share in shares:
        if share.engine == "zap" and (
            share.max_duration_seconds < ZAP_MIN_SECONDS
            or share.max_requests < ZAP_MIN_REQUEST_SECONDS * budget.requests_per_second
        ):
            raise SpecError("zap 的份額低於最小時間窗")
        if share.engine == "nuclei" and share.max_duration_seconds < NUCLEI_MIN_SECONDS:
            raise SpecError("nuclei 的份額低於最小時間窗")


def _check_quota(spec: ExperimentSpec) -> None:
    """平台的 target 是（組別, 靶場）：每個在 24 小時內的 scan 數不能超過 quota。"""
    counts: dict[tuple[str, str], int] = {}
    for cell in spec.cells:
        key = (cell.group, cell.target)
        counts[key] = counts.get(key, 0) + cell.repetitions
    for block in spec.comparisons:
        key = (block.group, block.target)
        counts[key] = counts.get(key, 0) + 2
    if any(count > MAX_SCANS_PER_TARGET for count in counts.values()):
        raise SpecError(f"同一個組別與靶場最多 {MAX_SCANS_PER_TARGET} 個 scan（平台的 quota）")
