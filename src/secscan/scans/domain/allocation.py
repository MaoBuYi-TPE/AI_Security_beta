"""引擎子預算（T31；docs/DECISIONS.md §29）：多引擎的 scan 可以凍結每個引擎的上限。

- 選填：沒有指定時行為不變，每個 run 分到 scan 剩下的全部預算（§16.4）。
- 指定時，scan 的每個掃描引擎都要恰好列一次；各引擎的合計不超過 scan 的總額；份額不低於引擎的
  最小時間窗（低於它註定 BUDGET_EXHAUSTED，建立時就拒絕）。
- 每個 run 開始前取「scan 剩下的」與「這個引擎的上限」的較小值（請求數與秒數各自取）。先跑的引擎
  沒用完的份額作廢，不轉給後面的引擎：只會讓單一 run 的配額變小，不會放寬任何限制。

最小時間窗和 scanners 的 plan 相同；scans 依分層不能 import scanners，所以在這裡各寫一份，由單元
測試核對兩邊相同。
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from secscan.grants.domain.scope import Budget
from secscan.scans.domain.catalog import ENGINE_ORDER, Engine, InvalidScanRequestError

# zap：plan 的保留時間（60 秒）加最短的掃描時間（60 秒）；請求數換算成秒數（請求數 // 速率）也要
# 這麼多（scanners/domain/zap/plan.py 的 plan_seconds）。
ZAP_MIN_SECONDS = 120
ZAP_MIN_REQUEST_SECONDS = 120
# nuclei：最短的牆鐘時間（scanners/domain/nuclei/plan.py 的 MIN_PLAN_SECONDS）。
NUCLEI_MIN_SECONDS = 60
_MIN_SECONDS: Mapping[Engine, int] = MappingProxyType(
    {Engine.ZAP: ZAP_MIN_SECONDS, Engine.NUCLEI: NUCLEI_MIN_SECONDS}
)
_MIN_REQUEST_SECONDS: Mapping[Engine, int] = MappingProxyType({Engine.ZAP: ZAP_MIN_REQUEST_SECONDS})
_FIELD = "engine_budgets"
NO_ENGINE_BUDGETS: Mapping[Engine, "EngineBudget"] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class EngineBudget:
    """一個引擎凍結的上限（建立 scan 時寫入，之後不能修改）。"""

    max_requests: int
    max_duration_seconds: int

    def __post_init__(self) -> None:
        if not (_positive(self.max_requests) and _positive(self.max_duration_seconds)):
            raise ValueError("引擎的上限必須是正整數")


@dataclass(frozen=True, slots=True)
class EngineBudgetRequest:
    """請求中的一個引擎的份額（尚未檢查）。"""

    engine: Engine
    max_requests: int
    max_duration_seconds: int


def check_allocation_shape(
    engines: Sequence[Engine], requested: Sequence[EngineBudgetRequest] | None
) -> None:
    """只看請求本身：只用在兩個以上掃描引擎的 scan，每個引擎恰好列一次（取得任何鎖之前判斷）。"""
    if requested is None:
        return
    if len(set(engines)) < 2 or Engine.FAKE in engines:
        raise InvalidScanRequestError(f"{_FIELD} 只能用於兩個以上掃描引擎的 scan")
    listed = [item.engine for item in requested]
    if len(set(listed)) != len(listed):
        raise InvalidScanRequestError(f"{_FIELD} 的引擎不可重複")
    if set(listed) != set(engines):
        raise InvalidScanRequestError(f"{_FIELD} 必須為 engines 的每個引擎各列一次")


def resolve_engine_budgets(
    requested: Sequence[EngineBudgetRequest] | None, *, budget: Budget
) -> Mapping[Engine, EngineBudget]:
    """scan 的總額確定之後：每個份額是 1 到總額的整數、合計不超過總額、不低於最小時間窗。

    形狀已由 check_allocation_shape 檢查過。訊息說明規則，不回顯請求的值。
    """
    if requested is None:
        return NO_ENGINE_BUDGETS
    for item in requested:
        _within("max_requests", item.max_requests, budget.max_requests)
        _within("max_duration_seconds", item.max_duration_seconds, budget.max_duration_seconds)
    _total("max_requests", sum(item.max_requests for item in requested), budget.max_requests)
    _total(
        "max_duration_seconds",
        sum(item.max_duration_seconds for item in requested),
        budget.max_duration_seconds,
    )
    for item in requested:
        _minimum(item, requests_per_second=budget.requests_per_second)
    ordered = sorted(requested, key=lambda item: ENGINE_ORDER.index(item.engine))
    return MappingProxyType(
        {
            item.engine: EngineBudget(
                max_requests=item.max_requests, max_duration_seconds=item.max_duration_seconds
            )
            for item in ordered
        }
    )


def allowance(requests: int, seconds: int, cap: EngineBudget | None) -> tuple[int, int]:
    """run 的配額：scan 剩下的（請求數、秒數）與這個引擎的上限，各自取較小值。"""
    if cap is None:
        return requests, seconds
    return min(requests, cap.max_requests), min(seconds, cap.max_duration_seconds)


def _within(field: str, value: int, total: int) -> None:
    if not _positive(value) or value > total:
        raise InvalidScanRequestError(
            f"{_FIELD} 的 {field} 必須是 1 到 {total}（scan 的總額）的整數"
        )


def _total(field: str, value: int, total: int) -> None:
    if value > total:
        raise InvalidScanRequestError(
            f"{_FIELD} 的 {field} 的合計不能超過 scan 的 {field}（{total}）"
        )


def _minimum(item: EngineBudgetRequest, *, requests_per_second: int) -> None:
    engine = item.engine.value
    seconds = _MIN_SECONDS.get(item.engine)
    if seconds is not None and item.max_duration_seconds < seconds:
        raise InvalidScanRequestError(
            f"{_FIELD} 中 {engine} 的 max_duration_seconds 至少要 {seconds} 秒（最小時間窗）"
        )
    request_seconds = _MIN_REQUEST_SECONDS.get(item.engine)
    if request_seconds is not None and item.max_requests < request_seconds * requests_per_second:
        raise InvalidScanRequestError(
            f"{_FIELD} 中 {engine} 的 max_requests 至少要 {request_seconds} 秒的請求數"
            f"（{request_seconds * requests_per_second}，依 requests_per_second 換算）"
        )


def _positive(value: int) -> bool:
    # bool 是 int 的子類別：True 不能被當成 1。
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1
