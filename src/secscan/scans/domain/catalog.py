"""引擎與 scan profile 的規則（docs/DECISIONS.md §13.1、§13.3）。

只能從伺服器的 allowlist 選擇（contract §7）。真的 Adapter 整合之前只開放 fake：DB 不會出現
「zap 成功、其實沒跑 ZAP」的紀錄（CLAUDE.md §3：Mock 不等於 Adapter 完成）。
"""

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from secscan.grants.domain.matching import ScopeRules
from secscan.targets.domain import TargetKind


class Engine(StrEnum):
    ZAP = "zap"
    NUCLEI = "nuclei"
    SCHEMATHESIS = "schemathesis"
    # 不發任何流量的測試引擎：結果一律標為 fixture（docs/DECISIONS.md §13.7）。
    FAKE = "fake"
    # 認證的 preflight（docs/DECISIONS.md §16.5）：綁定 auth profile 時由平台自動排在最前面，
    # 不能在請求中指定、不出現在 GET /scanners。
    PREFLIGHT = "preflight"


# 同一個 target 依序執行（CLAUDE.md §4），順序固定，與請求中的順序無關。preflight 一定最先。
ENGINE_ORDER: tuple[Engine, ...] = (
    Engine.PREFLIGHT,
    Engine.ZAP,
    Engine.NUCLEI,
    Engine.SCHEMATHESIS,
    Engine.FAKE,
)
# 請求可以指定的引擎（preflight 是內部的）。
SELECTABLE_ENGINES: tuple[Engine, ...] = tuple(
    engine for engine in ENGINE_ORDER if engine is not Engine.PREFLIGHT
)
AVAILABLE_ENGINES: frozenset[Engine] = frozenset({Engine.FAKE})
_UNAVAILABLE_REASONS: Mapping[Engine, str] = MappingProxyType(
    {
        Engine.PREFLIGHT: "preflight 不能指定：綁定 auth profile 時由平台自動加入",
        Engine.ZAP: "zap 的 Adapter 在 M3（T14）整合之後才能使用",
        Engine.NUCLEI: "nuclei 的 Adapter 在 M4（T18）整合之後才能使用",
        Engine.SCHEMATHESIS: "schemathesis 是 P1，M6 整合之後才能使用",
    }
)


# ZAP 的 web profile 從這裡開始 spider（docs/DECISIONS.md §18.7）。
WEB_SEED_PATH = "/"


class ScanProfile(StrEnum):
    API_ACTIVE_LAB = "api_active_lab"
    WEB_ACTIVE_LAB = "web_active_lab"


@dataclass(frozen=True, slots=True)
class ProfileRule:
    requires_spec: bool
    target_kinds: frozenset[TargetKind]


PROFILE_RULES: Mapping[ScanProfile, ProfileRule] = MappingProxyType(
    {
        ScanProfile.API_ACTIVE_LAB: ProfileRule(
            requires_spec=True, target_kinds=frozenset({TargetKind.API, TargetKind.HYBRID})
        ),
        ScanProfile.WEB_ACTIVE_LAB: ProfileRule(
            requires_spec=False, target_kinds=frozenset({TargetKind.WEB, TargetKind.HYBRID})
        ),
    }
)


class InvalidScanRequestError(ValueError):
    """請求內容不合規則（422 INVALID_REQUEST）；訊息說明原因，不含使用者的輸入。"""


class UnsupportedEngineError(ValueError):
    """引擎還沒有整合（422 ENGINE_UNSUPPORTED）。"""

    def __init__(self, engine: Engine) -> None:
        super().__init__(_UNAVAILABLE_REASONS.get(engine, f"{engine.value} 目前無法使用"))
        self.engine = engine


class IncompatibleProfileError(ValueError):
    """scan profile 與 target、規格不相容（422 PROFILE_INCOMPATIBLE）。"""


@dataclass(frozen=True, slots=True)
class PlannedRun:
    engine: Engine
    sequence: int


def plan_runs(
    engines: Sequence[Engine],
    *,
    authenticated: bool = False,
    available: Collection[Engine] = AVAILABLE_ENGINES,
) -> tuple[PlannedRun, ...]:
    """每個引擎一個 run，依固定的順序編號（從 1 開始）；authenticated 時最前面加上 preflight。

    先檢查請求本身（至少一個、不重複、fake 單獨使用），再檢查引擎是否已整合。
    """
    if not engines:
        raise InvalidScanRequestError("engines 至少要有一個引擎")
    if len(set(engines)) != len(engines):
        raise InvalidScanRequestError("engines 不可重複")
    if Engine.FAKE in engines and len(engines) > 1:
        raise InvalidScanRequestError("fake 必須單獨使用，不能和其他引擎混用")
    ordered = sorted(engines, key=ENGINE_ORDER.index)
    for engine in ordered:
        if engine not in available:
            raise UnsupportedEngineError(engine)
    if authenticated:
        ordered = [Engine.PREFLIGHT, *ordered]
    return tuple(
        PlannedRun(engine=engine, sequence=index) for index, engine in enumerate(ordered, 1)
    )


def check_profile(profile: ScanProfile, *, target_kind: TargetKind, has_spec: bool) -> None:
    """profile 與 target 的種類、是否帶規格相容；不相容時拋出 IncompatibleProfileError。"""
    rule = PROFILE_RULES[profile]
    if target_kind not in rule.target_kinds:
        kinds = " 或 ".join(kind.value for kind in TargetKind if kind in rule.target_kinds)
        raise IncompatibleProfileError(f"{profile.value} 只能用於 {kinds} 的 target")
    if rule.requires_spec and not has_spec:
        raise IncompatibleProfileError(f"{profile.value} 需要 api_spec_id")
    if not rule.requires_spec and has_spec:
        raise IncompatibleProfileError(f"{profile.value} 不接受 api_spec_id")


def check_operations(profile: ScanProfile, *, eligible_operations: int | None) -> None:
    """需要規格的 profile 至少要有一個 operation 在 grant 的範圍內（coverage 的分母不可為 0）。

    eligible_operations 是 None 代表沒有規格；和 profile 是否需要規格不一致是呼叫端的錯誤。
    """
    rule = PROFILE_RULES[profile]
    if rule.requires_spec != (eligible_operations is not None):
        raise ValueError("有沒有規格和 profile 的規則不一致")
    if eligible_operations == 0:
        raise IncompatibleProfileError("規格中沒有任何 operation 在 scope grant 的範圍內")


def check_seed_path(engines: Collection[Engine], profile: ScanProfile, rules: ScopeRules) -> None:
    """zap 的 web profile 從 / 開始 spider：grant 必須允許 GET /（§18.7）。

    只檢查 zap：fake 不送流量，不需要起點；api profile 由規格決定要送的請求。
    """
    if Engine.ZAP not in engines or profile is not ScanProfile.WEB_ACTIVE_LAB:
        return
    if rules.classify(method="GET", path=WEB_SEED_PATH) is not None:
        raise IncompatibleProfileError(
            f"zap 的 {profile.value} 需要 scope grant 允許 GET /（spider 的起點）"
        )
