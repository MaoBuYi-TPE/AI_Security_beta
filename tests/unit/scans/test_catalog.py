"""引擎與 scan profile 的規則（docs/DECISIONS.md §13.1、§13.3）。"""

from ipaddress import IPv4Address

import pytest

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.scans.domain.catalog import (
    AVAILABLE_ENGINES,
    ENGINE_ORDER,
    SELECTABLE_ENGINES,
    WEB_SEED_PATH,
    Engine,
    IncompatibleProfileError,
    InvalidScanRequestError,
    PlannedRun,
    ScanProfile,
    UnsupportedEngineError,
    check_operations,
    check_profile,
    check_seed_path,
    plan_runs,
)
from secscan.targets.domain import TargetKind, parse_origin

ZAP, NUCLEI, SCHEMATHESIS, FAKE = Engine.ZAP, Engine.NUCLEI, Engine.SCHEMATHESIS, Engine.FAKE
API_LAB, WEB_LAB = ScanProfile.API_ACTIVE_LAB, ScanProfile.WEB_ACTIVE_LAB


def test_only_integrated_engines_are_available() -> None:
    """使用者的決定（2026-10-26）：真的 Adapter 整合之前，DB 不會出現它們的 run（zap 在 T15）。"""
    assert frozenset({FAKE, ZAP}) == AVAILABLE_ENGINES


def test_fake_alone_is_planned_as_the_first_run() -> None:
    assert plan_runs([FAKE]) == (PlannedRun(engine=FAKE, sequence=1),)


@pytest.mark.parametrize(("engine", "milestone"), [(NUCLEI, "T18"), (SCHEMATHESIS, "M6")])
def test_engines_without_an_adapter_are_unsupported(engine: Engine, milestone: str) -> None:
    with pytest.raises(UnsupportedEngineError, match=milestone) as caught:
        plan_runs([engine])

    assert caught.value.engine is engine


def test_runs_follow_the_fixed_engine_order_regardless_of_the_request() -> None:
    """執行順序固定為 zap → nuclei → schemathesis（CLAUDE.md §4）；以「全部可用」的規則檢查。"""
    every_engine = frozenset(Engine)

    planned = plan_runs([SCHEMATHESIS, ZAP, NUCLEI], available=every_engine)

    assert planned == (
        PlannedRun(engine=ZAP, sequence=1),
        PlannedRun(engine=NUCLEI, sequence=2),
        PlannedRun(engine=SCHEMATHESIS, sequence=3),
    )


@pytest.mark.parametrize(
    ("engines", "reason"),
    [
        ([], "至少"),
        ([FAKE, FAKE], "重複"),
        ([FAKE, ZAP], "fake"),
        ([NUCLEI, FAKE], "fake"),
    ],
)
def test_empty_duplicate_or_mixed_engines_are_invalid(engines: list[Engine], reason: str) -> None:
    """fake 和真的引擎混用會污染結果；這些規則先於「尚未整合」判斷。"""
    with pytest.raises(InvalidScanRequestError, match=reason):
        plan_runs(engines, available=frozenset(Engine))


def test_mixing_fake_is_reported_before_unsupported_engines() -> None:
    with pytest.raises(InvalidScanRequestError, match="fake"):
        plan_runs([ZAP, FAKE])


@pytest.mark.parametrize(
    ("profile", "kind", "has_spec"),
    [
        (API_LAB, TargetKind.API, True),
        (API_LAB, TargetKind.HYBRID, True),
        (WEB_LAB, TargetKind.WEB, False),
        (WEB_LAB, TargetKind.HYBRID, False),
    ],
)
def test_compatible_profiles(profile: ScanProfile, kind: TargetKind, has_spec: bool) -> None:
    check_profile(profile, target_kind=kind, has_spec=has_spec)


@pytest.mark.parametrize(
    ("profile", "kind", "has_spec", "reason"),
    [
        (API_LAB, TargetKind.WEB, True, "api 或 hybrid"),
        (API_LAB, TargetKind.API, False, "api_spec_id"),
        (WEB_LAB, TargetKind.API, False, "web 或 hybrid"),
        (WEB_LAB, TargetKind.WEB, True, "api_spec_id"),
    ],
)
def test_incompatible_profiles(
    profile: ScanProfile, kind: TargetKind, has_spec: bool, reason: str
) -> None:
    with pytest.raises(IncompatibleProfileError, match=reason):
        check_profile(profile, target_kind=kind, has_spec=has_spec)


def test_an_api_scan_needs_at_least_one_operation_in_scope() -> None:
    check_operations(API_LAB, eligible_operations=1)
    with pytest.raises(IncompatibleProfileError, match="範圍"):
        check_operations(API_LAB, eligible_operations=0)


def test_a_web_scan_has_no_operations_to_check() -> None:
    check_operations(WEB_LAB, eligible_operations=None)


def test_operation_counts_must_match_whether_the_profile_takes_a_spec() -> None:
    """呼叫端的錯誤（不是使用者的輸入）：直接失敗，不默默接受。"""
    with pytest.raises(ValueError, match="規格"):
        check_operations(API_LAB, eligible_operations=None)
    with pytest.raises(ValueError, match="規格"):
        check_operations(WEB_LAB, eligible_operations=3)


# --- preflight（docs/DECISIONS.md §16.5）-----------------------------------------------------


def test_authenticated_scans_start_with_a_preflight() -> None:
    runs = plan_runs([Engine.FAKE], authenticated=True)

    assert runs == (
        PlannedRun(engine=Engine.PREFLIGHT, sequence=1),
        PlannedRun(engine=Engine.FAKE, sequence=2),
    )


def test_anonymous_scans_have_no_preflight() -> None:
    assert plan_runs([Engine.FAKE]) == (PlannedRun(engine=Engine.FAKE, sequence=1),)


def test_preflight_cannot_be_requested() -> None:
    with pytest.raises(UnsupportedEngineError, match="自動加入"):
        plan_runs([Engine.PREFLIGHT])


def test_selectable_engines_exclude_preflight() -> None:
    assert Engine.PREFLIGHT not in SELECTABLE_ENGINES
    assert ENGINE_ORDER[0] is Engine.PREFLIGHT
    assert set(SELECTABLE_ENGINES) == set(Engine) - {Engine.PREFLIGHT}


# --- zap 的 spider 起點（docs/DECISIONS.md §18.7）---------------------------------------------


def _rules(*paths: str, methods: tuple[HttpMethod, ...] = (HttpMethod.GET,)) -> ScopeRules:
    return ScopeRules.of(
        Scope(
            origins=(parse_origin("http://lab-web:3000"),),
            ips=(IPv4Address("10.89.7.20"),),
            paths=paths,
            allow_all_paths=not paths,
            excluded_paths=(),
            methods=methods,
        )
    )


def test_zap_on_the_web_profile_needs_get_on_the_root() -> None:
    check_seed_path((ZAP,), WEB_LAB, _rules("/", "/shop"))
    check_seed_path((ZAP,), WEB_LAB, _rules())
    with pytest.raises(IncompatibleProfileError, match="GET /"):
        check_seed_path((ZAP,), WEB_LAB, _rules("/shop"))
    with pytest.raises(IncompatibleProfileError, match="GET /"):
        check_seed_path((ZAP,), WEB_LAB, _rules(methods=(HttpMethod.POST,)))


def test_only_zap_on_the_web_profile_needs_the_root() -> None:
    check_seed_path((FAKE,), WEB_LAB, _rules("/shop"))
    check_seed_path((ZAP,), API_LAB, _rules("/api/items"))
    check_seed_path((Engine.PREFLIGHT, ZAP), API_LAB, _rules("/me"))


def test_the_seed_path_is_the_root() -> None:
    assert WEB_SEED_PATH == "/"
