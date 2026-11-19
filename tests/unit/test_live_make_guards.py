"""Live 的 recipe 不得讓檢查或測試空轉（G1d：程式碼審查 LOW-1、安全審查 B 的 LOW-1）。

以 repo 的 Makefile 實際執行 make；docker 與 uv 是 tests/unit/test_live_isolation_make.py 的替身
（compose config 交給真的 docker compose，只在用戶端解析），不連 Docker daemon、不建立任何資源。

- compose config 失敗（輸出完整、結束碼非零）或沒有輸出時，在 up 之前停止：shell 的管線只看最後一個
  指令的結束碼，下游的檢查不得蓋掉 compose 的失敗。
- 一次 make 只能有一個 Live 目標：Live 的目標共用 test-live-runner 這個前置，make 只執行它一次，
  其他目標的測試不會執行卻以 0 結束。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import re
from pathlib import Path

import pytest

from tests.live import env_guard
from tests.unit.test_live_isolation_make import (
    FIXED,
    MAKEFILE,
    Hostile,
    _definition,
    _recipe,
    _secrets_dirs,
)


@pytest.fixture
def hostile(tmp_path: Path) -> Hostile:
    return Hostile(tmp_path)


# --- compose config 的結束碼與空的輸出 ----------------------------------------------------------


def _stopped_before_up(hostile: Hostile, returncode: int, leaked: set[str]) -> None:
    """recipe 在 up 之前停止：沒有 up、alembic、pytest；trap 照樣清理（拋棄式目錄已刪除）。

    參數只有結束碼與洩漏的名稱：失敗時 pytest 的 traceback 會顯示 helper 的參數，所以不傳 make
    的輸出（G1 審查：失敗時不印出秘密）。
    """
    assert returncode != 0
    assert leaked == set()
    assert not any(argv[:1] == ["compose"] and "up" in argv for argv in hostile.docker_argvs())
    tools = [call["argv"][2:3] for call in hostile.calls() if call["tool"] == "uv"]
    assert ["alembic"] not in tools
    assert ["pytest"] not in tools
    directories = [
        name for name in _secrets_dirs(hostile) if name.startswith("secscan-live-secrets.")
    ]
    assert directories == []


@pytest.mark.parametrize("name", ["resolved", "unresolved", "environment"])
def test_a_failed_compose_config_stops_before_up(hostile: Hostile, name: str) -> None:
    """G1d（程式碼審查 LOW-1）：compose config 輸出完整的設定卻以非零結束時，下游檢查的結束碼不得
    蓋掉它（shell 的管線只看最後一個指令的結束碼）。"""
    hostile.set_scenario(config_fails=name)

    result = hostile.make()

    _stopped_before_up(hostile, result.returncode, hostile.leaked(result.stdout + result.stderr))
    # resolved：清理在 down -v 之前也以同一種 config 核對對象，替身讓它一樣失敗，所以清理
    # fail closed（不 down、留下診斷檔）；其他兩種的清理正常完成。
    assert bool(hostile.diagnostics()) is (name == "resolved")


def test_an_empty_environment_listing_stops_before_up(hostile: Hostile) -> None:
    """G1d：compose 以 0 結束、沒有輸出時，check-environment 不得因為沒有不允許的名稱而放行。"""
    hostile.set_scenario(config_empty="environment")

    result = hostile.make()

    _stopped_before_up(hostile, result.returncode, hostile.leaked(result.stdout + result.stderr))
    assert "沒有輸出" in result.stderr


def test_compose_config_output_is_checked_only_after_its_exit_code() -> None:
    """G1d：三個 config 的輸出先存進 shell 變數（不寫檔）、以 || exit 1 確認結束碼，之後才交給
    env_guard；沒有直接接在管線上的 config。"""
    flattened = _recipe("test-live-runner").replace("\\\n", " ")

    captured = re.findall(r"=\$\$\(\$\(LIVE_COMPOSE\) config ([^)]*)\) \|\| exit 1;", flattened)
    assert captured == [
        "--format json",
        "--no-env-resolution --format json",
        "--environment",
    ]
    # config 之後的第一個 | 不能是管線（|| 是結束碼的確認）。
    assert re.search(r"\$\(LIVE_COMPOSE\) config[^;|]*\|(?!\|)", flattened) is None


def test_the_required_environment_is_what_the_recipe_always_sets() -> None:
    """G1d：check-environment 要求的名稱，都是 recipe 一定會設定的（白名單的基本變數與固定的
    值）。"""
    always = {"PATH", "HOME", "TMPDIR", "SECSCAN_SECRETS_DIR", "SECSCAN_LIVE_SECRETS_DIR"}

    assert env_guard.REQUIRED_ENVIRONMENT.issubset(always | set(FIXED))
    assert {"COMPOSE_DISABLE_ENV_FILE", "SECSCAN_SECRETS_DIR"} <= env_guard.REQUIRED_ENVIRONMENT


# --- 一次 make 只能有一個 Live 目標（G1d；安全審查 B 的 LOW-1）-----------------------------------


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("test-live-zap", "test-live-db-roles"),
        ("test-live-runner", "test-live-secrets"),
        ("test-live-secrets", "test-live-secrets"),
        ("bench", "test-live-zap"),
        ("test-live-fixture-findings", "record-fixtures"),
    ],
)
def test_two_live_targets_in_one_make_are_refused(
    hostile: Hostile, first: str, second: str
) -> None:
    """Live 的目標都以 test-live-runner 為前置，make 只執行它一次（第一個目標的 LIVE_TESTS）：第二個
    目標沒有自己的 recipe、以 0 結束，看起來像通過。make 讀 Makefile 時就拒絕，不執行任何一步。"""
    result = hostile.make(first, target=second)

    assert result.returncode != 0
    assert "一次只能執行一個 Live 目標" in result.stderr
    assert hostile.calls() == []
    assert _secrets_dirs(hostile) == []


@pytest.mark.parametrize(
    ("argument", "environment"),
    [("MAKECMDGOALS=", {}), ("-e", {"MAKECMDGOALS": ""}), (None, {"MAKECMDGOALS": ""})],
    ids=["command-line", "environment-override", "environment"],
)
def test_overriding_the_goal_list_is_refused(
    hostile: Hostile, argument: str | None, environment: dict[str, str]
) -> None:
    """GNU make 3.81 讓命令列與環境變數的 MAKECMDGOALS 蓋掉 make 自己的值（實測）：蓋掉之後就數不到
    Live 的目標，所以一律拒絕。"""
    args = [item for item in (argument, "test-live-zap") if item is not None]

    result = hostile.make(*args, target="test-live-db-roles", **environment)

    assert result.returncode != 0
    assert "MAKECMDGOALS" in result.stderr
    assert hostile.calls() == []


def _rules() -> dict[str, tuple[str, str]]:
    """Makefile 的規則：目標 → （前置，recipe）。不含目標專屬的變數（target: VAR := …）。"""
    rules = {}
    pattern = r"^([a-z][a-z0-9-]*):(?!=)(.*)\n((?:\t.*\n)*)"
    for match in re.finditer(pattern, MAKEFILE, flags=re.MULTILINE):
        target, prerequisites, recipe = match.groups()
        if re.match(r"\s*(?:override\s+)?[A-Z_]+\s*[:+?]?=", prerequisites):
            continue
        rules[target] = (prerequisites, recipe)
    return rules


def test_the_live_goal_list_covers_every_live_target() -> None:
    """新增的 Live 目標（以 test-live-runner 為前置，或在 recipe 中遞迴呼叫它）都要列在
    LIVE_GOALS。"""
    live = {"test-live-runner"} | {
        target
        for target, (prerequisites, recipe) in _rules().items()
        if "test-live-runner" in prerequisites.split() or "test-live-runner" in recipe
    }

    assert set(_definition("LIVE_GOALS").replace("\\\n", " ").split()) == live
    assert {"test-live-zap", "test-live-secrets", "bench", "record-fixtures"} <= live
    assert re.search(r"^override LIVE_GOALS :?= ", MAKEFILE, flags=re.MULTILINE)


def test_one_live_target_with_other_goals_still_runs(hostile: Hostile) -> None:
    """拒絕只看 Live 的目標：一個 Live 目標加上非 Live 的目標照常執行。"""
    result = hostile.make("bench-evaluate", target="test-live-runner", BENCH_NAME="")

    assert "一次只能執行一個 Live 目標" not in result.stderr
    assert "需要設定 BENCH_NAME" in result.stdout
