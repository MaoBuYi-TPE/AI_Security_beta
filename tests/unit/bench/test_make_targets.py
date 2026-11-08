"""make bench 只是 test-live-runner 的包裝（BENCH-12；docs/DECISIONS.md §29）。

- 參數檢查（ENABLE_LIVE_LAB_TESTS、規格、結果目錄的名稱）是 bench 的前置；檢查都通過之後，recipe
  才遞迴執行 test-live-runner（以 make -j 執行時也不會先啟動 stack）。
- bench 的 recipe 只有這一行：建立、測試與清理完全沿用 test-live-runner（同一個隔離專案與範圍），
  不新增任何清理或 Docker 指令。
- 使用者給的值（BENCH_SPEC、BENCH_NAME…）以環境變數交給 shell 展開，不以 $(…) 嵌進 recipe 的文字。
- bench-check 與 bench-evaluate 是離線的：不碰 Docker、compose 或刪除檔案。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
LINES = MAKEFILE.splitlines()
OFFLINE_FORBIDDEN = ("docker", "compose", "rm ", "down", "pytest", "ENABLE_LIVE_LAB_TESTS")
USER_VALUES = (
    "BENCH_SPEC",
    "BENCH_NAME",
    "BENCH_TRUTH",
    "BENCH_ADJUDICATIONS",
    "BENCH_PAIR_LABELS",
    "BENCH_INCLUDE_HOLDOUT",
)
BENCH_TARGETS = ("bench-check", "bench-live-check", "bench", "bench-evaluate")


def _rule(target: str) -> tuple[list[str], list[str]]:
    """target 的前置與 recipe（以 tab 開頭的連續行）。"""
    [index] = [
        i for i, line in enumerate(LINES) if line.startswith(f"{target}:") and ":=" not in line
    ]
    prerequisites = LINES[index].split(":", 1)[1].split()
    recipe = []
    for line in LINES[index + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line)
    return prerequisites, recipe


def _logical(recipe: list[str]) -> str:
    """以 \\ 接續的多行合成一行。"""
    return " ".join(line.strip().removesuffix("\\").strip() for line in recipe)


def test_bench_checks_everything_before_it_runs_the_live_stack() -> None:
    prerequisites, recipe = _rule("bench")

    assert prerequisites == ["bench-live-check", "bench-check"]
    assert _logical(recipe) == (
        "@$(MAKE) --no-print-directory test-live-runner "
        "LIVE_TESTS=tests/live/test_bench_live.py LIVE_PYTEST_ARGS=-s"
    )


def test_bench_has_no_target_specific_variables() -> None:
    assert not [line for line in LINES if re.match(r"bench[a-z-]*: \w+ :?=", line)]


def test_the_live_gate_is_checked_first() -> None:
    _, recipe = _rule("bench-live-check")

    [line] = recipe
    assert line.startswith('\t@[ "$$ENABLE_LIVE_LAB_TESTS" = 1 ] || {')
    assert line.endswith("exit 1; }")


def test_the_offline_targets_do_not_touch_docker_or_files() -> None:
    for target in ("bench-check", "bench-evaluate"):
        prerequisites, recipe = _rule(target)
        assert prerequisites == []
        text = _logical(recipe)
        assert "benchmarks.cli" in text
        for word in OFFLINE_FORBIDDEN:
            assert word not in text, (target, word)


def test_user_values_reach_the_shell_as_environment_variables() -> None:
    """$(BENCH_SPEC) 會在 shell 解析之前被 make 替換成文字；"$$BENCH_SPEC" 由 shell 展開，不會被當成
    指令（安全審查 L1）。"""
    exported = next(line for line in LINES if line.startswith("export BENCH_"))
    assert exported.split()[1:] == list(USER_VALUES)
    for target in BENCH_TARGETS:
        text = _logical(_rule(target)[1])
        for name in USER_VALUES:
            assert f"$({name})" not in text, (target, name)
    assert '"$$BENCH_SPEC" "$$BENCH_NAME"' in _logical(_rule("bench-check")[1])


def test_results_stay_in_the_ignored_directory() -> None:
    assert "BENCH_RESULTS := $(CURDIR)/benchmarks/results" in MAKEFILE
    assert "benchmarks/results/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


def test_the_bench_targets_are_phony() -> None:
    phony = MAKEFILE.split(".PHONY:", 1)[1].split("\n\n", 1)[0]

    for target in BENCH_TARGETS:
        assert f" {target}" in phony.replace("\\\n", " ").replace("\t", " ")
