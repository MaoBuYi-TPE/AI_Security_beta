"""make bench 只是 test-live-runner 的包裝（BENCH-12；docs/DECISIONS.md §29）。

- 參數檢查（ENABLE_LIVE_LAB_TESTS、規格、結果目錄的名稱）排在啟動 stack 之前。
- bench 沒有自己的 recipe：建立、測試與清理完全沿用 test-live-runner（同一個隔離專案與範圍），
  不新增任何清理或 Docker 指令。
- bench-check 與 bench-evaluate 是離線的：不碰 Docker、compose 或刪除檔案。
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
LINES = MAKEFILE.splitlines()
OFFLINE_FORBIDDEN = ("docker", "compose", "rm ", "down", "pytest", "ENABLE_LIVE_LAB_TESTS")


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


def _variables(target: str) -> dict[str, str]:
    prefix = f"{target}: "
    pairs = [
        line[len(prefix) :].split(" := ", 1)
        for line in LINES
        if line.startswith(prefix) and " := " in line
    ]
    return {pair[0]: pair[1] for pair in pairs}


def test_bench_checks_everything_before_the_live_stack_and_has_no_recipe() -> None:
    prerequisites, recipe = _rule("bench")

    assert prerequisites == ["bench-live-check", "bench-check", "test-live-runner"]
    assert recipe == []


def test_bench_only_runs_the_bench_test_with_its_own_environment() -> None:
    variables = _variables("bench")

    assert variables["LIVE_TESTS"] == "tests/live/test_bench_live.py"
    assert variables["LIVE_PYTEST_ENV"] == (
        'BENCH_SPEC="$(BENCH_SPEC)" BENCH_RESULTS_DIR="$(BENCH_RESULTS)/$(BENCH_NAME)"'
    )
    assert set(variables) == {"LIVE_TESTS", "LIVE_PYTEST_ENV", "LIVE_PYTEST_ARGS"}


def test_the_live_gate_is_checked_first() -> None:
    _, recipe = _rule("bench-live-check")

    [line] = recipe
    assert line.startswith('\t@[ "$$ENABLE_LIVE_LAB_TESTS" = 1 ] || {')
    assert line.endswith("exit 1; }")


def test_the_offline_targets_do_not_touch_docker_or_files() -> None:
    for target in ("bench-check", "bench-evaluate"):
        prerequisites, recipe = _rule(target)
        assert prerequisites == []
        text = "\n".join(recipe)
        assert "benchmarks.cli" in text
        for word in OFFLINE_FORBIDDEN:
            assert word not in text, (target, word)


def test_results_stay_in_the_ignored_directory() -> None:
    assert "BENCH_RESULTS := $(CURDIR)/benchmarks/results" in MAKEFILE
    assert "benchmarks/results/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()


def test_the_bench_targets_are_phony() -> None:
    phony = MAKEFILE.split(".PHONY:", 1)[1].split("\n\n", 1)[0]

    for target in ("bench-check", "bench-live-check", "bench", "bench-evaluate"):
        assert f" {target}" in phony.replace("\\\n", " ").replace("\t", " ")
