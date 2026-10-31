"""Run the live cleanup shell with a Docker stub, without touching the Docker daemon."""

import os
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tests/live/guard_paths_cleanup.sh"
STEPS = (
    "ps-capture",
    "rm-capture",
    "ps-receivers",
    "rm-receivers",
    "ps-scan",
    "rm-scan",
    "ps-lab",
    "rm-lab",
    "compose-down",
    "network-scan",
    "network-lab",
)
STUB = """#!/bin/sh
case "$*" in
  'ps -aq --filter name=secscan-live-t33-capture-') step=ps-capture; output=capture-id ;;
  'ps -aq --filter name=secscan-live-t11-t33-') step=ps-receivers; output=receivers-id ;;
  'rm -f -v receivers-id') step=rm-receivers ;;
  'ps -aq --filter network=scan') step=ps-scan; output=scan-id ;;
  'ps -aq --filter network=lab') step=ps-lab; output=lab-id ;;
  'rm -f -v capture-id') step=rm-capture ;;
  'rm -f -v scan-id') step=rm-scan ;;
  'rm -f -v lab-id') step=rm-lab ;;
  'compose down -v --remove-orphans') step=compose-down ;;
  'network rm scan') step=network-scan ;;
  'network rm lab') step=network-lab ;;
  *) exit 99 ;;
esac
printf '%s\\n' "$step" >> "$CALLS"
case ",${FAIL_STEPS}," in *",${step},"*) exit 31 ;; esac
[ -z "$output" ] || printf '%s\\n' "$output"
exit 0
"""


def _cleanup(tmp_path: Path, *, original: int, failures: tuple[str, ...]) -> tuple[int, list[str]]:
    stub = tmp_path / "docker"
    stub.write_text(STUB)
    stub.chmod(0o700)
    calls = tmp_path / "calls"
    result = subprocess.run(  # noqa: S603 - fixed shell script and controlled Docker stub
        [
            "/bin/sh",
            "-c",
            "live_compose_down() { docker compose down -v --remove-orphans; }; "
            '. "$1"; cleanup_guard_paths "$2" scan lab',
            "cleanup-test",
            str(SCRIPT),
            str(original),
        ],
        env={
            **os.environ,
            "PATH": f"{tmp_path}:/usr/bin:/bin",
            "CALLS": str(calls),
            "FAIL_STEPS": ",".join(failures),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, calls.read_text().splitlines() if calls.exists() else []


@pytest.mark.parametrize("failure", STEPS)
def test_cleanup_failure_fails_an_otherwise_successful_run(tmp_path: Path, failure: str) -> None:
    status, calls = _cleanup(tmp_path, original=0, failures=(failure,))

    assert status != 0
    assert failure in calls
    # A failed inventory has no IDs to delete, but must not prevent remaining cleanup.
    expected = [
        step
        for step in STEPS
        if step != failure.replace("ps-", "rm-") or not failure.startswith("ps-")
    ]
    assert calls == expected


def test_successful_cleanup_returns_success(tmp_path: Path) -> None:
    assert _cleanup(tmp_path, original=0, failures=()) == (0, list(STEPS))


@pytest.mark.parametrize("original", [1, 7, 130])
def test_cleanup_preserves_the_original_failure_and_attempts_every_remaining_step(
    tmp_path: Path, original: int
) -> None:
    status, calls = _cleanup(
        tmp_path, original=original, failures=("rm-capture", "compose-down", "network-scan")
    )

    assert status == original
    assert calls == list(STEPS)


def test_multiple_cleanup_failures_do_not_hide_each_other(tmp_path: Path) -> None:
    status, calls = _cleanup(
        tmp_path, original=0, failures=("ps-capture", "rm-scan", "compose-down", "network-scan")
    )

    assert status != 0
    assert calls == [step for step in STEPS if step != "rm-capture"]


def test_the_real_recipe_uses_the_tested_cleanup() -> None:
    recipe = (ROOT / "Makefile").read_text().split("test-live-guard-paths: env", 1)[1]

    assert ". tests/live/guard_paths_cleanup.sh" in recipe
    install = "guard_paths_install_cleanup $(LIVE_SCAN_NET) $(LIVE_LAB_NET)"
    assert install in recipe
    assert recipe.index(install) < recipe.index("$(MAKE) --no-print-directory scan-net")
    assert recipe.index(install) < recipe.index("$(LIVE_COMPOSE) up -d --wait db")
    assert recipe.rstrip().endswith('exit "$$status"')
    assert "live_compose_down() { $(LIVE_COMPOSE) down -v --remove-orphans; }" in recipe


def _trapped_cleanup(
    tmp_path: Path, *, signal_number: int | None, original: int, failures: tuple[str, ...]
) -> tuple[int, list[str]]:
    import signal

    stub = tmp_path / "docker"
    stub.write_text(STUB)
    stub.chmod(0o700)
    calls = tmp_path / "calls"
    commands = (
        "live_compose_down() { docker compose down -v --remove-orphans; }; "
        '. "$1"; status=$2; guard_paths_install_cleanup scan lab; '
    )
    if signal_number is not None:
        commands += (
            '"$3" -c ' + "\"import time; print('phase-ready', flush=True); time.sleep(30)\"; "
        )
    commands += 'exit "$status"'
    process = subprocess.Popen(  # noqa: S603 - fixed shell and controlled Docker stub
        [
            sys.executable,
            "-c",
            "import os, signal, sys; "
            "signal.signal(signal.SIGINT, signal.SIG_DFL); "
            "signal.signal(signal.SIGTERM, signal.SIG_DFL); "
            "os.execv('/bin/sh', ['/bin/sh', *sys.argv[1:]])",
            "-c",
            commands,
            "signal-test",
            str(SCRIPT),
            str(original),
            sys.executable,
        ],
        env={
            **os.environ,
            "PATH": f"{tmp_path}:/usr/bin:/bin",
            "CALLS": str(calls),
            "FAIL_STEPS": ",".join(failures),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        if signal_number is not None:
            assert process.stdout is not None
            assert process.stdout.readline().strip() == "phase-ready"
            os.killpg(process.pid, signal_number)
        process.communicate(timeout=10)
    finally:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=5)
    return process.returncode, calls.read_text().splitlines() if calls.exists() else []


@pytest.mark.parametrize("signal_number", [2, 15], ids=["SIGINT", "SIGTERM"])
@pytest.mark.parametrize("original", [0, 7])
@pytest.mark.parametrize("failures", [(), ("rm-capture", "compose-down", "network-scan")])
def test_real_process_group_signal_cleans_once_and_preserves_failure(
    tmp_path: Path, signal_number: int, original: int, failures: tuple[str, ...]
) -> None:
    status, calls = _trapped_cleanup(
        tmp_path, signal_number=signal_number, original=original, failures=failures
    )

    assert status == (original or 128 + signal_number)
    assert calls == list(STEPS)


@pytest.mark.parametrize(
    ("original", "failures", "expected"),
    [
        (0, (), 0),
        (0, ("compose-down",), 1),
        (7, ("compose-down",), 7),
    ],
)
def test_exit_trap_returns_the_cleanup_result(
    tmp_path: Path, original: int, failures: tuple[str, ...], expected: int
) -> None:
    status, calls = _trapped_cleanup(
        tmp_path, signal_number=None, original=original, failures=failures
    )

    assert status == expected
    assert calls == list(STEPS)
