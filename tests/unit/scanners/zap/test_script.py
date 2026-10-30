"""掃描的 script 實際以 dash 執行（docs/DECISIONS.md §18.2；審查 M1）。

容器的路徑（/scan/、/zap/zap.sh）換成暫存目錄與一個記下環境與參數的替身；其他字元不動，
所以測的是 sha256 核准的同一份邏輯。映像的 /bin/sh 是 dash（macOS 的 /bin/sh 是 bash，要用
/bin/dash）。
"""

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from secscan.scanners.domain.zap.script import (
    LOG_FILE,
    OUTPUT_UNWRITABLE,
    SCAN_SCRIPT,
    WRAPPER_REFUSED,
)

DASH = shutil.which("dash")
pytestmark = pytest.mark.skipif(DASH is None, reason="沒有 dash")

HEADER = "Authorization: Bearer t0k$en `x` \\n"
STUB = """#!/bin/sh
env | grep '^ZAP_AUTH' | sort
echo "args: $*"
"""


@dataclass(frozen=True)
class Result:
    code: int
    log: str | None


def _run(tmp_path: Path, env: dict[str, str], *, header: str | None) -> Result:
    root = tmp_path / "scan"
    for name in ("in", "out", "secret"):
        (root / name).mkdir(parents=True, exist_ok=True)
    if header is not None:
        (root / "secret" / "auth-header").write_text(header, encoding="utf-8")
    stub = tmp_path / "zap" / "zap.sh"
    stub.parent.mkdir(exist_ok=True)
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(stat.S_IRWXU)
    script = SCAN_SCRIPT.replace("/scan/", f"{root}/").replace("/zap/zap.sh", str(stub))
    assert DASH is not None
    completed = subprocess.run(  # noqa: S603
        [DASH, "-c", script],
        env={"PATH": os.defpath, **env},
        capture_output=True,
        check=False,
    )
    log = root / "out" / LOG_FILE
    return Result(completed.returncode, log.read_text(encoding="utf-8") if log.exists() else None)


def _header_env(**overrides: str) -> dict[str, str]:
    return {
        "SECSCAN_TARGET_AUTH": "header",
        "ZAP_AUTH_HEADER": "Authorization",
        "ZAP_AUTH_HEADER_SITE": "lab-web",
        **overrides,
    }


def test_anonymous_runs_zap_silently_without_any_auth_variable(tmp_path: Path) -> None:
    env = {"SECSCAN_TARGET_AUTH": "none", "ZAP_AUTH_HEADER_VALUE": "leak", "ZAP_AUTH_HEADER": "X"}

    result = _run(tmp_path, env, header=None)

    assert result.code == 0
    assert result.log is not None
    assert "ZAP_AUTH" not in result.log
    assert " -cmd -silent -nostdout " in result.log
    assert "-configfile " in result.log
    assert "-autorun " in result.log


def test_anonymous_with_a_secret_file_is_refused(tmp_path: Path) -> None:
    result = _run(tmp_path, {"SECSCAN_TARGET_AUTH": "none"}, header=HEADER)

    assert (result.code, result.log) == (WRAPPER_REFUSED, None)


@pytest.mark.parametrize("ending", ["", "\n"])
def test_header_mode_exports_the_value_exactly(tmp_path: Path, ending: str) -> None:
    result = _run(tmp_path, _header_env(), header=HEADER + ending)

    assert result.code == 0
    assert result.log is not None
    assert "ZAP_AUTH_HEADER_VALUE=Bearer t0k$en `x` \\n\n" in result.log
    assert "ZAP_AUTH_HEADER=Authorization\n" in result.log
    assert "ZAP_AUTH_HEADER_SITE=lab-web\n" in result.log


@pytest.mark.parametrize(
    ("env", "header"),
    [
        (_header_env(), None),
        (_header_env(), "X-Api-Key: abc"),
        (_header_env(), "Authorization: "),
        (_header_env(), "Authorization:Bearer abc"),
        (_header_env(ZAP_AUTH_HEADER=""), HEADER),
        (_header_env(ZAP_AUTH_HEADER_SITE=""), HEADER),
        ({"SECSCAN_TARGET_AUTH": "header", "ZAP_AUTH_HEADER": "Authorization"}, HEADER),
        ({"SECSCAN_TARGET_AUTH": "basic"}, HEADER),
        ({}, None),
    ],
)
def test_inconsistent_modes_and_files_are_refused(
    tmp_path: Path, env: dict[str, str], header: str | None
) -> None:
    assert _run(tmp_path, env, header=header) == Result(WRAPPER_REFUSED, None)


def test_an_unwritable_output_directory_stops_before_zap(tmp_path: Path) -> None:
    out = tmp_path / "scan" / "out"
    out.mkdir(parents=True)
    out.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        result = _run(tmp_path, {"SECSCAN_TARGET_AUTH": "none"}, header=None)
    finally:
        out.chmod(stat.S_IRWXU)

    assert (result.code, result.log) == (OUTPUT_UNWRITABLE, None)
