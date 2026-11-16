"""make secrets 與開發的 compose 呼叫（CSEC-05；T23b-b2，docs/DECISIONS.md §32）。

- 以 repo 的 Makefile 在 pytest 的暫存目錄中實際執行 `make secrets`（UV_RUN= 並把 venv 放進 PATH；
  env 以 -o 略過，.env 是暫存目錄中的 canary）：secrets/ 建立在暫存目錄，不碰 repo 的 secrets/。
- 靜態檢查：哪些目標依賴 secrets；所有以 compose.yaml 執行的開發目標都由同一個變數設定
  SECSCAN_SECRETS_DIR（D16），不受 shell 中同名變數的影響。
"""

import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from secscan.cli.secret_files import SECRET_FILES

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE_PATH = ROOT / "Makefile"
MAKEFILE = MAKEFILE_PATH.read_text(encoding="utf-8")
# 依賴 secrets 的目標（G0 的 S4、S5：up 會建立掛載它的容器；runs-layout-migrate 以
# compose run 掛載）。
NEEDS_SECRETS = ("db-up", "test-db-up", "up", "runs-layout-migrate")
# 不需要秘密檔的目標（S4：config、build、pull、down 不檢查檔案是否存在）。
NO_SECRETS = ("build", "images", "down", "db-down")


def _prerequisites(target: str) -> list[str]:
    match = re.search(rf"^{re.escape(target)}:(?!=)(.*)$", MAKEFILE, flags=re.MULTILINE)
    assert match is not None, target
    return match.group(1).split()


def _recipe(target: str) -> str:
    match = re.search(rf"^{re.escape(target)}:(?!=).*\n((?:\t.*\n)+)", MAKEFILE, flags=re.MULTILINE)
    assert match is not None, target
    return match.group(1)


def _write_env(directory: Path) -> dict[str, str]:
    values = {
        item.env_name: Fernet.generate_key().decode()
        if item.kind == "keys"
        else secrets.token_hex(24)
        for item in SECRET_FILES
    }
    (directory / ".env").write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8"
    )
    return values


def _make(directory: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    make = shutil.which("make")
    assert make is not None, "需要 make"
    venv_bin = str(Path(sys.executable).parent)
    # 固定的 make 與 repo 的 Makefile；env 以 -o 略過（.env 已由測試寫好）。
    return subprocess.run(  # noqa: S603
        [make, "--no-print-directory", "-f", str(MAKEFILE_PATH), "-o", "env", "UV_RUN=", *args],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            "PATH": f"{venv_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(directory),
            "LC_ALL": "C.UTF-8",
            **env,
        },
    )


def test_make_secrets_writes_the_files_without_showing_values(tmp_path: Path) -> None:
    values = _write_env(tmp_path)

    result = _make(tmp_path, "secrets")

    output = result.stdout + result.stderr
    assert result.returncode == 0, [name for name, value in values.items() if value in output]
    directory = tmp_path / "secrets"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for item in SECRET_FILES:
        path = directory / item.file_name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_bytes() == values[item.env_name].encode()
    assert [name for name, value in values.items() if value in output] == []
    assert not (ROOT / "secrets").exists()


def test_secrets_check_detects_a_difference_without_writing(tmp_path: Path) -> None:
    _write_env(tmp_path)
    assert _make(tmp_path, "secrets").returncode == 0
    assert _make(tmp_path, "secrets", "SECRETS_CHECK=1").returncode == 0
    changed = tmp_path / "secrets" / "db_password"
    changed.write_text("x" * 48, encoding="ascii")

    result = _make(tmp_path, "secrets", "SECRETS_CHECK=1")

    assert result.returncode != 0
    assert "db_password" in result.stdout + result.stderr
    assert changed.read_text(encoding="ascii") == "x" * 48


def test_a_generic_check_variable_does_not_switch_to_check_mode(tmp_path: Path) -> None:
    """變數名稱是 SECRETS_CHECK：shell 中常見的 CHECK 不會讓 make secrets 靜默改成只檢查。"""
    _write_env(tmp_path)

    result = _make(tmp_path, "secrets", CHECK="1")

    assert result.returncode == 0
    assert (tmp_path / "secrets" / "db_password").exists()


def test_secrets_is_phony_and_depends_on_env() -> None:
    phony = re.search(r"^\.PHONY:((?:.*\\\n)*.*)$", MAKEFILE, flags=re.MULTILINE)
    assert phony is not None

    assert "secrets" in phony.group(1).replace("\\\n", " ").split()
    assert _prerequisites("secrets") == ["env"]
    assert "sync-secret-files --dir secrets $(if $(SECRETS_CHECK),--check,)" in _recipe("secrets")


@pytest.mark.parametrize("target", NEEDS_SECRETS)
def test_targets_that_start_containers_sync_the_secrets_first(target: str) -> None:
    prerequisites = _prerequisites(target)

    assert "secrets" in prerequisites
    assert prerequisites.index("env") < prerequisites.index("secrets")


@pytest.mark.parametrize("target", NO_SECRETS)
def test_targets_that_start_nothing_do_not_need_the_secrets(target: str) -> None:
    assert "secrets" not in _prerequisites(target)


def test_every_development_compose_call_sets_the_secrets_directory() -> None:
    """D16：開發的 compose 呼叫都經由 DEV_COMPOSE（明確設定 SECSCAN_SECRETS_DIR=./secrets）。"""
    assert "\nDEV_SECRETS_ENV := SECSCAN_SECRETS_DIR=./secrets\n" in MAKEFILE
    assert "\nDEV_COMPOSE = $(DEV_SECRETS_ENV) $(COMPOSE) -f $(DB_FILE)\n" in MAKEFILE
    assert "\nAPP_COMPOSE = $(DEV_COMPOSE) --profile app\n" in MAKEFILE
    for line in MAKEFILE.splitlines():
        if line.startswith("\t") and "$(COMPOSE) -f $(DB_FILE)" in line:
            raise AssertionError(f"直接以 compose.yaml 執行：{line.strip()}")
