"""make secrets 與開發的 compose 呼叫（CSEC-05；T23b-b2，docs/DECISIONS.md §32）。

- 實際執行 `make secrets` 的測試都在 pytest 的暫存目錄建立 sandbox：假的 repo 只有 repo 的
  Makefile 的複本，工作目錄與 HOME 各自分開；以 -f 指定複本、在工作目錄執行（UV_RUN= 並把 venv
  放進 PATH；env 以 -o 略過，.env 是工作目錄中的 canary）。repo 的 Makefile 不直接執行，Makefile
  所在的目錄（REPO_DIR）不是 repo；secrets/ 只出現在工作目錄。repo 的 secrets/（G2 之後合法存在）
  只比對前後的非明文事實，不讀內容。
- 靜態檢查：哪些目標依賴 secrets；所有以 compose.yaml 執行的開發目標都由同一個變數設定
  SECSCAN_SECRETS_DIR（D16），不受 shell 中同名變數的影響。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from secscan.cli.secret_files import SECRET_FILES

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE_PATH = ROOT / "Makefile"
MAKEFILE = MAKEFILE_PATH.read_text(encoding="utf-8")
# repo 的秘密檔目錄：G2 之後合法存在（make test 也會先執行 make secrets），測試只確認它沒有改變。
REPO_SECRETS = ROOT / "secrets"
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


def _facts(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_mode,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _tree_facts(directory: Path) -> tuple[object, ...]:
    """目錄與其中每個項目的非明文事實（lstat：不跟隨 symlink，不讀內容）。

    內容的任何寫入都會改變 mtime 與 ctime，原子替換會改變 inode，新增、刪除會改變名稱與目錄本身，
    所以不需要讀秘密檔的內容就能確認沒有改變。目錄不存在時只記錄不存在。
    """
    try:
        top = directory.lstat()
    except FileNotFoundError:
        return ("absent",)
    if not stat.S_ISDIR(top.st_mode):
        return (_facts(top),)
    entries = tuple((entry.name, *_facts(entry.lstat())) for entry in sorted(directory.iterdir()))
    return (_facts(top), entries)


@dataclass(frozen=True)
class _Sandbox:
    """一項測試的 make 環境：假的 repo（只有 Makefile 的複本）、工作目錄與 HOME 彼此分開。"""

    makefile: Path
    work: Path
    home: Path
    # 建立 sandbox 時 repo 的 secrets/ 的非明文事實（_assert_confined 比對）。
    repo_secrets: tuple[object, ...]


def _sandbox(base: Path) -> _Sandbox:
    """在 pytest 的暫存目錄建立 sandbox；同一項測試的每次 make 都用同一個（同一份 Makefile 複本）。

    HOME 和工作目錄分開：寫到 ~/secrets 的回歸不會被當成寫進工作目錄。
    """
    repo, work, home = base / "repo", base / "work", base / "home"
    for directory in (repo, work, home):
        directory.mkdir()
    shutil.copy2(MAKEFILE_PATH, repo / "Makefile")
    return _Sandbox(repo / "Makefile", work, home, _tree_facts(REPO_SECRETS))


def _make(box: _Sandbox, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    """以 sandbox 的 Makefile 複本、在它的工作目錄執行 make；沒有預設的 Makefile。"""
    # 防護：複本、工作目錄與 HOME 都不在 repo 中，REPO_DIR 與 --dir secrets 都碰不到
    # repo 的 secrets/。
    repo_dir = MAKEFILE_PATH.parent.resolve()
    for path in (box.makefile, box.work, box.home):
        assert not path.resolve().is_relative_to(repo_dir), "sandbox 必須在 repo 之外"
    make = shutil.which("make")
    assert make is not None, "需要 make"
    venv_bin = str(Path(sys.executable).parent)
    # 固定的 make 與 Makefile 的複本；env 以 -o 略過（.env 已由測試寫好）。PATH、HOME、LC_ALL
    # 放在最後：測試傳入的變數不會改掉 sandbox 的 HOME。
    return subprocess.run(  # noqa: S603
        [make, "--no-print-directory", "-f", str(box.makefile), "-o", "env", "UV_RUN=", *args],
        cwd=box.work,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            **env,
            "PATH": f"{venv_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(box.home),
            "LC_ALL": "C.UTF-8",
        },
    )


def _assert_confined(box: _Sandbox) -> None:
    """make 只寫入工作目錄：假的 repo 只有 Makefile 的複本、HOME 是空的、暫存目錄沒有多出的
    項目，repo 的 secrets/ 和建立 sandbox 時的非明文事實相同。"""
    assert sorted(path.name for path in box.makefile.parent.iterdir()) == ["Makefile"]
    assert sorted(path.name for path in box.work.iterdir()) == [".env", "secrets"]
    assert list(box.home.iterdir()) == []
    assert sorted(path.name for path in box.work.parent.iterdir()) == ["home", "repo", "work"]
    assert _tree_facts(REPO_SECRETS) == box.repo_secrets


def test_make_secrets_writes_the_files_without_showing_values(tmp_path: Path) -> None:
    """secrets/ 只建立在工作目錄：不寫進 Makefile 所在的目錄（假的 repo）、HOME 或暫存目錄的其他
    位置，repo 的 secrets/ 前後的非明文事實相同。"""
    box = _sandbox(tmp_path)
    values = _write_env(box.work)

    result = _make(box, "secrets")

    output = result.stdout + result.stderr
    assert result.returncode == 0, [name for name, value in values.items() if value in output]
    directory = box.work / "secrets"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert sorted(path.name for path in directory.iterdir()) == sorted(
        item.file_name for item in SECRET_FILES
    )
    for item in SECRET_FILES:
        path = directory / item.file_name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_bytes() == values[item.env_name].encode()
    assert [name for name, value in values.items() if value in output] == []
    _assert_confined(box)


def test_secrets_check_detects_a_difference_without_writing(tmp_path: Path) -> None:
    box = _sandbox(tmp_path)
    _write_env(box.work)
    assert _make(box, "secrets").returncode == 0
    assert _make(box, "secrets", "SECRETS_CHECK=1").returncode == 0
    changed = box.work / "secrets" / "db_password"
    changed.write_text("x" * 48, encoding="ascii")

    result = _make(box, "secrets", "SECRETS_CHECK=1")

    assert result.returncode != 0
    assert "db_password" in result.stdout + result.stderr
    assert changed.read_text(encoding="ascii") == "x" * 48
    _assert_confined(box)


def test_a_generic_check_variable_does_not_switch_to_check_mode(tmp_path: Path) -> None:
    """變數名稱是 SECRETS_CHECK：shell 中常見的 CHECK 不會讓 make secrets 靜默改成只檢查。"""
    box = _sandbox(tmp_path)
    _write_env(box.work)

    result = _make(box, "secrets", CHECK="1")

    assert result.returncode == 0
    assert (box.work / "secrets" / "db_password").exists()
    _assert_confined(box)


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
