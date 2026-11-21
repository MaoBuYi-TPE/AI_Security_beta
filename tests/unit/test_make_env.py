"""make env 補齊本機 .env 的規則（KEY-05；docs/DECISIONS.md §30.2）。

實際執行 `make env` 的測試都在 pytest 的暫存目錄建立 sandbox：假的 repo 只有 repo 的 Makefile 的
複本，工作目錄與 HOME 各自分開；以 -f 指定複本、在工作目錄執行。repo 的 Makefile 不直接執行（只唯讀
解析 recipe），Makefile 所在的目錄（REPO_DIR）不是 repo；.env 只出現在工作目錄。repo 根目錄真正的
.env 只比對前後的非明文事實（lstat），不讀內容。

- 冪等：只附加缺少的秘密與金鑰，不覆寫、重設或輪替既有的值。
- 任何一個是空值時，在寫入之前就停止。
- 三組加密金鑰各自以 openssl 產生（url-safe base64 的 32 bytes），互不相同。
- 產生的值只寫進 .env，終端只顯示名稱；.env 維持 600。
"""

import base64
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
# repo 根目錄真正的 .env：測試只確認它沒有改變（lstat 的事實，不讀內容）。
REPO_ENV = ROOT / ".env"
# DB_OWNER_PASSWORD：migration 的 owner 角色（T23b-b1；ROLE-07）。
LOCAL_SECRETS = ("DB_PASSWORD", "DB_ADMIN_PASSWORD", "TEST_DB_PASSWORD", "DB_OWNER_PASSWORD")
KEY_NAMES = ("SECRET_ENCRYPTION_KEYS", "EVIDENCE_ENCRYPTION_KEYS", "CONTENT_ENCRYPTION_KEYS")
GENERATED = "已在 .env 產生"
# 既有的金鑰（固定的測試值，不是真的金鑰）：make env 不得改動它。
EXISTING_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()


def _facts(path: Path) -> tuple[int, ...] | str:
    """lstat 的非明文事實（不跟隨 symlink，不讀內容）；不存在時只記錄不存在。

    內容的任何寫入（含 touch）都會改變 mtime 與 ctime，chmod 會改變 mode 與 ctime，原子替換會改變
    inode，所以不需要讀 .env 就能確認沒有改變。
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent"
    return (
        info.st_mode,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@dataclass(frozen=True)
class _Sandbox:
    """一項測試的 make 環境：假的 repo（只有 Makefile 的複本）、工作目錄與 HOME 彼此分開。"""

    makefile: Path
    work: Path
    home: Path
    # 建立 sandbox 時 repo 的 .env 的非明文事實（_assert_confined 比對）。
    repo_env: tuple[int, ...] | str


def _sandbox(base: Path) -> _Sandbox:
    """在 pytest 的暫存目錄建立 sandbox；同一項測試的每次 make 都用同一個（同一份 Makefile 複本）。

    HOME 和工作目錄分開：寫到 ~/.env 的回歸不會被當成寫進工作目錄。
    """
    repo, work, home = base / "repo", base / "work", base / "home"
    for directory in (repo, work, home):
        directory.mkdir()
    shutil.copy2(MAKEFILE, repo / "Makefile")
    return _Sandbox(repo / "Makefile", work, home, _facts(REPO_ENV))


def _make_env(box: _Sandbox) -> subprocess.CompletedProcess[str]:
    """以 sandbox 的 Makefile 複本、在它的工作目錄執行 make env；沒有預設的 Makefile。"""
    # 防護：複本、工作目錄與 HOME 都不在 repo 中，REPO_DIR 與相對路徑的 .env 都碰不到 repo 的 .env。
    repo_dir = MAKEFILE.parent.resolve()
    for path in (box.makefile, box.work, box.home):
        assert not path.resolve().is_relative_to(repo_dir), "sandbox 必須在 repo 之外"
    make = shutil.which("make")
    assert make is not None, "需要 make"
    assert shutil.which("openssl") is not None, "make env 需要 openssl"
    return subprocess.run(  # noqa: S603 - 固定的 make 與 Makefile 的複本；工作目錄在 sandbox 中
        [make, "--no-print-directory", "-f", str(box.makefile), "env"],
        cwd=box.work,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(box.home), "LC_ALL": "C"},
    )


def _assert_confined(box: _Sandbox) -> None:
    """make env 只寫入工作目錄的 .env：假的 repo 只有 Makefile 的複本、HOME 是空的、暫存目錄沒有
    多出的項目，repo 的 .env 和建立 sandbox 時的非明文事實相同。"""
    assert sorted(path.name for path in box.makefile.parent.iterdir()) == ["Makefile"]
    assert sorted(path.name for path in box.work.iterdir()) == [".env"]
    assert list(box.home.iterdir()) == []
    assert sorted(path.name for path in box.work.parent.iterdir()) == ["home", "repo", "work"]
    assert _facts(REPO_ENV) == box.repo_env


def _values(env_file: Path) -> dict[str, str]:
    lines = env_file.read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if line and not line.startswith("#"))


def test_a_fresh_env_gets_every_secret_and_three_distinct_keys(tmp_path: Path) -> None:
    box = _sandbox(tmp_path)

    result = _make_env(box)
    env_file = box.work / ".env"

    assert result.returncode == 0, result.stdout + result.stderr
    values = _values(env_file)
    assert set(values) == {*LOCAL_SECRETS, *KEY_NAMES}
    for key in KEY_NAMES:
        assert len(values[key]) == 44, key
        assert len(base64.urlsafe_b64decode(values[key])) == 32, key
    assert len({values[key] for key in KEY_NAMES}) == len(KEY_NAMES)
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    output = result.stdout + result.stderr
    for key, value in values.items():
        assert key in output
        assert value not in output, key
    _assert_confined(box)


def test_a_second_run_changes_nothing(tmp_path: Path) -> None:
    box = _sandbox(tmp_path)
    env_file = box.work / ".env"
    assert _make_env(box).returncode == 0
    before = env_file.read_bytes()

    again = _make_env(box)

    assert again.returncode == 0, again.stdout + again.stderr
    assert env_file.read_bytes() == before
    assert GENERATED not in again.stdout
    _assert_confined(box)


def test_existing_values_are_kept_and_only_missing_keys_are_appended(tmp_path: Path) -> None:
    """dotenv 也接受 export 前綴與等號前後的空白；最後一行沒有換行時先補上。"""
    box = _sandbox(tmp_path)
    env_file = box.work / ".env"
    original = f"export SECRET_ENCRYPTION_KEYS = {EXISTING_KEY}\nDB_PASSWORD=keep-me"
    env_file.write_text(original, encoding="utf-8")

    result = _make_env(box)

    assert result.returncode == 0, result.stdout + result.stderr
    text = env_file.read_text(encoding="utf-8")
    assert text.startswith(original + "\n")
    appended = _values_from(text[len(original) + 1 :])
    assert set(appended) == {
        "DB_ADMIN_PASSWORD",
        "TEST_DB_PASSWORD",
        "DB_OWNER_PASSWORD",
        *KEY_NAMES[1:],
    }
    assert text.count("SECRET_ENCRYPTION_KEYS") == 1
    assert [line for line in text.splitlines() if line.startswith("DB_PASSWORD=")] == [
        "DB_PASSWORD=keep-me"
    ]
    assert EXISTING_KEY not in result.stdout
    _assert_confined(box)


def _values_from(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if line)


@pytest.mark.parametrize("key", [*KEY_NAMES, "DB_PASSWORD"])
def test_an_empty_value_stops_before_anything_is_written(tmp_path: Path, key: str) -> None:
    box = _sandbox(tmp_path)
    env_file = box.work / ".env"
    env_file.write_text(f"DB_ADMIN_PASSWORD=keep-me\n{key}=  \n", encoding="utf-8")
    before = env_file.read_bytes()

    result = _make_env(box)

    assert result.returncode != 0
    assert key in result.stdout
    assert env_file.read_bytes() == before
    _assert_confined(box)


def test_the_permissions_are_tightened(tmp_path: Path) -> None:
    box = _sandbox(tmp_path)
    env_file = box.work / ".env"
    env_file.write_text("", encoding="utf-8")
    env_file.chmod(0o644)

    assert _make_env(box).returncode == 0
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    _assert_confined(box)


def test_generated_values_go_only_into_the_file() -> None:
    """recipe 中出現產生的值（$$value、$$secret）的每一行，只能是產生、檢查長度或附加到 .env。"""
    lines = MAKEFILE.read_text(encoding="utf-8").splitlines()
    start = lines.index("env:")
    recipe = []
    for line in lines[start + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line)
    uses = [line for line in recipe if "$$value" in line or "$$secret" in line]

    assert uses
    for line in uses:
        assert ">> .env" in line or "$$(openssl rand" in line or "$${#" in line, line
    assert "rand -base64 32" in "\n".join(recipe)
