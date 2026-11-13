"""make env 補齊本機 .env 的規則（KEY-05；docs/DECISIONS.md §30.2）。

以 repo 的 Makefile 在 pytest 的暫存目錄中執行 make env（工作目錄是暫存目錄，所以只寫那裡的 .env），
不碰 repo 根目錄真正的 .env。

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
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
# DB_OWNER_PASSWORD：migration 的 owner 角色（T23b-b1；ROLE-07）。
LOCAL_SECRETS = ("DB_PASSWORD", "DB_ADMIN_PASSWORD", "TEST_DB_PASSWORD", "DB_OWNER_PASSWORD")
KEY_NAMES = ("SECRET_ENCRYPTION_KEYS", "EVIDENCE_ENCRYPTION_KEYS", "CONTENT_ENCRYPTION_KEYS")
GENERATED = "已在 .env 產生"
# 既有的金鑰（固定的測試值，不是真的金鑰）：make env 不得改動它。
EXISTING_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()


def _make_env(directory: Path) -> subprocess.CompletedProcess[str]:
    make = shutil.which("make")
    assert make is not None, "需要 make"
    assert shutil.which("openssl") is not None, "make env 需要 openssl"
    return subprocess.run(  # noqa: S603 - 固定的 make 與 Makefile；工作目錄是 pytest 的暫存目錄
        [make, "--no-print-directory", "-f", str(MAKEFILE), "env"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(directory), "LC_ALL": "C"},
    )


def _values(env_file: Path) -> dict[str, str]:
    lines = env_file.read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if line and not line.startswith("#"))


def test_a_fresh_env_gets_every_secret_and_three_distinct_keys(tmp_path: Path) -> None:
    result = _make_env(tmp_path)
    env_file = tmp_path / ".env"

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


def test_a_second_run_changes_nothing(tmp_path: Path) -> None:
    assert _make_env(tmp_path).returncode == 0
    before = (tmp_path / ".env").read_bytes()

    again = _make_env(tmp_path)

    assert again.returncode == 0, again.stdout + again.stderr
    assert (tmp_path / ".env").read_bytes() == before
    assert GENERATED not in again.stdout


def test_existing_values_are_kept_and_only_missing_keys_are_appended(tmp_path: Path) -> None:
    """dotenv 也接受 export 前綴與等號前後的空白；最後一行沒有換行時先補上。"""
    env_file = tmp_path / ".env"
    original = f"export SECRET_ENCRYPTION_KEYS = {EXISTING_KEY}\nDB_PASSWORD=keep-me"
    env_file.write_text(original, encoding="utf-8")

    result = _make_env(tmp_path)

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


def _values_from(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if line)


@pytest.mark.parametrize("key", [*KEY_NAMES, "DB_PASSWORD"])
def test_an_empty_value_stops_before_anything_is_written(tmp_path: Path, key: str) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f"DB_ADMIN_PASSWORD=keep-me\n{key}=  \n", encoding="utf-8")
    before = env_file.read_bytes()

    result = _make_env(tmp_path)

    assert result.returncode != 0
    assert key in result.stdout
    assert env_file.read_bytes() == before


def test_the_permissions_are_tightened(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    env_file.chmod(0o644)

    assert _make_env(tmp_path).returncode == 0
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


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
