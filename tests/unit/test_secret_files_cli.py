"""secscan-admin sync-secret-files 與 generate-secret-files（CSEC-04、CSEC-12 的 generate 部分）。

每個測試在自己的暫存目錄執行：.env 與秘密都是這次產生的 canary，不碰 repo 的 .env 與 secrets/。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

import secscan.cli as cli
from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.cli import secret_files as module
from secscan.cli.secret_files import (
    DB_ROLE_WARNING,
    SECRET_FILES,
    TEMP_PREFIX,
    SecretSources,
    generate_values,
)
from secscan.core.config import ENV_FILE
from secscan.core.secret_files import MAX_SECRET_LENGTH, MIN_DB_PASSWORD_LENGTH
from secscan.security.secret_cipher import parse_keys

ROOT = Path(__file__).resolve().parents[2]
FRAGMENT_LENGTH = 8
ENV_NAMES = tuple(item.env_name for item in SECRET_FILES)
FILE_NAMES = tuple(item.file_name for item in SECRET_FILES)


def _value(env_name: str) -> str:
    item = next(item for item in SECRET_FILES if item.env_name == env_name)
    if item.kind == "keys":
        return Fernet.generate_key().decode()
    return secrets.token_hex(24)


def _leaks(text: str, values: dict[str, str]) -> list[str]:
    """text 含哪些值的任何一段長度 FRAGMENT_LENGTH 的子字串；只回傳名稱。"""
    found = []
    for name, value in values.items():
        if any(
            value[start : start + FRAGMENT_LENGTH] in text
            for start in range(len(value) - FRAGMENT_LENGTH + 1)
        ):
            found.append(name)
    return found


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.env_file = root / ".env"
        self.secrets = root / "secrets"
        self.values: dict[str, str] = {}

    def write_env(self, **overrides: str) -> None:
        self.values = {name: _value(name) for name in ENV_NAMES} | overrides
        lines = [f"{name}={value}" for name, value in self.values.items()]
        self.env_file.write_text("APP_ENV=dev\n" + "\n".join(lines) + "\n", encoding="utf-8")
        self.env_file.chmod(0o600)

    def env_digest(self) -> str:
        return hashlib.sha256(self.env_file.read_bytes()).hexdigest()

    def file(self, name: str) -> Path:
        return self.secrets / name


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Workspace:
    # conftest 讓設定類別不讀 .env；這裡還原成正式的預設值（工作目錄的 .env）來驗證它。
    monkeypatch.setitem(SecretSources.model_config, "env_file", ENV_FILE)
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    space = Workspace(tmp_path)
    space.write_env()
    return space


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(["sync-secret-files", *argv])
    out, err = capsys.readouterr()
    assert out == ""
    return code, err


# ----------------------------------------------------------------------------- sync


def test_sync_writes_each_secret_without_a_trailing_newline(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    before = workspace.env_digest()

    code, err = _run(capsys)

    assert code == EXIT_OK
    assert stat.S_IMODE(workspace.secrets.stat().st_mode) == 0o700
    for item in SECRET_FILES:
        path = workspace.file(item.file_name)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_bytes() == workspace.values[item.env_name].encode()
        assert f"{item.file_name}：新增" in err
    assert sorted(os.listdir(workspace.secrets)) == sorted(FILE_NAMES)
    assert _leaks(err, workspace.values) == []
    assert workspace.env_digest() == before


def test_sync_is_idempotent(workspace: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    _run(capsys)
    inodes = {name: workspace.file(name).stat().st_ino for name in FILE_NAMES}

    code, err = _run(capsys)

    assert code == EXIT_OK
    assert {name: workspace.file(name).stat().st_ino for name in FILE_NAMES} == inodes
    for name in FILE_NAMES:
        assert f"{name}：不變" in err
    assert DB_ROLE_WARNING not in err


def test_sync_replaces_a_changed_value_atomically_and_warns_for_db_passwords(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(capsys)
    old_inode = workspace.file("db_password").stat().st_ino
    unchanged_inode = workspace.file("content_encryption_keys").stat().st_ino
    previous = workspace.values
    workspace.write_env(**{name: previous[name] for name in ENV_NAMES if name != "DB_PASSWORD"})

    code, err = _run(capsys)

    assert code == EXIT_OK
    assert workspace.file("db_password").read_bytes() == workspace.values["DB_PASSWORD"].encode()
    assert workspace.file("db_password").stat().st_ino != old_inode
    assert stat.S_IMODE(workspace.file("db_password").stat().st_mode) == 0o600
    assert workspace.file("content_encryption_keys").stat().st_ino == unchanged_inode
    assert "db_password：更新" in err
    assert DB_ROLE_WARNING in err
    assert _leaks(err, workspace.values | {"old": previous["DB_PASSWORD"]}) == []


def test_sync_does_not_warn_for_the_test_db_password(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(capsys)
    previous = workspace.values
    workspace.write_env(**{n: previous[n] for n in ENV_NAMES if n != "TEST_DB_PASSWORD"})

    _, err = _run(capsys)

    assert "test_db_password：更新" in err
    assert DB_ROLE_WARNING not in err


def test_sync_rewrites_a_file_with_a_wider_mode(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(capsys)
    workspace.file("db_password").chmod(0o644)

    code, err = _run(capsys)

    assert code == EXIT_OK
    assert stat.S_IMODE(workspace.file("db_password").stat().st_mode) == 0o600
    # 內容沒有變：回報「修正權限」，不印出 DB 角色密碼的警告（程式碼審查 LOW-3：原本誤報「更新」）。
    assert "db_password：修正權限" in err
    assert "db_password：更新" not in err
    assert DB_ROLE_WARNING not in err


@pytest.mark.parametrize(
    "name", ["DB_OWNER_PASSWORD", "db_owner_password", "CONTENT_ENCRYPTION_KEYS"]
)
def test_a_same_named_environment_variable_is_refused(
    workspace: Workspace,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    """安全審查 L1：shell 中殘留的同名變數（不分大小寫）會讓容器與主機工具的值分歧。sync 只以
    .env 為來源：同名的環境變數存在就拒絕，不寫任何檔案、不印出值。"""
    canary = secrets.token_hex(24)
    monkeypatch.setenv(name, canary)

    code, err = _run(capsys)

    leaked = canary[:FRAGMENT_LENGTH] in err
    # 明確的原因（不是值的格式不對之類的其他原因）。
    refused_for_shadowing = "同名" in err and name.upper() in err
    assert code == EXIT_FAILURE
    assert refused_for_shadowing
    assert not leaked
    assert not workspace.secrets.exists()


def test_the_sources_are_the_dotenv_file_only(
    workspace: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """設定類別本身也不採用環境變數（即使指令的檢查被繞過，值仍然來自 .env）。"""
    monkeypatch.setenv("DB_OWNER_PASSWORD", secrets.token_hex(24))

    value = SecretSources().values()["db_owner_password"]

    from_dotenv = (
        value is not None and value.get_secret_value() == workspace.values["DB_OWNER_PASSWORD"]
    )
    assert from_dotenv


@pytest.mark.parametrize(
    "name", [item.env_name for item in SECRET_FILES if item.kind == "password"]
)
def test_db_passwords_shorter_than_initdb_accepts_are_refused(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    """安全審查 L6、程式碼審查 LOW-3、資料庫審查 LOW-1：sync 和 initdb 的長度規則一致（至少
    32）。"""
    workspace.write_env(**{name: "a" * (MIN_DB_PASSWORD_LENGTH - 1)})

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert name in err
    assert f"{MIN_DB_PASSWORD_LENGTH}" in err
    assert not workspace.secrets.exists()


def test_the_shortest_db_password_initdb_accepts_is_accepted(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace.write_env(DB_PASSWORD="a" * MIN_DB_PASSWORD_LENGTH)

    assert _run(capsys)[0] == EXIT_OK


def test_the_length_rule_is_the_same_as_initdb() -> None:
    """契約：initdb（10-roles.sql 的 awk）對 owner 與應用程式角色的密碼要求的長度，等於 sync 的
    規則。"""
    text = (ROOT / "deploy" / "postgres" / "initdb" / "10-roles.sql").read_text(encoding="utf-8")

    rules = re.findall(r"length\(\$0\) >= (\d+) && length\(\$0\) <= (\d+)", text)

    assert len(rules) == 2
    assert set(rules) == {(str(MIN_DB_PASSWORD_LENGTH), str(MAX_SECRET_LENGTH))}


@pytest.mark.parametrize(
    "bad",
    ["", "has space", "quote'd", 'quote"d', "back`tick", "é" * 40, "x" * 4096],
    ids=["empty", "space", "single-quote", "double-quote", "backtick", "non-ascii", "too-long"],
)
def test_sync_refuses_invalid_values_and_writes_nothing(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], bad: str
) -> None:
    workspace.write_env(DB_PASSWORD=bad)

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert "DB_PASSWORD" in err
    assert not workspace.secrets.exists()
    if bad:
        assert bad not in err


def test_sync_refuses_a_missing_value(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    text = workspace.env_file.read_text(encoding="utf-8")
    workspace.env_file.write_text(
        "\n".join(line for line in text.splitlines() if not line.startswith("TEST_DB_PASSWORD=")),
        encoding="utf-8",
    )

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert "TEST_DB_PASSWORD" in err
    assert not workspace.secrets.exists()


@pytest.mark.parametrize("name", ["SECRET_ENCRYPTION_KEYS", "CONTENT_ENCRYPTION_KEYS"])
def test_sync_refuses_malformed_keys(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    canary = secrets.token_hex(24)
    workspace.write_env(**{name: canary})

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert name in err
    assert canary[:FRAGMENT_LENGTH] not in err
    assert not workspace.secrets.exists()


def test_sync_refuses_a_symlinked_directory(
    workspace: Workspace,
    capsys: pytest.CaptureFixture[str],
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    elsewhere.chmod(0o700)
    workspace.secrets.symlink_to(elsewhere)

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert "symlink" in err
    assert os.listdir(elsewhere) == []


def test_sync_refuses_a_directory_with_a_wider_mode(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace.secrets.mkdir(mode=0o700)
    workspace.secrets.chmod(0o755)

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert "0700" in err
    assert os.listdir(workspace.secrets) == []


def test_sync_refuses_a_directory_owned_by_someone_else(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace.secrets.mkdir(mode=0o700)
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert "擁有" in err
    assert os.listdir(workspace.secrets) == []


def test_sync_refuses_a_symlinked_secret_file(
    workspace: Workspace,
    capsys: pytest.CaptureFixture[str],
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    target = tmp_path_factory.mktemp("target") / "outside"
    target.write_text("outside", encoding="utf-8")
    workspace.secrets.mkdir(mode=0o700)
    workspace.file("db_password").symlink_to(target)

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert "db_password" in err
    assert target.read_text(encoding="utf-8") == "outside"


def test_stale_temporaries_are_removed_and_unknown_files_are_kept(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace.secrets.mkdir(mode=0o700)
    (workspace.secrets / f"{TEMP_PREFIX}db_password.0123").write_text("x", encoding="utf-8")
    (workspace.secrets / "notes.txt").write_text("keep", encoding="utf-8")

    code, err = _run(capsys)

    assert code == EXIT_OK
    assert not (workspace.secrets / f"{TEMP_PREFIX}db_password.0123").exists()
    assert (workspace.secrets / "notes.txt").read_text(encoding="utf-8") == "keep"
    assert "notes.txt" in err


def test_sync_is_dispatched_before_loading_settings(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """只 delenv APP_ENV 不夠（APP_ENV=dev 時缺密碼也不會失敗）：把 Settings 換成一定失敗的替身。"""

    def _refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("sync-secret-files 不應載入 Settings")

    monkeypatch.setattr(cli, "Settings", _refuse)

    assert _run(capsys)[0] == EXIT_OK


# ----------------------------------------------------------------------------- --check


def test_check_passes_after_sync(workspace: Workspace, capsys: pytest.CaptureFixture[str]) -> None:
    _run(capsys)

    code, err = _run(capsys, "--check")

    assert code == EXIT_OK
    assert "一致" in err


def test_check_without_the_directory_fails_and_creates_nothing(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = _run(capsys, "--check")

    assert code == EXIT_FAILURE
    assert not workspace.secrets.exists()


@pytest.mark.parametrize("change", ["missing", "different"])
def test_check_reports_missing_and_different_files_without_writing(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], change: str
) -> None:
    _run(capsys)
    path = workspace.file("evidence_encryption_keys")
    if change == "missing":
        path.unlink()
    else:
        path.write_bytes(Fernet.generate_key())
    snapshot = sorted(os.listdir(workspace.secrets))

    code, err = _run(capsys, "--check")

    assert code == EXIT_FAILURE
    assert "evidence_encryption_keys" in err
    assert sorted(os.listdir(workspace.secrets)) == snapshot
    assert _leaks(err, workspace.values) == []


# ----------------------------------------------------------------------------- generate


def _generate(capsys: pytest.CaptureFixture[str], directory: Path) -> tuple[int, str]:
    code = main(["generate-secret-files", str(directory)])
    out, err = capsys.readouterr()
    assert out == ""
    return code, err


@pytest.fixture
def fresh(tmp_path: Path) -> Path:
    directory = tmp_path / "secscan-live-secrets.abc123"
    directory.mkdir(mode=0o700)
    return directory


def test_generate_writes_seven_independent_values(
    fresh: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, err = _generate(capsys, fresh)

    assert code == EXIT_OK
    assert sorted(os.listdir(fresh)) == sorted(FILE_NAMES)
    contents = {name: (fresh / name).read_bytes() for name in FILE_NAMES}
    assert len(set(contents.values())) == len(FILE_NAMES)
    for item in SECRET_FILES:
        value = contents[item.file_name]
        assert stat.S_IMODE((fresh / item.file_name).stat().st_mode) == 0o600
        assert not value.endswith(b"\n")
        if item.kind == "keys":
            assert len(parse_keys(value.decode(), item.env_name)) == 1
        else:
            assert len(value) == 48
            int(value, 16)
    assert _leaks(err, {k: v.decode() for k, v in contents.items()}) == []


def test_generate_does_not_read_dotenv(
    fresh: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    canary = secrets.token_hex(24)
    (tmp_path / ".env").write_text(f"DB_PASSWORD={canary}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def _refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("generate-secret-files 不應讀取 .env")

    monkeypatch.setattr(module, "SecretSources", _refuse)
    monkeypatch.setattr(cli, "Settings", _refuse)

    assert _generate(capsys, fresh)[0] == EXIT_OK
    assert (fresh / "db_password").read_bytes() != canary.encode()


@pytest.mark.parametrize(
    "prepare",
    [
        lambda d: (d / "existing").write_text("x", encoding="utf-8"),
        lambda d: d.chmod(0o755),
    ],
    ids=["not-empty", "wider-mode"],
)
def test_generate_refuses_a_directory_that_is_not_new_and_private(
    fresh: Path, capsys: pytest.CaptureFixture[str], prepare: Callable[[Path], object]
) -> None:
    prepare(fresh)
    before = sorted(os.listdir(fresh))

    code, _ = _generate(capsys, fresh)

    assert code == EXIT_FAILURE
    assert sorted(os.listdir(fresh)) == before


def test_generate_refuses_a_symlinked_or_missing_directory(
    fresh: Path, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    link = tmp_path / "link"
    link.symlink_to(fresh)

    assert _generate(capsys, link)[0] == EXIT_FAILURE
    assert _generate(capsys, tmp_path / "missing")[0] == EXIT_FAILURE
    assert os.listdir(fresh) == []


def test_generated_values_are_new_each_time() -> None:
    assert generate_values() != generate_values()


@pytest.mark.skipif(os.geteuid() == 0, reason="root 讀得到 0000 的檔案")
def test_sync_reports_an_unreadable_secret_file_without_its_content(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(capsys)
    path = workspace.file("db_password")
    path.chmod(0o000)
    try:
        code, err = _run(capsys)
    finally:
        path.chmod(0o600)

    assert code == EXIT_FAILURE
    assert "無法讀取 db_password" in err
    assert _leaks(err, workspace.values) == []


def test_sync_reports_a_directory_it_cannot_create(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    parent = workspace.root / "read-only"
    parent.mkdir(mode=0o500)
    try:
        code, err = _run(capsys, "--dir", str(parent / "secrets"))
    finally:
        parent.chmod(0o700)

    assert code == EXIT_FAILURE
    assert "無法建立" in err
