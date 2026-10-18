"""secscan-admin create-admin-key（T05 DoD：初始管理 key 由本機 CLI 建立，且只顯示一次）。

CLI 和 API 一樣從 DB_* 讀取連線設定；tests/conftest.py 已清掉開發者環境中的值，這裡再指向
測試資料庫。
"""

import re
import stat
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secscan.cli import EXIT_FAILURE, EXIT_OK, main
from secscan.security.api_key_tokens import hash_key, parse_prefix
from tests.integration.api_support import Seeder, unique_name
from tests.integration.conftest import app_engine, migrate_to_head
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

SECRET_HEX = 64
UNREACHABLE_PORT = 1


def _use_database(
    monkeypatch: pytest.MonkeyPatch, database: ProvisionedDatabase, *, port: int | None = None
) -> None:
    monkeypatch.setenv("DB_HOST", database.host)
    monkeypatch.setenv("DB_PORT", str(port if port is not None else database.port))
    monkeypatch.setenv("DB_NAME", database.name)
    monkeypatch.setenv("DB_USER", database.name)
    monkeypatch.setenv("DB_PASSWORD", database.password)


def test_admin_key_is_printed_once_and_stored_only_as_hash(
    api_database: ProvisionedDatabase,
    api_client: TestClient,
    seed: Seeder,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_database(monkeypatch, api_database)

    exit_code = main(["create-admin-key", "--name", "本機管理員"])

    out, err = capsys.readouterr()
    key = out.strip()
    prefix = parse_prefix(key)
    assert exit_code == EXIT_OK
    assert out == f"{key}\n"
    assert prefix is not None
    # stderr 只有說明、id 與 prefix，沒有 key。
    assert prefix in err
    assert key[-SECRET_HEX:] not in err
    # 這把 key 是 platform_admin：可以建立 project。
    created = api_client.post(
        "/api/v1/projects",
        json={"name": unique_name("cli")},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert created.status_code == 201
    # DB 只存 hash；audit 沒有 actor，標明來自 CLI，也不含 key。
    [row] = seed.query(
        "SELECT id, role, project_id, key_hash, created_at, expires_at, "
        "row_to_json(api_keys)::text AS row FROM api_keys WHERE prefix = :prefix",
        prefix=prefix,
    )
    assert (row.role, row.project_id, row.key_hash) == ("platform_admin", None, hash_key(key))
    assert key[-SECRET_HEX:] not in row.row
    assert abs(row.expires_at - row.created_at - timedelta(days=90)) < timedelta(minutes=1)
    [event] = seed.query(
        "SELECT actor_key_id, redacted_changes, row_to_json(audit_events)::text AS row "
        "FROM audit_events WHERE object_id = :id",
        id=row.id,
    )
    assert event.actor_key_id is None
    assert event.redacted_changes["source"] == "cli"
    assert key[-SECRET_HEX:] not in event.row


def test_lifetime_can_be_shortened(
    api_database: ProvisionedDatabase,
    seed: Seeder,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_database(monkeypatch, api_database)

    assert main(["create-admin-key", "--name", "short", "--expires-in-days", "1"]) == EXIT_OK

    prefix = parse_prefix(capsys.readouterr().out.strip())
    [row] = seed.query(
        "SELECT expires_at - created_at AS lifetime FROM api_keys WHERE prefix = :prefix",
        prefix=prefix,
    )
    assert abs(row.lifetime - timedelta(days=1)) < timedelta(minutes=1)


def test_unmigrated_database_is_reported(
    fresh_database: ProvisionedDatabase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_database(monkeypatch, fresh_database)

    exit_code = main(["create-admin-key", "--name", "admin"])

    out, err = capsys.readouterr()
    assert exit_code == EXIT_FAILURE
    assert out == ""
    assert "make migrate" in err


def test_unreachable_database_is_reported_without_secrets(
    api_database: ProvisionedDatabase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_database(monkeypatch, api_database, port=UNREACHABLE_PORT)
    started = datetime.now()

    exit_code = main(["create-admin-key", "--name", "admin"])

    out, err = capsys.readouterr()
    assert exit_code == EXIT_FAILURE
    assert out == ""
    assert "make db-up" in err
    assert api_database.password not in err
    assert datetime.now() - started < timedelta(seconds=30)


def test_output_file_receives_the_key_with_owner_only_permissions(
    api_database: ProvisionedDatabase,
    api_client: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_database(monkeypatch, api_database)
    target = tmp_path / "admin.key"

    exit_code = main(["create-admin-key", "--name", "to-file", "--output", str(target)])

    out, err = capsys.readouterr()
    key = target.read_text(encoding="utf-8").strip()
    assert exit_code == EXIT_OK
    assert out == ""
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert parse_prefix(key) is not None
    assert str(target) in err
    assert key[-SECRET_HEX:] not in err
    response = api_client.get("/api/v1/projects", headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 200


def test_unready_database_leaves_no_output_file(
    fresh_database: ProvisionedDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_database(monkeypatch, fresh_database)
    target = tmp_path / "admin.key"

    exit_code = main(["create-admin-key", "--name", "admin", "--output", str(target)])

    assert exit_code == EXIT_FAILURE
    assert not target.exists()
    assert "make migrate" in capsys.readouterr().err


@pytest.mark.parametrize("to_file", [False, True], ids=["stdout", "output-file"])
def test_commit_failure_prints_no_key_and_leaves_no_file(
    fresh_database: ProvisionedDatabase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    to_file: bool,
) -> None:
    """commit 失敗時 key 並不存在，不能印出或寫出任何 key。

    以 DEFERRABLE 的 constraint trigger 讓 INSERT 成功、直到 commit 才失敗。
    """
    migrate_to_head(fresh_database)
    seed = Seeder(engine := app_engine(fresh_database))
    try:
        seed.execute(
            "CREATE FUNCTION reject_keys_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'rejected at commit'; END $$"
        )
        seed.execute(
            "CREATE CONSTRAINT TRIGGER api_keys_reject_at_commit AFTER INSERT ON api_keys "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_keys_at_commit()"
        )
        _use_database(monkeypatch, fresh_database)
        target = tmp_path / "admin.key"
        args = ["create-admin-key", "--name", "admin"]

        exit_code = main([*args, "--output", str(target)] if to_file else args)

        [count] = seed.query("SELECT count(*) AS n FROM api_keys")
    finally:
        engine.dispose()

    out, err = capsys.readouterr()
    assert exit_code == EXIT_FAILURE
    assert out == ""
    assert not target.exists()
    assert "沒有建立任何 key" in err
    assert count.n == 0


class _BrokenStdout:
    def write(self, _text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        raise BrokenPipeError(32, "Broken pipe")


def test_undeliverable_key_is_reported_without_its_value(
    api_database: ProvisionedDatabase,
    seed: Seeder,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """key 已 commit 但 stdout 寫不出去：回報 id 讓人撤銷；沒有人拿得到它的值，不會印出來。"""
    _use_database(monkeypatch, api_database)
    monkeypatch.setattr(sys, "stdout", _BrokenStdout())

    exit_code = main(["create-admin-key", "--name", "lost"])

    err = capsys.readouterr().err
    assert exit_code == EXIT_FAILURE
    match = re.search(r"id ([0-9a-f-]{36})", err)
    assert match is not None
    [row] = seed.query(
        "SELECT name, revoked_at FROM api_keys WHERE id = CAST(:id AS uuid)", id=match.group(1)
    )
    assert (row.name, row.revoked_at) == ("lost", None)
    assert "secscan_" not in err
