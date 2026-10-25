"""secscan-admin rotate-secret-keys（T08 DoD：支援換版；docs/DECISIONS.md §12.3）。

換版會重新加密資料庫中所有的密文，所以每個測試用一個全新的資料庫，不動 API 測試共用的 api_database。
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from uuid import UUID

import pytest
from cryptography.fernet import Fernet

from secscan.cli import EXIT_FAILURE, EXIT_OK, MAX_LISTED_PROFILES, main
from secscan.security.secret_cipher import SecretCipher, SecretUnreadableError
from tests.integration.api_support import Seeder
from tests.integration.conftest import app_engine, migrate_to_head
from tests.integration.database import ProvisionedDatabase
from tests.secret_support import TEST_SECRET_ENCRYPTION_KEYS, bearer_context

pytestmark = pytest.mark.integration

UNREACHABLE_PORT = 1
UUID_TEXT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@dataclass(frozen=True)
class Lab:
    seed: Seeder
    database: ProvisionedDatabase
    profile_ids: tuple[UUID, ...]


@pytest.fixture
def lab(fresh_database: ProvisionedDatabase) -> Iterator[Lab]:
    """兩個 profile，其中一個換過 secret（版本 1 的密文已清除）；都以測試金鑰加密。"""
    migrate_to_head(fresh_database)
    engine = app_engine(fresh_database)
    seed = Seeder(engine)
    world = seed.world()
    target = seed.target(world.operator_a, world.project_a.id)
    first = seed.auth_profile(world.operator_a, target, role_label="user_a", value="secret-a")
    second = seed.auth_profile(world.operator_a, target, role_label="user_b", value="secret-b")
    yield Lab(seed=seed, database=fresh_database, profile_ids=(first.id, second.id))
    engine.dispose()


def _use(
    monkeypatch: pytest.MonkeyPatch,
    database: ProvisionedDatabase,
    keys: str,
    *,
    port: int | None = None,
) -> None:
    monkeypatch.setenv("DB_HOST", database.host)
    monkeypatch.setenv("DB_PORT", str(port if port is not None else database.port))
    monkeypatch.setenv("DB_NAME", database.name)
    monkeypatch.setenv("DB_USER", database.name)
    monkeypatch.setenv("DB_PASSWORD", database.password)
    monkeypatch.setenv("SECRET_ENCRYPTION_KEYS", keys)


def _tokens(lab: Lab) -> dict[UUID, bytes]:
    rows = lab.seed.query(
        "SELECT profile_id, encrypted_secret FROM auth_profile_versions "
        "WHERE encrypted_secret IS NOT NULL"
    )
    return {row.profile_id: row.encrypted_secret for row in rows}


def _reveal(keys: str, profile_id: UUID, token: bytes) -> str:
    return SecretCipher.from_setting(keys).reveal(token, context=bearer_context(profile_id))


def test_rotation_moves_every_secret_to_the_new_key(
    lab: Lab, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    new = Fernet.generate_key().decode()
    _use(monkeypatch, lab.database, f"{new},{TEST_SECRET_ENCRYPTION_KEYS}")

    exit_code = main(["rotate-secret-keys"])

    out, err = capsys.readouterr()
    assert (exit_code, out) == (EXIT_OK, "")
    assert "2 份" in err
    tokens = _tokens(lab)
    assert set(tokens) == set(lab.profile_ids)
    first, second = lab.profile_ids
    assert _reveal(new, first, tokens[first]) == "secret-a"
    assert _reveal(new, second, tokens[second]) == "secret-b"
    [event] = lab.seed.query(
        "SELECT actor_key_id, project_id, redacted_changes FROM audit_events "
        "WHERE action = 'auth_secrets.reencrypt'"
    )
    assert (event.actor_key_id, event.project_id, event.redacted_changes) == (
        None,
        None,
        {"reencrypted": 2},
    )

    # 移除舊金鑰後再執行一次：全部都解得開，代表可以安全地丟掉舊金鑰。
    _use(monkeypatch, lab.database, new)
    assert main(["rotate-secret-keys"]) == EXIT_OK
    with pytest.raises(SecretUnreadableError):
        _reveal(TEST_SECRET_ENCRYPTION_KEYS, first, _tokens(lab)[first])


def test_rotation_without_the_old_key_changes_nothing(
    lab: Lab, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _tokens(lab)
    _use(monkeypatch, lab.database, Fernet.generate_key().decode())

    exit_code = main(["rotate-secret-keys"])

    out, err = capsys.readouterr()
    assert (exit_code, out) == (EXIT_FAILURE, "")
    assert "2 份" in err
    assert all(str(profile_id) in err for profile_id in lab.profile_ids)
    assert _tokens(lab) == before
    assert (
        lab.seed.query("SELECT 1 FROM audit_events WHERE action = 'auth_secrets.reencrypt'") == []
    )


def test_rotation_needs_a_reachable_and_migrated_database(
    fresh_database: ProvisionedDatabase,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use(monkeypatch, fresh_database, TEST_SECRET_ENCRYPTION_KEYS)
    assert main(["rotate-secret-keys"]) == EXIT_FAILURE
    assert "make migrate" in capsys.readouterr().err

    _use(monkeypatch, fresh_database, TEST_SECRET_ENCRYPTION_KEYS, port=UNREACHABLE_PORT)
    assert main(["rotate-secret-keys"]) == EXIT_FAILURE
    assert "make db-up" in capsys.readouterr().err


def test_a_failed_commit_changes_nothing(
    lab: Lab, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """以 DEFERRABLE 的 constraint trigger 讓 UPDATE 成功、直到 commit 才失敗。

    做法同 test_cli.py 的 commit 失敗。
    """
    lab.seed.execute(
        "CREATE FUNCTION reject_rotation_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN RAISE EXCEPTION 'rejected at commit'; END $$"
    )
    lab.seed.execute(
        "CREATE CONSTRAINT TRIGGER versions_reject_at_commit AFTER UPDATE ON auth_profile_versions "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_rotation_at_commit()"
    )
    before = _tokens(lab)
    new = Fernet.generate_key().decode()
    _use(monkeypatch, lab.database, f"{new},{TEST_SECRET_ENCRYPTION_KEYS}")

    exit_code = main(["rotate-secret-keys"])

    out, err = capsys.readouterr()
    assert (exit_code, out) == (EXIT_FAILURE, "")
    assert "已回滾" in err
    assert _tokens(lab) == before


def test_many_unreadable_profiles_are_summarised(
    lab: Lab, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    world = lab.seed.world()
    for _ in range(2):
        target = lab.seed.target(world.operator_a, world.project_a.id)
        for index in range(6):
            lab.seed.auth_profile(world.operator_a, target, role_label=f"user_{index}")
    _use(monkeypatch, lab.database, Fernet.generate_key().decode())

    assert main(["rotate-secret-keys"]) == EXIT_FAILURE

    err = capsys.readouterr().err
    assert "有 14 份" in err
    assert "等 14 個" in err
    assert len(UUID_TEXT.findall(err)) == MAX_LISTED_PROFILES
