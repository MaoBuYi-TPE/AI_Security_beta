"""T21 停用 auth profile：終止狀態、清除密文、新 scan 409、排隊中的 scan 在交出 secret 前失敗。"""

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from secscan.api_keys.domain import Role
from secscan.audit.service import AuditTrail
from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.auth_profiles.service import AuthProfileService
from secscan.core.errors import AppError
from secscan.main import create_app
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.locks import Race, wait_until_waiting_for_a_lock
from tests.integration.sql_support import INTEGRITY_CONSTRAINT_VIOLATION, violation

pytestmark = pytest.mark.integration
IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32
PREFLIGHT = frozenset({ScanEngine.PREFLIGHT})


class InjectedError(RuntimeError):
    """故障注入。"""


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def scannable(queue_seed: Seeder, world: World) -> Scannable:
    return queue_seed.scannable(world)


def disable(client: TestClient, scannable: Scannable, headers: dict[str, str]) -> object:
    return client.post(
        f"/api/v1/auth-profiles/{scannable.profile.id}/disable",
        json={"reason": "外洩疑慮，停用並更換"},
        headers=headers,
    )


def secrets(seed: Seeder, scannable: Scannable) -> int:
    [row] = seed.query(
        "SELECT count(*) AS n FROM auth_profile_versions "
        "WHERE profile_id = :id AND encrypted_secret IS NOT NULL",
        id=scannable.profile.id,
    )
    return int(row.n)


def test_disable_is_terminal_and_idempotent(
    client: TestClient, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    assert secrets(queue_seed, scannable) == 1
    first = disable(client, scannable, world.operator_a.headers)
    assert first.status_code == 200, first.text  # type: ignore[attr-defined]
    assert first.json()["data"]["disabled_at"] is not None  # type: ignore[attr-defined]
    assert first.json()["data"]["secret_configured"] is False  # type: ignore[attr-defined]
    assert secrets(queue_seed, scannable) == 0
    again = disable(client, scannable, world.operator_a.headers)
    assert again.status_code == 200  # type: ignore[attr-defined]
    [audit] = queue_seed.query(
        "SELECT count(*) AS n FROM audit_events WHERE action = 'auth_profile.disable'"
    )
    assert audit.n == 1
    patched = client.patch(
        f"/api/v1/auth-profiles/{scannable.profile.id}",
        json={"secret": "new-secret-value"},
        headers=world.operator_a.headers,
    )
    assert patched.status_code == 409
    assert patched.json()["error"]["code"] == "AUTH_PROFILE_DISABLED"
    with pytest.raises(AppError) as caught:
        queue_seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)
    assert caught.value.code == "AUTH_PROFILE_DISABLED"
    assert caught.value.status_code == 409


def test_disable_requires_a_writer_and_hides_other_projects(
    client: TestClient, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    assert disable(client, scannable, world.viewer_a.headers).status_code == 403  # type: ignore[attr-defined]
    outsider = queue_seed.member(world.admin, world.project_b.id, Role.OPERATOR)
    assert disable(client, scannable, outsider.headers).status_code == 404  # type: ignore[attr-defined]
    blank = client.post(
        f"/api/v1/auth-profiles/{scannable.profile.id}/disable",
        json={"reason": " "},
        headers=world.operator_a.headers,
    )
    assert blank.status_code == 422
    assert secrets(queue_seed, scannable) == 1


def test_a_queued_scan_fails_before_the_secret_is_handed_over(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    queue_seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)
    assert disable(client, scannable, world.operator_a.headers).status_code == 200  # type: ignore[attr-defined]
    lease = queue.claim("runner-1", PREFLIGHT)
    assert lease is not None
    launch = queue.prepare_launch(lease, image_ref=IMAGE)
    assert launch.secret is None
    assert launch.progress.run_status is RunStatus.FAILED
    [run] = queue_seed.query("SELECT error_code FROM scanner_runs WHERE id = :id", id=lease.run_id)
    assert run.error_code == RunErrorCode.AUTH_PROFILE_DISABLED


def test_the_database_only_allows_disabling_once(
    client: TestClient, queue_owner_engine: Engine, world: World, scannable: Scannable
) -> None:
    with sessionmaker(queue_owner_engine)() as session:
        for statement in (
            "UPDATE auth_profiles SET name = 'renamed' WHERE id = :id",
            "UPDATE auth_profiles SET disabled_at = now() WHERE id = :id",
            "DELETE FROM auth_profiles WHERE id = :id",
        ):
            error = violation(session, statement, {"id": scannable.profile.id})
            assert error.sqlstate in {INTEGRITY_CONSTRAINT_VIOLATION, "23514"}, statement
    assert disable(client, scannable, world.operator_a.headers).status_code == 200  # type: ignore[attr-defined]
    with sessionmaker(queue_owner_engine)() as session:
        for statement in (
            "UPDATE auth_profiles SET disabled_at = NULL, disabled_by_key_id = NULL WHERE id = :id",
            "UPDATE auth_profiles SET disabled_at = now() WHERE id = :id",
        ):
            error = violation(session, statement, {"id": scannable.profile.id})
            assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION, statement


def test_disable_waits_for_a_scan_being_created_with_the_profile(
    queue_database: ProvisionedDatabase,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    def work(session: Session) -> object:
        return AuthProfileService(session).disable(
            world.operator_a.principal, scannable.profile.id, reason="停用", request_id=None
        )

    rival = Race(queue_database, "disable-rival", work)
    with sessionmaker(queue_engine).begin() as session:
        # 建立 scan 時以 FOR SHARE 鎖住 profile（ScanService._auth）。
        AuthProfileRepository(session).lock(scannable.profile.id, shared=True)
        rival.start()
        wait_until_waiting_for_a_lock(queue_seed, "disable-rival")
    rival.join()
    assert rival.errors == []
    assert secrets(queue_seed, scannable) == 0


def test_a_failed_disable_rolls_back(
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_: object, **__: object) -> None:
        raise InjectedError

    monkeypatch.setattr(AuditTrail, "record", fail)
    with pytest.raises(InjectedError), sessionmaker(queue_engine).begin() as session:
        AuthProfileService(session).disable(
            world.operator_a.principal, scannable.profile.id, reason="停用", request_id=None
        )
    assert secrets(queue_seed, scannable) == 1
    [row] = queue_seed.query(
        "SELECT disabled_at FROM auth_profiles WHERE id = :id", id=scannable.profile.id
    )
    assert row.disabled_at is None


def test_every_later_run_of_a_scan_fails_before_any_secret(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )
    scan = queue_seed.scan(world.operator_a, scannable, auth_profile_id=scannable.profile.id)
    preflight = queue.claim("runner-1", PREFLIGHT)
    assert preflight is not None
    assert disable(client, scannable, world.operator_a.headers).status_code == 200  # type: ignore[attr-defined]
    assert queue.prepare(preflight).run_status is RunStatus.FAILED
    later = queue.claim("runner-1", frozenset(ScanEngine) - PREFLIGHT)
    assert later is not None
    assert queue.prepare(later).run_status is RunStatus.FAILED
    errors = queue_seed.query(
        "SELECT error_code FROM scanner_runs WHERE scan_id = :id ORDER BY sequence", id=scan.id
    )
    assert [row.error_code for row in errors] == ["AUTH_PROFILE_DISABLED"] * len(errors)


NEW_VERSION = (
    "INSERT INTO auth_profile_versions (profile_id, version, type, preflight_method, "
    "preflight_path, preflight_expected_status, preflight_expected_json, "
    "encrypted_secret, created_by_key_id) SELECT profile_id, version + 1, type, "
    "preflight_method, preflight_path, preflight_expected_status, "
    "preflight_expected_json, 'gAAAAAx', created_by_key_id FROM auth_profile_versions "
    "WHERE profile_id = :id ORDER BY version DESC LIMIT 1"
)


def test_a_direct_insert_racing_a_disable_waits_and_is_rejected(
    queue_database: ProvisionedDatabase,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    scannable: Scannable,
) -> None:
    """繞過應用程式直接新增版本、同時有停用尚未 commit：trigger 以 FOR SHARE 等停用 commit，
    重新讀到已停用而拒絕；不會留下帶密文的版本（安全審查 L6）。"""
    profile = scannable.profile.id

    def work(session: Session) -> object:
        return session.execute(text(NEW_VERSION), {"id": profile})

    rival = Race(queue_database, "insert-rival", work)
    with sessionmaker(queue_engine).begin() as session:
        AuthProfileService(session).disable(
            world.operator_a.principal, profile, reason="停用", request_id=None
        )
        rival.start()
        wait_until_waiting_for_a_lock(queue_seed, "insert-rival")
    rival.join()
    [error] = rival.errors
    assert isinstance(error, IntegrityError)
    assert "disabled profile" in str(error)
    assert secrets(queue_seed, scannable) == 0


def test_the_database_keeps_a_disabled_profile_without_secrets(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, scannable: Scannable
) -> None:
    profile = scannable.profile.id
    with sessionmaker(queue_engine)() as session:
        # 只設定停用而不清除密文：commit 時被 deferred 檢查擋下。
        session.execute(
            text(
                "UPDATE auth_profiles SET disabled_at = now(), disabled_by_key_id = :key "
                "WHERE id = :id"
            ),
            {"id": profile, "key": world.operator_a.principal.key_id},
        )
        with pytest.raises(IntegrityError, match="must not keep any secret"):
            session.commit()
    assert disable(client, scannable, world.operator_a.headers).status_code == 200  # type: ignore[attr-defined]
    with sessionmaker(queue_engine)() as session:
        error = violation(session, NEW_VERSION, {"id": profile})
        assert "disabled profile" in str(error)
