"""真實舊 profile 的讀取、金鑰換版與修復；不繞過任何 DB trigger。"""

from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.credentials import AuthType, Credential, SecretValue
from secscan.auth_profiles.domain.model import (
    ChangeInput,
    NewAuthProfile,
    NewProfileVersion,
    ProfileDefinition,
    secret_context,
)
from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.auth_profiles.service import AuthProfileService
from secscan.core.errors import ErrorCode
from secscan.core.pagination import PageRequest
from secscan.scans.domain.catalog import Engine, ScanProfile, plan_runs
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import AuthBinding, NewScan
from secscan.scans.queue import QueueOperations
from secscan.scans.repository import ScanRepository
from secscan.targets.domain import Target
from tests.integration.scan_support import DEFAULT_CLOCK, create_scan, new_key, scan_world
from tests.integration.scope_support import LAB, Members, app_error
from tests.integration.test_auth_profile_service import target as target
from tests.integration.test_auth_profile_service import team as team
from tests.secret_support import shared_cipher
from tests.unit.auth_profiles.test_model import ME

pytestmark = pytest.mark.integration


def _legacy(session: Session, team: Members, target: Target) -> UUID:
    repository = AuthProfileRepository(session)
    profile_id = repository.create(
        NewAuthProfile(
            target_id=target.id,
            name="legacy",
            role_label="legacy_user",
            created_by_key_id=team.operator_a.key_id,
        )
    )
    credential = Credential(AuthType.API_KEY_HEADER, "X-ZAP-Scan-ID")
    repository.add_version(
        profile_id,
        version=1,
        new_version=NewProfileVersion(
            definition=ProfileDefinition(credential, ME),
            encrypted_secret=shared_cipher().seal(
                "synthetic-legacy-canary", context=secret_context(profile_id, credential)
            ),
            created_by_key_id=team.operator_a.key_id,
        ),
    )
    return profile_id


def test_legacy_profile_remains_readable_rotatable_and_repairable(
    db_session: Session, team: Members, target: Target
) -> None:
    profile_id = _legacy(db_session, team, target)
    service = AuthProfileService(db_session, cipher=shared_cipher())
    page = PageRequest(limit=100)

    old = service.get(team.viewer_a, profile_id)
    assert old.current.definition.credential.header_name == "X-ZAP-Scan-ID"
    assert profile_id in {
        item.id for item in service.list_for_target(team.viewer_a, target.id, page).items
    }
    assert len(service.versions(team.viewer_a, profile_id, page).items) == 1
    assert service.reencrypt_secrets() >= 1
    stored = AuthProfileRepository(db_session).sealed_secret(profile_id, version=1)
    assert stored is not None
    assert shared_cipher().reveal(stored.token, context=stored.context) == "synthetic-legacy-canary"

    repaired = service.update(
        team.operator_a,
        profile_id,
        ChangeInput(header_name="X-API-Key", secret=SecretValue("new-synthetic-canary")),
        request_id=None,
    )

    assert repaired.current.version == 2
    assert repaired.current.definition.credential.header_name == "X-API-Key"
    history = service.versions(team.viewer_a, profile_id, page).items
    assert [version.version for version in history] == [2, 1]
    assert history[1].secret_configured is False
    assert history[1].definition.credential.header_name == "X-ZAP-Scan-ID"


def test_new_scan_rejects_a_stored_legacy_profile_without_creating_runs(
    db_session: Session,
) -> None:
    world = scan_world(db_session)
    profile_id = _legacy(db_session, world.team, world.target)

    error = app_error(
        lambda: create_scan(db_session, world, world.request(auth_profile_id=profile_id))
    )

    assert (error.status_code, error.code) == (422, ErrorCode.INVALID_REQUEST)
    assert not ScanRepository(db_session).has_active(world.target.id)
    assert "synthetic-legacy-canary" not in error.message


def test_legacy_queued_scan_is_rejected_before_assigning_a_container_or_secret(
    db_session: Session,
) -> None:
    world = scan_world(db_session)
    profile_id = _legacy(db_session, world.team, world.target)
    repository = ScanRepository(db_session)
    # 舊版可建立這個快照；以 repository 插入歷史資料，不停用 trigger 或用途驗證。
    scan_id = repository.create(
        NewScan(
            project_id=world.team.project_a,
            target_id=world.target.id,
            target_origin=world.target.origin,
            scope_grant_id=world.grant.id,
            api_spec_id=world.spec.id,
            auth=AuthBinding(profile_id, 1, "legacy_user"),
            profile=ScanProfile.API_ACTIVE_LAB,
            budget=world.grant.budget,
            runs=plan_runs((Engine.FAKE,), authenticated=True),
            operations=(),
            idempotency_key=new_key(),
            request_sha256=bytes(32),
            created_by_key_id=world.operator.key_id,
        )
    )
    queue = QueueOperations(db_session, lab=LAB)
    lease = queue.claim("legacy-profile-test", (Engine.PREFLIGHT,))
    assert lease is not None
    assert lease.scan_id == scan_id

    launch = queue.prepare_launch(
        lease, image_ref="busybox:1.38.0@sha256:" + "ab" * 32, clock=DEFAULT_CLOCK
    )

    assert launch.progress.run_status is RunStatus.FAILED
    assert launch.secret is None
    assert launch.egress is None
    persisted = repository.get(scan_id)
    assert persisted is not None
    run = persisted.runs[0]
    assert run.error_code is RunErrorCode.PLAN_REJECTED
    assert run.container is False
    assert "synthetic-legacy-canary" not in repr(launch)
