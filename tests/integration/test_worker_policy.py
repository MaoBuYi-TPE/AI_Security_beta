"""T33：worker 對政策、逐筆授權與完整性採同一信任結果。"""

from typing import Any
from uuid import UUID

import pytest

from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.guard.domain.telemetry import telemetry_file_name
from secscan.scanners.domain.zap.results import PARSER_VERSION
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.observation import ParsedRun, RunOutcome
from secscan.scans.queue import ScanQueue
from secscan.worker.telemetry import TelemetryReader
from tests.integration.api_support import Seeder, World
from tests.integration.test_worker_zap import (
    ZAP,
    Dirs,
    _collected,
    _run,
    _summary,
    _telemetry,
    _worker,
)
from tests.integration.test_worker_zap import (
    dirs as _dirs_fixture,
)
from tests.integration.test_worker_zap import (
    queue as _queue_fixture,
)
from tests.integration.test_worker_zap import (
    world as _world_fixture,
)

dirs, queue, world = _dirs_fixture, _queue_fixture, _world_fixture

pytestmark = pytest.mark.integration


def test_encoded_evidence_is_checked_once_and_shared_by_parser_and_coverage(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = _collected(
        queue,
        queue_seed,
        world,
        dirs,
        "findings",
        policy_version=GuardPolicyVersion.ENCODED_PARAMS,
        paths=("/", "/users/{name}"),
        telemetry=_telemetry([("/users/name%27", 200)]),
    )
    original = TelemetryReader.evidence
    calls: list[UUID] = []

    def counted(self: TelemetryReader, run_id: UUID, **options: Any) -> Any:
        calls.append(run_id)
        return original(self, run_id, **options)

    monkeypatch.setattr(TelemetryReader, "evidence", counted)
    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert calls == [lease.run_id]
    assert run.result_details["traffic_verified"] is True
    assert run.coverage_recorded
    assert run.result_details["guard_traffic"]["policy_version"] == "encoded-params-1"
    assert run.result_details["guard_traffic"]["forwarded_encoded"] == 1


@pytest.mark.parametrize("path", ["/admin", "/other/name%27"])
def test_unauthorized_telemetry_blocks_both_coverage_and_parser_verification(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
    path: str,
) -> None:
    lease = _collected(
        queue,
        queue_seed,
        world,
        dirs,
        "findings",
        policy_version=GuardPolicyVersion.ENCODED_PARAMS,
        paths=("/", "/users/{name}"),
        telemetry=_telemetry([(path, 200)]),
    )

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert not run.coverage_recorded
    assert run.result_details["traffic_verified"] is False
    assert run.result_details["guard_traffic"]["forwarded_encoded"] is None


def test_zero_requests_do_not_hide_mismatched_policy_versions(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
) -> None:
    lease = _collected(
        queue,
        queue_seed,
        world,
        dirs,
        "clean",
        telemetry=b"",
        policy_version=GuardPolicyVersion.ENCODED_PARAMS,
    )
    _summary(dirs, lease, forwarded=0, denied={})  # schema 2，錯誤的 strict 版本

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    assert run.status == "succeeded"  # 不以壞掉的證據判定沒有流量，也不重試。
    assert not run.coverage_recorded
    assert run.result_details["traffic_verified"] is False
    traffic = run.result_details["guard_traffic"]
    assert traffic["policy_version"] == "strict-1"
    assert traffic["answered"] is traffic["forwarded_encoded"] is None


@pytest.mark.parametrize("version", list(GuardPolicyVersion))
def test_missing_last_request_is_only_legacy_strict_compatible(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
    version: GuardPolicyVersion,
) -> None:
    lease = _collected(
        queue,
        queue_seed,
        world,
        dirs,
        "clean",
        policy_version=version,
        telemetry=_telemetry([("/one", 200), ("/two", 200)]),
    )
    (dirs.telemetry / telemetry_file_name(lease.run_id)).write_bytes(_telemetry([("/one", 200)]))

    _worker(queue, dirs).drain()

    run = _run(queue_seed, lease.run_id)
    expected = version is GuardPolicyVersion.STRICT
    assert run.coverage_recorded is expected
    assert run.result_details["traffic_verified"] is expected
    assert run.result_details["guard_traffic"]["forwarded_encoded"] is None


def test_historical_null_version_stays_null_and_uses_strict_authorization(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
) -> None:
    lease = _collected(
        queue,
        queue_seed,
        world,
        dirs,
        "findings",
        paths=("/", "/users/{name}"),
        telemetry=_telemetry([("/users/name%27", 200)]),
    )

    _worker(queue, dirs).drain()

    [row] = queue_seed.query(
        "SELECT guard_policy_version FROM scanner_runs WHERE id = :id", id=lease.run_id
    )
    assert row.guard_policy_version is None
    run = _run(queue_seed, lease.run_id)
    assert not run.coverage_recorded
    assert run.result_details["traffic_verified"] is False


def test_policy_traffic_details_fit_the_actual_jsonb_limit(
    queue: ScanQueue,
    queue_seed: Seeder,
    world: World,
    dirs: Dirs,
) -> None:
    from secscan.guard.domain.requests import Reason
    from secscan.scans.domain.observation import MAX_DETAILS_BYTES, Exclusion
    from secscan.scans.domain.traffic import AuthHealth, GuardTraffic

    lease = _collected(queue, queue_seed, world, dirs, "clean")
    parsing = queue.claim_collected("worker-1", ZAP)
    assert parsing is not None
    count = 10**12
    parsed = ParsedRun(
        parser_version=PARSER_VERSION,
        outcome=RunOutcome(RunStatus.SUCCEEDED),
        duplicates=count,
        truncated_fields=count,
        excluded=dict.fromkeys(Exclusion, count),
        components=dict.fromkeys((f"addon-{index}" for index in range(9)), "1.44.0"),
        traffic=GuardTraffic(
            forwarded=count,
            forwarded_encoded=count,
            answered=count,
            policy_version=GuardPolicyVersion.ENCODED_PARAMS,
            denied=dict.fromkeys((reason.value for reason in Reason), count),
            first_at=4_102_444_800.123456,
            last_at=4_102_444_800.123456,
            auth=AuthHealth(count, count, count),
        ),
    )

    queue.record_results(parsing, parsed, (), exit_code=0)

    [row] = queue_seed.query(
        "SELECT octet_length(result_details::text) AS size FROM scanner_runs WHERE id = :id",
        id=lease.run_id,
    )
    assert row.size < MAX_DETAILS_BYTES == 4096
