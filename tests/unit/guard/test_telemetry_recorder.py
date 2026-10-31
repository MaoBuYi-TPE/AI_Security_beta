"""guard 的 telemetry 記錄（docs/DECISIONS.md §16）：轉送的每個請求一行、summary 原子寫入。

- 放行之前先保留名額；寫不出 telemetry 就釋放名額並拋出例外（addon 會拒絕這個請求：記錄不完整，
  runner 算出的剩下預算就不可信）。
- 拒絕只計數；summary 在轉送時立刻寫入，拒絕的計數由定期的 flush 寫入。
- 超過保留期限的檔案與記憶體中的計數會被清除。
"""

import json
import os
from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest

from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.domain.budget import RunBudget
from secscan.guard.domain.policy import GuardPolicyVersion, Policy, PolicyState
from secscan.guard.domain.requests import Reason
from secscan.guard.domain.telemetry import (
    ForwardedRequest,
    UpstreamResponse,
    decode_line,
    decode_summary,
    summary_file_name,
    telemetry_file_name,
)
from secscan.guard.telemetry import TelemetryRecorder, TelemetryWriteError
from secscan.targets.domain import parse_ipv4, parse_origin

RUN = UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")
SCAN = UUID("0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d")
BOOT = UUID("3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b")
NOW = 1_767_598_800.0


def _policy(max_requests: int = 3, run_id: UUID = RUN) -> Policy:
    return Policy(
        policy_version=GuardPolicyVersion.STRICT,
        run_id=run_id,
        scan_id=SCAN,
        state=PolicyState.ACTIVE,
        token_sha256="ab" * 32,
        not_after=int(NOW) + 600,
        renew_until=int(NOW) + 30,
        scope=Scope(
            origins=(parse_origin("http://lab-target:8080"),),
            ips=(parse_ipv4("10.89.7.20"),),
            paths=("/api",),
            allow_all_paths=False,
            excluded_paths=(),
            methods=(HttpMethod.GET,),
        ),
        budget=RunBudget(requests_per_second=2, burst=1, max_requests=max_requests),
        auth_header="authorization",
    )


@pytest.fixture
def recorder(tmp_path: Path) -> TelemetryRecorder:
    return TelemetryRecorder(tmp_path, boot_id=BOOT)


def _lines(directory: Path, run_id: UUID = RUN) -> list[object]:
    raw = (directory / telemetry_file_name(run_id)).read_bytes()
    return [decode_line(line) for line in raw.splitlines(keepends=True)]


def _summary(directory: Path, run_id: UUID = RUN) -> object:
    return decode_summary((directory / summary_file_name(run_id)).read_bytes(), run_id=run_id)


def test_forwarded_requests_and_responses_are_recorded(
    recorder: TelemetryRecorder, tmp_path: Path
) -> None:
    policy = _policy()
    assert recorder.reserve(policy)

    sequence = recorder.forwarded(
        policy.run_id, method="GET", path="/api", authenticated=True, at=NOW
    )
    recorder.response(RUN, sequence=sequence, status=200, at=NOW + 0.1)

    assert sequence == 1
    assert _lines(tmp_path) == [
        ForwardedRequest(sequence=1, at=NOW, method="GET", path="/api", authenticated=True),
        UpstreamResponse(sequence=1, at=NOW + 0.1, status=200),
    ]
    summary = _summary(tmp_path)
    assert summary.forwarded == 1  # type: ignore[attr-defined]
    assert summary.scan_id == SCAN  # type: ignore[attr-defined]
    assert summary.boot_id == BOOT  # type: ignore[attr-defined]
    assert summary.exhausted is False  # type: ignore[attr-defined]
    assert (summary.first_at, summary.last_at) == (NOW, NOW)  # type: ignore[attr-defined]


def test_the_budget_is_enforced_per_run(recorder: TelemetryRecorder, tmp_path: Path) -> None:
    policy = _policy(max_requests=2)
    for index in range(2):
        assert recorder.reserve(policy)
        recorder.forwarded(
            policy.run_id, method="GET", path="/api", authenticated=False, at=NOW + index
        )

    assert not recorder.reserve(policy)
    assert _summary(tmp_path).exhausted is True  # type: ignore[attr-defined]
    other = _policy(run_id=UUID(int=9))
    assert recorder.reserve(other)


def test_released_reservations_free_the_slot(recorder: TelemetryRecorder) -> None:
    policy = _policy(max_requests=1)
    assert recorder.reserve(policy)
    recorder.release(RUN)

    assert recorder.reserve(policy)


def test_write_failures_release_the_slot_and_raise(
    recorder: TelemetryRecorder, tmp_path: Path
) -> None:
    policy = _policy(max_requests=1)
    assert recorder.reserve(policy)
    os.chmod(tmp_path, 0o500)
    try:
        with pytest.raises(TelemetryWriteError):
            recorder.forwarded(
                policy.run_id, method="GET", path="/api", authenticated=False, at=NOW
            )
    finally:
        os.chmod(tmp_path, 0o700)

    assert recorder.reserve(policy)  # 沒有轉送：名額還在


def test_denials_are_counted_and_flushed(recorder: TelemetryRecorder, tmp_path: Path) -> None:
    policy = _policy()
    recorder.denied(policy, Reason.PATH_EXCLUDED)
    recorder.denied(policy, Reason.PATH_EXCLUDED)
    recorder.denied(policy, Reason.RATE_LIMITED)
    assert not (tmp_path / summary_file_name(RUN)).exists()  # 拒絕不立刻寫

    recorder.flush()

    summary = _summary(tmp_path)
    assert summary.denied == {"PATH_EXCLUDED": 2, "RATE_LIMITED": 1}  # type: ignore[attr-defined]
    assert summary.forwarded == 0  # type: ignore[attr-defined]
    assert not (tmp_path / telemetry_file_name(RUN)).exists()


def test_a_run_without_budget_is_reported_exhausted_on_flush(
    recorder: TelemetryRecorder, tmp_path: Path
) -> None:
    policy = _policy(max_requests=0)
    assert not recorder.reserve(policy)
    recorder.denied(policy, Reason.BUDGET_EXHAUSTED)

    recorder.flush()

    assert _summary(tmp_path).exhausted is True  # type: ignore[attr-defined]


def test_flush_errors_are_reported(recorder: TelemetryRecorder, tmp_path: Path) -> None:
    recorder.denied(_policy(), Reason.PATH_EXCLUDED)
    os.chmod(tmp_path, 0o500)
    try:
        with pytest.raises(TelemetryWriteError):
            recorder.flush()
    finally:
        os.chmod(tmp_path, 0o700)


def test_old_runs_are_pruned(tmp_path: Path) -> None:
    clock = [NOW]
    recorder = TelemetryRecorder(tmp_path, boot_id=BOOT, clock=lambda: clock[0])
    policy, recent = _policy(), _policy(run_id=UUID(int=9))
    for each, at in ((policy, NOW), (recent, NOW + 7_000)):
        clock[0] = at
        recorder.reserve(each)
        recorder.forwarded(each.run_id, method="GET", path="/api", authenticated=False, at=at)
    (tmp_path / "unrelated.txt").write_text("keep")
    for each, at in ((policy, NOW), (recent, NOW + 7_000)):
        for name in (telemetry_file_name(each.run_id), summary_file_name(each.run_id)):
            os.utime(tmp_path / name, (at, at))
    clock[0] = NOW + 7_200

    removed = recorder.prune(max_age=3_600)

    assert removed == 2
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(
        ["unrelated.txt", telemetry_file_name(recent.run_id), summary_file_name(recent.run_id)]
    )
    assert recorder.runs == 1


def test_runs_with_pending_reservations_are_not_pruned(tmp_path: Path) -> None:
    clock = [NOW]
    recorder = TelemetryRecorder(tmp_path, boot_id=BOOT, clock=lambda: clock[0])
    recorder.reserve(_policy())
    clock[0] = NOW + 7_200

    recorder.prune(max_age=3_600)

    assert recorder.runs == 1


def test_counts_resume_after_a_guard_restart(tmp_path: Path) -> None:
    """guard 重啟後由 summary 接續：重啟不會讓 run 重新拿到整份預算（SEC-13）。"""
    policy = _policy(max_requests=2)
    first = TelemetryRecorder(tmp_path, boot_id=BOOT)
    first.reserve(policy)
    first.forwarded(policy.run_id, method="GET", path="/api", authenticated=False, at=NOW)
    first.denied(policy, Reason.PATH_EXCLUDED)
    first.flush()

    restarted = TelemetryRecorder(tmp_path, boot_id=UUID(int=7))
    assert restarted.reserve(policy)
    sequence = restarted.forwarded(
        policy.run_id, method="GET", path="/api", authenticated=False, at=NOW
    )

    assert sequence == 2
    assert not restarted.reserve(policy)
    summary = _summary(tmp_path)
    assert summary.forwarded == 2  # type: ignore[attr-defined]
    assert summary.denied == {"PATH_EXCLUDED": 1}  # type: ignore[attr-defined]
    assert summary.boot_id == UUID(int=7)  # type: ignore[attr-defined]
    assert summary.first_at == NOW  # type: ignore[attr-defined]
    assert [line.sequence for line in _lines(tmp_path)] == [1, 2]  # type: ignore[attr-defined]


@pytest.mark.parametrize("content", [b"{", b"{}"])
def test_unreadable_summaries_fail_closed(tmp_path: Path, content: bytes) -> None:
    (tmp_path / summary_file_name(RUN)).write_bytes(content)
    recorder = TelemetryRecorder(tmp_path, boot_id=BOOT)

    with pytest.raises(TelemetryWriteError):
        recorder.reserve(_policy())


def test_a_summary_of_another_scan_fails_closed(tmp_path: Path) -> None:
    first = TelemetryRecorder(tmp_path, boot_id=BOOT)
    first.denied(_policy(), Reason.PATH_EXCLUDED)
    first.flush()
    other_scan = replace(_policy(), scan_id=UUID(int=5))

    with pytest.raises(TelemetryWriteError):
        TelemetryRecorder(tmp_path, boot_id=BOOT).reserve(other_scan)


def test_a_run_cannot_change_its_scan(recorder: TelemetryRecorder) -> None:
    recorder.denied(_policy(), Reason.PATH_EXCLUDED)

    with pytest.raises(TelemetryWriteError):
        recorder.reserve(replace(_policy(), scan_id=UUID(int=5)))


def test_prune_failures_are_reported(recorder: TelemetryRecorder, tmp_path: Path) -> None:
    (tmp_path / telemetry_file_name(RUN)).write_bytes(b"")
    os.utime(tmp_path / telemetry_file_name(RUN), (0, 0))
    os.chmod(tmp_path, 0o500)
    try:
        with pytest.raises(TelemetryWriteError):
            recorder.prune(max_age=60)
    finally:
        os.chmod(tmp_path, 0o700)


def test_responses_of_unknown_runs_are_errors(recorder: TelemetryRecorder) -> None:
    with pytest.raises(TelemetryWriteError):
        recorder.response(RUN, sequence=1, status=200, at=NOW)


def test_line_append_failures_leave_the_count_unchanged(
    recorder: TelemetryRecorder, tmp_path: Path
) -> None:
    """summary 先寫、行後寫：中途失敗時磁碟上最多多算一個（保守），記憶體中的名額已釋放。"""
    policy = _policy(max_requests=1)
    (tmp_path / telemetry_file_name(RUN)).mkdir()
    recorder.reserve(policy)

    with pytest.raises(TelemetryWriteError):
        recorder.forwarded(policy.run_id, method="GET", path="/api", authenticated=False, at=NOW)

    assert recorder.reserve(policy)
    recorder.release(RUN)
    recorder.flush()  # 記憶體回到轉送之前：沒有轉送、也沒有轉送的時間
    summary = _summary(tmp_path)
    counts = (summary.forwarded, summary.first_at, summary.last_at)  # type: ignore[attr-defined]
    assert counts == (0, None, None)


def test_files_are_owner_only(recorder: TelemetryRecorder, tmp_path: Path) -> None:
    policy = _policy()
    recorder.reserve(policy)
    recorder.forwarded(policy.run_id, method="GET", path="/api", authenticated=False, at=NOW)

    assert (tmp_path / telemetry_file_name(RUN)).stat().st_mode & 0o777 == 0o600
    assert (tmp_path / summary_file_name(RUN)).stat().st_mode & 0o777 == 0o400


def test_lines_are_one_json_object_each(recorder: TelemetryRecorder, tmp_path: Path) -> None:
    policy = _policy()
    recorder.reserve(policy)
    recorder.forwarded(policy.run_id, method="GET", path="/api", authenticated=False, at=NOW)

    [line] = (tmp_path / telemetry_file_name(RUN)).read_bytes().splitlines()
    assert json.loads(line)["e"] == "request"


def test_unrecordable_requests_release_their_slot(recorder: TelemetryRecorder) -> None:
    policy = _policy(max_requests=1)
    recorder.reserve(policy)

    with pytest.raises(TelemetryWriteError):
        recorder.forwarded(RUN, method="GET", path="/a b", authenticated=False, at=NOW)

    assert recorder.reserve(policy)


def test_unrecordable_responses_are_errors(recorder: TelemetryRecorder) -> None:
    recorder.denied(_policy(), Reason.PATH_EXCLUDED)

    with pytest.raises(TelemetryWriteError):
        recorder.response(RUN, sequence=1, status=99, at=NOW)


def test_flush_writes_only_changed_runs(recorder: TelemetryRecorder, tmp_path: Path) -> None:
    policy = _policy()
    recorder.reserve(policy)
    recorder.forwarded(RUN, method="GET", path="/api", authenticated=False, at=NOW)
    before = (tmp_path / summary_file_name(RUN)).stat().st_ino

    recorder.flush()

    assert (tmp_path / summary_file_name(RUN)).stat().st_ino == before


def test_a_summary_that_cannot_be_read_fails_closed(tmp_path: Path) -> None:
    (tmp_path / summary_file_name(RUN)).mkdir()

    with pytest.raises(TelemetryWriteError):
        TelemetryRecorder(tmp_path, boot_id=BOOT).reserve(_policy())


def test_short_writes_are_retried_and_write_errors_reported(
    recorder: TelemetryRecorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy()
    recorder.reserve(policy)
    recorder.forwarded(RUN, method="GET", path="/api", authenticated=False, at=NOW)

    def fail(descriptor: int, data: object) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("secscan.guard.telemetry.os.write", fail)
    with pytest.raises(TelemetryWriteError, match="ENOSPC"):
        recorder.response(RUN, sequence=1, status=200, at=NOW)


def test_files_that_vanish_during_pruning_are_skipped(
    recorder: TelemetryRecorder, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Vanished:
        name = telemetry_file_name(RUN)

        def stat(self, *, follow_symlinks: bool) -> os.stat_result:
            raise FileNotFoundError

    monkeypatch.setattr("secscan.guard.telemetry.os.scandir", lambda _: [_Vanished()])

    assert recorder.prune(max_age=0) == 0


def test_listing_failures_are_reported(tmp_path: Path) -> None:
    recorder = TelemetryRecorder(tmp_path / "missing", boot_id=BOOT)

    with pytest.raises(TelemetryWriteError):
        recorder.prune(max_age=0)
