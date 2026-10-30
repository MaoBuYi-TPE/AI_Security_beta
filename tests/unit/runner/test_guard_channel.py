"""runner 與 guard 交換資料的一側（docs/DECISIONS.md §15.3、§15.7）。

- GuardChannel：寫入與刪除 policy（原子寫入、0400）、讀 guard 的 status、清除殘留。
- RunEgress：一個 run 的 token 與 policy；not_after、renew_until 的計算，封鎖與續約。
"""

import base64
import os
import stat
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest

from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.domain.budget import RunBudget
from secscan.guard.domain.credentials import parse_proxy_authorization, token_digest
from secscan.guard.domain.policy import (
    MAX_POLICY_BYTES,
    Policy,
    PolicyState,
    policy_file_name,
)
from secscan.guard.domain.status import STATUS_FILE_NAME, StatusIssue
from secscan.guard.domain.telemetry import summary_file_name
from secscan.guard.files import write_atomic
from secscan.runner.egress import GuardEndpoint, RunEgress
from secscan.runner.guard import GuardChannel, GuardUnavailableError
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.model import Lease
from secscan.scans.queue import EgressScope
from secscan.targets.domain import parse_ipv4, parse_origin
from tests.guard_support import ENDPOINT, GUARD_LISTEN, GuardDouble

NOW = 1_767_598_800.4
LEASE = Lease(
    run_id=UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"),
    scan_id=UUID("0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"),
    engine=Engine.FAKE,
    owner="runner-1",
)
SCOPE = Scope(
    origins=(parse_origin("http://lab-target:8080"), parse_origin("http://other:8080")),
    ips=(parse_ipv4("10.89.7.20"),),
    paths=("/api/items/{id}",),
    allow_all_paths=False,
    excluded_paths=("/api/admin",),
    methods=(HttpMethod.GET,),
)


BUDGET = RunBudget(requests_per_second=2, burst=1, max_requests=1_234)


def _egress(
    valid_until: datetime | None = None, auth_header: str | None = "x-api-key"
) -> EgressScope:
    return EgressScope(
        origin=parse_origin("http://lab-target:8080"),
        scope=SCOPE,
        valid_until=valid_until or datetime.fromtimestamp(NOW, UTC) + timedelta(days=1),
        budget=BUDGET,
        auth_header=auth_header,
    )


@pytest.fixture
def guard(tmp_path: Path) -> GuardDouble:
    return GuardDouble.create(tmp_path)


def _open(channel: GuardChannel, **overrides: object) -> RunEgress:
    options: dict[str, object] = {
        "lease": LEASE,
        "egress": _egress(),
        "endpoint": ENDPOINT,
        "now": NOW,
        "wall_clock_seconds": 600,
        "renew_until": NOW + 30,
    }
    options.update(overrides)
    return RunEgress.open(channel, **options)  # type: ignore[arg-type]


# --- GuardEndpoint ----------------------------------------------------------------------------


def test_endpoint_parsing() -> None:
    assert GuardEndpoint.parse("10.89.8.254:8080") == GuardEndpoint(
        IPv4Address("10.89.8.254"), 8080
    )
    assert ENDPOINT.listen == GUARD_LISTEN


@pytest.mark.parametrize(
    "text", ["10.89.8.254", "guard:8080", "10.89.8.254:0", "10.89.8.254:080", "010.89.8.254:8080"]
)
def test_endpoint_rejects_anything_else(text: str) -> None:
    with pytest.raises(ValueError, match="GUARD"):
        GuardEndpoint.parse(text)


# --- health -----------------------------------------------------------------------------------


def test_a_fresh_enforcing_guard_is_available(guard: GuardDouble) -> None:
    health = guard.channel().health()

    assert health.available
    assert health.boot_id == guard.boot_id


@pytest.mark.parametrize(
    ("change", "issue"),
    [
        ("vanish", StatusIssue.MISSING),
        ("stop", StatusIssue.NOT_ENFORCING),
        ("stale", StatusIssue.STALE),
        ("listen", StatusIssue.LISTEN),
        ("corrupt", StatusIssue.INVALID),
        ("symlink", StatusIssue.INVALID),
        ("directory", StatusIssue.INVALID),
    ],
)
def test_unhealthy_guards(guard: GuardDouble, change: str, issue: StatusIssue) -> None:
    if change == "vanish":
        guard.vanish()
    elif change == "stop":
        guard.stop()
    elif change == "stale":
        guard.write_status(guard.status(updated_at=int(NOW) - 3600))
    elif change == "listen":
        guard.write_status(guard.status(listen="10.89.8.253:8080"))
    elif change == "corrupt":
        write_atomic(guard.status_dir, STATUS_FILE_NAME, b"{")
    elif change == "symlink":
        guard.vanish()
        (guard.status_dir / STATUS_FILE_NAME).symlink_to(guard.status_dir / "elsewhere.json")
    else:
        guard.vanish()
        (guard.status_dir / STATUS_FILE_NAME).mkdir()

    health = guard.channel().health()

    assert not health.available
    assert health.issue is issue


def test_writable_needs_the_policy_directory(guard: GuardDouble) -> None:
    assert guard.channel().writable()

    os.chmod(guard.policies, stat.S_IRUSR | stat.S_IXUSR)
    try:
        assert not guard.channel().writable()
    finally:
        os.chmod(guard.policies, stat.S_IRWXU)
    assert guard.policy_files() == []


# --- RunEgress --------------------------------------------------------------------------------


def test_policy_is_built_from_the_grant_and_the_target(guard: GuardDouble) -> None:
    egress = _open(guard.channel())

    policy = egress.policy
    assert policy.run_id == LEASE.run_id
    assert policy.scan_id == LEASE.scan_id
    assert policy.state is PolicyState.ACTIVE
    assert policy.scope.origins == (parse_origin("http://lab-target:8080"),)  # 只有 target
    assert (policy.scope.ips, policy.scope.paths, policy.scope.methods) == (
        SCOPE.ips,
        SCOPE.paths,
        SCOPE.methods,
    )
    assert policy.scope.excluded_paths == SCOPE.excluded_paths
    assert policy.budget == BUDGET  # 這個 run 剩下的預算（佇列算好）
    assert policy.auth_header == "x-api-key"
    assert policy.renew_until == int(NOW) + 30
    assert policy.not_after == int(NOW) + 600


def test_not_after_is_capped_by_the_grant(guard: GuardDouble) -> None:
    valid_until = datetime.fromtimestamp(NOW + 100.9, UTC)

    egress = _open(guard.channel(), egress=_egress(valid_until))

    assert egress.policy.not_after == int(NOW + 100.9)


def test_the_proxy_url_carries_a_fresh_token(guard: GuardDouble) -> None:
    first, second = _open(guard.channel()), _open(guard.channel())

    url = urlsplit(first.proxy_url)
    assert (url.scheme, url.hostname, url.port) == ("http", "10.89.8.254", 8080)
    assert (url.path, url.query, url.fragment) == ("", "", "")
    assert url.username is not None
    assert url.password is not None
    header = base64.b64encode(f"{url.username}:{url.password}".encode()).decode()
    credentials = parse_proxy_authorization([f"Basic {header}"])
    assert credentials is not None
    assert credentials.run_id == LEASE.run_id
    assert token_digest(credentials.token) == first.policy.token_sha256
    assert first.proxy_url != second.proxy_url
    assert credentials.token not in repr(first)


def test_activate_writes_a_read_only_policy(guard: GuardDouble) -> None:
    egress = _open(guard.channel())

    egress.activate()

    assert guard.policy(LEASE.run_id) == egress.policy
    path = guard.policies / policy_file_name(LEASE.run_id)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o400


def test_renew_and_block(guard: GuardDouble) -> None:
    egress = _open(guard.channel())
    egress.activate()

    egress.renew(NOW + 45.7)
    renewed = guard.policy(LEASE.run_id)
    egress.block()
    egress.block()  # 可以重複呼叫
    blocked = guard.policy(LEASE.run_id)

    assert renewed is not None
    assert renewed.renew_until == int(NOW + 45.7)
    assert blocked is not None
    assert blocked.state is PolicyState.BLOCKED
    assert blocked.renew_until == renewed.renew_until


def test_a_blocked_policy_is_never_renewed(guard: GuardDouble) -> None:
    egress = _open(guard.channel())
    egress.activate()
    egress.block()

    egress.renew(NOW + 100)

    policy = guard.policy(LEASE.run_id)
    assert policy is not None
    assert policy.state is PolicyState.BLOCKED
    assert policy.renew_until == int(NOW) + 30  # 封鎖之後不再延長（突變檢查發現）


def test_blocking_before_activation_writes_nothing(guard: GuardDouble) -> None:
    egress = _open(guard.channel())

    egress.block()
    egress.discard()

    assert guard.policy_files() == []


def test_discard_removes_the_policy_and_is_idempotent(guard: GuardDouble) -> None:
    egress = _open(guard.channel())
    egress.activate()

    egress.discard()
    egress.discard()

    assert guard.policy_files() == []


def test_write_failures_mean_the_guard_is_unavailable(guard: GuardDouble) -> None:
    egress = _open(guard.channel())
    os.chmod(guard.policies, stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(GuardUnavailableError):
            egress.activate()
    finally:
        os.chmod(guard.policies, stat.S_IRWXU)


def test_remove_failures_mean_the_guard_is_unavailable(guard: GuardDouble) -> None:
    egress = _open(guard.channel())
    egress.activate()
    os.chmod(guard.policies, stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(GuardUnavailableError):
            egress.discard()
    finally:
        os.chmod(guard.policies, stat.S_IRWXU)


# --- 對帳與啟動時的清理（docs/DECISIONS.md §17.2、§17.4） ----------------------------------------


def _activated(guard: GuardDouble, run_id: UUID | None = None) -> UUID:
    lease = Lease(run_id or uuid4(), uuid4(), Engine.FAKE, "x")
    _open(guard.channel(), lease=lease).activate()
    return lease.run_id


def test_block_turns_a_leftover_policy_into_a_blocked_one(guard: GuardDouble) -> None:
    run_id = _activated(guard)
    before = guard.policy(run_id)
    assert before is not None

    assert guard.channel().block(run_id) is True

    after = guard.policy(run_id)
    assert after == before.blocked()
    assert after.state is PolicyState.BLOCKED


def test_block_leaves_a_blocked_policy_as_it_is(guard: GuardDouble) -> None:
    run_id = _activated(guard)
    guard.channel().block(run_id)
    path = guard.policies / policy_file_name(run_id)
    inode = path.stat().st_ino

    assert guard.channel().block(run_id) is True
    assert path.stat().st_ino == inode  # 沒有再寫一次


def test_block_of_a_missing_policy_reports_it(guard: GuardDouble) -> None:
    assert guard.channel().block(uuid4()) is False


@pytest.mark.parametrize("damage", ["symlink", "directory", "oversized", "corrupt", "other_run"])
def test_block_refuses_a_policy_it_cannot_trust(guard: GuardDouble, damage: str) -> None:
    """讀不出來或格式不符：拋 GuardUnavailableError，不動那個檔案（guard 本來就會拒絕它）。"""
    run_id = uuid4()
    path = guard.policies / policy_file_name(run_id)
    if damage == "symlink":
        path.symlink_to(guard.policies / policy_file_name(_activated(guard)))
    elif damage == "directory":
        path.mkdir()
    elif damage == "oversized":
        path.write_bytes(b" " * (MAX_POLICY_BYTES + 2))
    elif damage == "corrupt":
        path.write_bytes(b"{not json")
    else:
        other = _activated(guard)
        path.write_bytes((guard.policies / policy_file_name(other)).read_bytes())
    before = path.lstat()

    with pytest.raises(GuardUnavailableError):
        guard.channel().block(run_id)

    after = path.lstat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


def test_policy_runs_lists_only_policy_files(guard: GuardDouble) -> None:
    runs = {_activated(guard), _activated(guard)}
    (guard.policies / ".tmp-abc").write_bytes(b"x")
    (guard.policies / "README").write_bytes(b"keep")
    (guard.policies / "notes.json").write_bytes(b"x")
    (guard.policies / f"{str(uuid4()).upper()}.json").write_bytes(b"x")  # 不是標準格式
    (guard.policies / f"{uuid4()}.json").mkdir()

    assert guard.channel().policy_runs() == runs


def test_an_entry_that_disappears_while_listing_is_skipped(
    guard: GuardDouble, monkeypatch: pytest.MonkeyPatch
) -> None:
    """另一個 runner 正在以 rename 寫入：列出之後才消失的條目跳過，不讓啟動失敗。"""
    kept = _activated(guard)
    gone = _activated(guard)
    temporary = guard.policies / ".tmp-gone"
    temporary.write_bytes(b"x")
    os.utime(temporary, (NOW - 61, NOW - 61))
    real_lstat = Path.lstat

    def vanishing(path: Path) -> os.stat_result:
        if path.name in {policy_file_name(gone), ".tmp-gone"}:
            raise FileNotFoundError(path.name)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", vanishing)
    channel = GuardChannel(
        guard.policies,
        guard.status_dir,
        telemetry_dir=guard.telemetry,
        listen=GUARD_LISTEN,
        clock=lambda: NOW,
    )

    assert channel.policy_runs() == {kept}
    assert channel.sweep_temporary(older_than=60) == 0


def test_sweeping_tolerates_a_vanished_file_and_reports_other_errors(
    guard: GuardDouble, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = guard.policies / ".tmp-stale"
    stale.write_bytes(b"x")
    os.utime(stale, (NOW - 61, NOW - 61))
    channel = GuardChannel(
        guard.policies,
        guard.status_dir,
        telemetry_dir=guard.telemetry,
        listen=GUARD_LISTEN,
        clock=lambda: NOW,
    )

    def vanished(path: Path) -> None:
        raise FileNotFoundError(path.name)

    def denied(path: Path) -> None:
        raise PermissionError(path.name)

    monkeypatch.setattr(Path, "unlink", vanished)
    assert channel.sweep_temporary(older_than=60) == 0
    monkeypatch.setattr(Path, "unlink", denied)
    with pytest.raises(GuardUnavailableError):
        channel.sweep_temporary(older_than=60)


def test_an_entry_that_cannot_be_inspected_is_reported(
    guard: GuardDouble, monkeypatch: pytest.MonkeyPatch
) -> None:
    _activated(guard)

    def denied(path: Path) -> os.stat_result:
        raise PermissionError(path.name)

    monkeypatch.setattr(Path, "lstat", denied)

    with pytest.raises(GuardUnavailableError):
        guard.channel().policy_runs()


def test_an_unreadable_policy_directory_is_reported(guard: GuardDouble) -> None:
    guard.policies.rename(guard.policies.with_name("moved"))

    with pytest.raises(GuardUnavailableError):
        guard.channel().policy_runs()
    with pytest.raises(GuardUnavailableError):
        guard.channel().sweep_temporary(older_than=60)


def test_only_stale_temporary_files_are_swept(guard: GuardDouble) -> None:
    """暫存檔可能是另一個 runner 正在寫的：超過 60 秒才刪。"""
    run_id = _activated(guard)
    stale, fresh = guard.policies / ".tmp-stale", guard.policies / ".tmp-fresh"
    stale.write_bytes(b"x")
    fresh.write_bytes(b"x")
    os.utime(stale, (NOW - 61, NOW - 61))
    os.utime(fresh, (NOW - 59, NOW - 59))
    channel = GuardChannel(
        guard.policies,
        guard.status_dir,
        telemetry_dir=guard.telemetry,
        listen=GUARD_LISTEN,
        clock=lambda: NOW,
    )

    assert channel.sweep_temporary(older_than=60) == 1
    assert guard.policy_files() == [".tmp-fresh", policy_file_name(run_id)]


def test_a_policy_written_despite_an_error_can_still_be_blocked_and_removed(
    guard: GuardDouble, monkeypatch: pytest.MonkeyPatch
) -> None:
    """os.replace 成功、之後的 fsync 失敗：檔案已經生效，封鎖與刪除仍要處理它（審查發現）。"""
    channel = guard.channel()
    egress = _open(channel)
    real_write = channel.write

    def write_then_fail(policy: Policy) -> None:
        real_write(policy)
        raise GuardUnavailableError("無法寫入 guard 的 policy（EIO）")

    monkeypatch.setattr(channel, "write", write_then_fail)
    with pytest.raises(GuardUnavailableError):
        egress.activate()
    monkeypatch.setattr(channel, "write", real_write)

    egress.block()
    blocked = guard.policy(LEASE.run_id)
    egress.discard()

    assert blocked is not None
    assert blocked.state is PolicyState.BLOCKED
    assert guard.policy_files() == []


# --- telemetry 的 summary（docs/DECISIONS.md §16.4）------------------------------------------


def test_a_run_without_a_summary_has_none(guard: GuardDouble) -> None:
    assert guard.channel().summary(LEASE.run_id) is None


def test_the_summary_is_read_strictly(guard: GuardDouble) -> None:
    guard.write_summary(
        LEASE.run_id, LEASE.scan_id, forwarded=3, denied={"PATH_EXCLUDED": 2}, exhausted=True
    )

    summary = guard.channel().summary(LEASE.run_id)

    assert summary is not None
    assert (summary.forwarded, summary.denied_total, summary.exhausted) == (3, 2, True)


@pytest.mark.parametrize("content", [b"{", b"{}", b" " * 70_000])
def test_unreadable_summaries_mean_the_guard_is_unavailable(
    guard: GuardDouble, content: bytes
) -> None:
    (guard.telemetry / summary_file_name(LEASE.run_id)).write_bytes(content)

    with pytest.raises(GuardUnavailableError):
        guard.channel().summary(LEASE.run_id)


def test_symlinked_summaries_are_refused(guard: GuardDouble, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(b"{}")
    (guard.telemetry / summary_file_name(LEASE.run_id)).symlink_to(elsewhere)

    with pytest.raises(GuardUnavailableError):
        guard.channel().summary(LEASE.run_id)
