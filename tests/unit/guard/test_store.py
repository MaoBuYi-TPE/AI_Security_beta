"""guard 讀取 policy 檔（docs/DECISIONS.md §15.3）與 runner、guard 共用的原子寫入。

每個請求 stat 一次，inode、mtime 或 size 變了才重讀；只接受一般檔案（O_NOFOLLOW）；快取有上限，
損毀的結果也快取（不必每個請求重新解析）。
"""

import os
import stat
from collections.abc import Callable
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard import store as store_module
from secscan.guard.domain.budget import RunBudget
from secscan.guard.domain.policy import (
    MAX_POLICY_BYTES,
    Policy,
    PolicyError,
    PolicyState,
    decode_policy,
    encode_policy,
    policy_file_name,
)
from secscan.guard.files import AtomicWriteError, remove_file, write_atomic
from secscan.guard.store import PolicyStore
from secscan.targets.domain import parse_ipv4, parse_origin

RUN_ID = UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")


def _policy(run_id: UUID = RUN_ID, *, renew_until: int = 1_767_598_830) -> Policy:
    return Policy(
        run_id=run_id,
        scan_id=uuid4(),
        state=PolicyState.ACTIVE,
        token_sha256="ab" * 32,
        not_after=1_767_600_000,
        renew_until=renew_until,
        scope=Scope(
            origins=(parse_origin("http://lab-target:8080"),),
            ips=(parse_ipv4("10.89.7.20"),),
            paths=("/api",),
            allow_all_paths=False,
            excluded_paths=(),
            methods=(HttpMethod.GET,),
        ),
        budget=RunBudget(requests_per_second=2, burst=1, max_requests=100),
        auth_header=None,
    )


def _write(directory: Path, policy: Policy) -> None:
    write_atomic(directory, policy_file_name(policy.run_id), encode_policy(policy))


class _CountingDecode:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, raw: bytes, *, run_id: UUID) -> Policy:
        self.calls += 1
        return decode_policy(raw, run_id=run_id)


@pytest.fixture
def decode() -> _CountingDecode:
    return _CountingDecode()


@pytest.fixture
def store(tmp_path: Path, decode: _CountingDecode) -> PolicyStore:
    return PolicyStore(tmp_path, decode=decode)


# --- 原子寫入 ---------------------------------------------------------------------------------


def test_atomic_write_creates_a_read_only_file(tmp_path: Path) -> None:
    write_atomic(tmp_path, "a.json", b"{}")

    info = os.stat(tmp_path / "a.json")
    assert stat.S_IMODE(info.st_mode) == 0o400
    assert (tmp_path / "a.json").read_bytes() == b"{}"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["a.json"]


def test_atomic_write_replaces_with_a_new_inode(tmp_path: Path) -> None:
    write_atomic(tmp_path, "a.json", b"1")
    before = os.stat(tmp_path / "a.json").st_ino

    write_atomic(tmp_path, "a.json", b"2")

    assert (tmp_path / "a.json").read_bytes() == b"2"
    assert os.stat(tmp_path / "a.json").st_ino != before
    assert sorted(path.name for path in tmp_path.iterdir()) == ["a.json"]


@pytest.mark.parametrize("name", ["../x.json", "a/b.json", "", ".", "..", ".hidden"])
def test_atomic_write_only_accepts_plain_names(tmp_path: Path, name: str) -> None:
    with pytest.raises(AtomicWriteError):
        write_atomic(tmp_path, name, b"{}")


def test_atomic_write_refuses_a_symlinked_directory(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)

    with pytest.raises(AtomicWriteError):
        write_atomic(tmp_path / "link", "a.json", b"{}")
    assert list(real.iterdir()) == []


def test_atomic_write_leaves_nothing_behind_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object, **__: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", broken)

    with pytest.raises(AtomicWriteError, match="ENOSPC"):
        write_atomic(tmp_path, "a.json", b"{}")
    assert list(tmp_path.iterdir()) == []


def test_remove_file_is_idempotent(tmp_path: Path) -> None:
    write_atomic(tmp_path, "a.json", b"{}")

    remove_file(tmp_path, "a.json")
    remove_file(tmp_path, "a.json")

    assert list(tmp_path.iterdir()) == []


def test_remove_file_reports_other_failures(tmp_path: Path) -> None:
    (tmp_path / "dir.json").mkdir()

    with pytest.raises(AtomicWriteError):
        remove_file(tmp_path, "dir.json")


# --- PolicyStore ------------------------------------------------------------------------------


def test_missing_policy_is_none(store: PolicyStore) -> None:
    assert store.load(RUN_ID) is None


def test_loads_and_compiles_the_policy(tmp_path: Path, store: PolicyStore) -> None:
    policy = _policy()
    _write(tmp_path, policy)

    compiled = store.load(RUN_ID)

    assert compiled is not None
    assert compiled.policy == policy
    assert compiled.rules.methods == frozenset({"GET"})


def test_unchanged_files_are_parsed_once(
    tmp_path: Path, store: PolicyStore, decode: _CountingDecode
) -> None:
    _write(tmp_path, _policy())

    for _ in range(5):
        store.load(RUN_ID)

    assert decode.calls == 1


def test_a_replaced_file_is_read_again(
    tmp_path: Path, store: PolicyStore, decode: _CountingDecode
) -> None:
    _write(tmp_path, _policy())
    first = store.load(RUN_ID)
    renewed = _policy(renew_until=1_767_598_999)
    write_atomic(tmp_path, policy_file_name(RUN_ID), encode_policy(renewed))

    second = store.load(RUN_ID)

    assert decode.calls == 2
    assert first is not None
    assert second is not None
    assert second.policy.renew_until == 1_767_598_999


def test_a_removed_file_is_forgotten(tmp_path: Path, store: PolicyStore) -> None:
    _write(tmp_path, _policy())
    assert store.load(RUN_ID) is not None

    remove_file(tmp_path, policy_file_name(RUN_ID))

    assert store.load(RUN_ID) is None


def test_corrupt_results_are_cached_too(
    tmp_path: Path, store: PolicyStore, decode: _CountingDecode
) -> None:
    write_atomic(tmp_path, policy_file_name(RUN_ID), b"{not json")

    for _ in range(3):
        with pytest.raises(PolicyError):
            store.load(RUN_ID)

    assert decode.calls == 1


def test_symlinks_are_refused(tmp_path: Path, store: PolicyStore) -> None:
    other = uuid4()
    _write(tmp_path, _policy(other))
    (tmp_path / policy_file_name(RUN_ID)).symlink_to(tmp_path / policy_file_name(other))

    with pytest.raises(PolicyError, match="一般檔案"):
        store.load(RUN_ID)


@pytest.mark.parametrize(
    "make",
    [
        lambda path: path.mkdir(),
        lambda path: os.mkfifo(path),
    ],
)
def test_special_files_are_refused(
    tmp_path: Path, store: PolicyStore, make: Callable[[Path], None]
) -> None:
    make(tmp_path / policy_file_name(RUN_ID))

    with pytest.raises(PolicyError, match="一般檔案"):
        store.load(RUN_ID)


def test_oversized_files_are_refused_without_parsing(
    tmp_path: Path, store: PolicyStore, decode: _CountingDecode
) -> None:
    (tmp_path / policy_file_name(RUN_ID)).write_bytes(b" " * (MAX_POLICY_BYTES + 1))

    with pytest.raises(PolicyError, match="大小"):
        store.load(RUN_ID)
    assert decode.calls == 0


def test_unreadable_files_are_errors(tmp_path: Path, store: PolicyStore) -> None:
    _write(tmp_path, _policy())
    os.chmod(tmp_path / policy_file_name(RUN_ID), 0)

    try:
        with pytest.raises(PolicyError, match="讀不到"):
            store.load(RUN_ID)
    finally:
        os.chmod(tmp_path / policy_file_name(RUN_ID), 0o400)


def test_cache_is_bounded(tmp_path: Path, decode: _CountingDecode) -> None:
    store = PolicyStore(tmp_path, decode=decode, max_cached=2)
    runs = [uuid4() for _ in range(3)]
    for run_id in runs:
        _write(tmp_path, _policy(run_id))
        store.load(run_id)

    store.load(runs[0])  # 已被擠出快取：重新解析

    assert decode.calls == 4
    assert store.cached == 2


def test_a_file_replaced_while_reading_is_read_again(
    tmp_path: Path, store: PolicyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """runner 每 5 秒換一次檔：stat 與開檔之間剛好被換掉時重讀一次，不誤拒（審查建議）。"""
    _write(tmp_path, _policy())
    real = store_module._read_regular
    calls: list[int] = []

    def replaced_once(path: Path, expected: os.stat_result) -> bytes:
        calls.append(1)
        if len(calls) == 1:
            raise store_module.ReplacedError
        return real(path, os.stat(path, follow_symlinks=False))

    monkeypatch.setattr(store_module, "_read_regular", replaced_once)

    assert store.load(RUN_ID) is not None
    assert len(calls) == 2


def test_a_file_that_keeps_changing_is_an_error(
    tmp_path: Path, store: PolicyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, _policy())

    def always(path: Path, expected: os.stat_result) -> bytes:
        raise store_module.ReplacedError

    monkeypatch.setattr(store_module, "_read_regular", always)

    with pytest.raises(store_module.ReplacedError):
        store.load(RUN_ID)
