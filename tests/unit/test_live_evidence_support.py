"""live 的原始證據輔助程式（tests/live/evidence_assertions.py）：不連 Docker 的部分。

T23a 起 runs volume 在 run 結束之後只剩加密檔：讀原始輸出要先等加密完成、再以 export-evidence
解密；直接讀 volume 只用來確認密文。這裡以替身取代 docker 指令，確認等待、錯誤與比對的邏輯。
"""

import hashlib
import subprocess
from typing import Any

import pytest

from tests.live import evidence_assertions as evidence

RUN = "6f1c2d3e-4b5a-4c6d-8e7f-001122334455"


def _completed(code: int, stdout: bytes = b"", stderr: bytes = b"") -> Any:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout, stderr=stderr)


def test_waiting_ends_when_only_the_sealed_directory_is_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    states = iter([["in", "out", "sealed"], ["sealed"]])
    monkeypatch.setattr(evidence, "entries", lambda _run: next(states))
    monkeypatch.setattr(evidence, "wait_for", lambda check, **_: check() or check())

    assert evidence.wait_sealed(RUN) is True


def test_a_run_without_a_directory_has_nothing_to_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence, "entries", lambda _run: None)
    exported: list[str] = []
    monkeypatch.setattr(evidence, "export", lambda _run, path: exported.append(path))

    assert evidence.run_file(RUN, "out/zap.log") is None
    assert exported == []


def test_entries_come_from_a_read_only_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence, "_busybox", lambda _script: _completed(0, b"sealed\n"))
    assert evidence.entries(RUN) == ["sealed"]
    monkeypatch.setattr(evidence, "_busybox", lambda _script: _completed(1))
    assert evidence.entries(RUN) is None


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (_completed(0, b"plain"), b"plain"),
        (_completed(1, stderr="找不到這個檔案的加密檔。".encode()), None),
        (_completed(1, stderr="沒有這個 run 的原始證據（不存在或已清除）。".encode()), None),
    ],
)
def test_export_reads_stdout_or_reports_a_missing_file(
    monkeypatch: pytest.MonkeyPatch, result: Any, expected: bytes | None
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: result)

    assert evidence.export(RUN, "out/zap.log") == expected


def test_other_export_failures_stop_the_test(monkeypatch: pytest.MonkeyPatch) -> None:
    failed = _completed(1, stderr="加密檔解不開：金鑰不對，或內容被改過。".encode())
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: failed)

    with pytest.raises(AssertionError, match="解不開"):
        evidence.export(RUN, "out/zap.log")


def test_sealed_bytes_must_not_contain_known_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence, "wait_sealed", lambda _run: True)
    monkeypatch.setattr(evidence, "sealed_bytes", lambda _run: b"./sealed\ngAAAAA...")

    evidence.assert_sealed(RUN, [b"lab.example"])
    with pytest.raises(AssertionError, match="明文"):
        evidence.assert_sealed(RUN, [b"gAAAAA"])


def test_exports_are_compared_with_the_artifact_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {"out/report.json": b"report", "in/plan.json": b"plan"}
    monkeypatch.setattr(evidence, "export", lambda _run, path: files.get(path))
    artifacts = [
        {"kind": "output", "path": "report.json", "sha256": hashlib.sha256(b"report").hexdigest()},
        {"kind": "input", "path": "plan.json", "sha256": hashlib.sha256(b"plan").hexdigest()},
    ]

    evidence.assert_exports_match(RUN, artifacts)
    with pytest.raises(AssertionError, match=r"report\.json"):
        evidence.assert_exports_match(RUN, [{**artifacts[0], "sha256": "0" * 64}])
