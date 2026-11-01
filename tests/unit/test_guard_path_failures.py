"""Capture failures must remain failures while preserving encrypted diagnostic evidence."""

import io
import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet

from tests.guard_path_evidence import EvidenceError
from tests.live import guard_paths_support as support
from tests.live import test_guard_paths_live as live
from tests.live.lab_support import Target

TARGET = Target("secscan-live-lab-test", "lab-test", "10.89.10.221", 3000)


def _store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> support.EvidenceStore:
    monkeypatch.setenv("SECSCAN_GUARD_PATH_RECORD_DIR", str(tmp_path))
    return support.EvidenceStore.open("strict-1", "failure-test")


def _read(store: support.EvidenceStore, name: str) -> bytes:
    return Fernet(store.key).decrypt((store.directory / (name + ".fernet")).read_bytes())


def test_capture_exit_retains_stderr_and_never_masks_it_with_missing_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path, monkeypatch)
    capture = support.Capture(TARGET, store)
    process = Mock()
    process.poll.return_value = 1
    process.returncode = 1
    process.wait.return_value = 1
    process.communicate.return_value = (None, b"synthetic-private-stderr")
    capture.process = process
    capture.output = io.BytesIO()
    capture.path.write_bytes(Fernet(store.key).encrypt(b'{"kind":"ready"}') + b"\n")
    commands: list[tuple[str, ...]] = []

    def command(store: support.EvidenceStore, label: str, *arguments: str) -> dict[str, Any]:
        commands.append(arguments)
        result = {"returncode": 1, "error": None}
        store.write(label + ".result.json", result)
        return result

    monkeypatch.setattr(support, "docker", Mock(side_effect=AssertionError("missing-container")))
    monkeypatch.setattr(support, "docker_evidence", command, raising=False)
    with pytest.raises(EvidenceError, match="capture process exited unsuccessfully"):
        capture.finish()

    assert not any(command[0] == "stop" for command in commands)
    assert _read(store, "capture-stderr.log") == b"synthetic-private-stderr"
    assert json.loads(_read(store, "capture-exit.json"))["returncode"] == 1
    assert (
        b"synthetic-private-stderr"
        not in (store.directory / "capture-stderr.log.fernet").read_bytes()
    )
    assert json.loads(_read(store, "capture-validation.json"))["valid"] is False


@pytest.mark.parametrize("api_fails", [False, True])
def test_measure_saves_every_available_artifact_before_capture_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    api_fails: bool,
) -> None:
    store = _store(tmp_path, monkeypatch)
    monkeypatch.setattr(support.EvidenceStore, "open", Mock(return_value=store))
    capture = Mock()
    capture.start.return_value = capture
    capture.finish.side_effect = EvidenceError("capture incomplete")
    monkeypatch.setattr(live, "Capture", Mock(return_value=capture))
    monkeypatch.setattr(live, "environment", lambda target: {"test": True})
    monkeypatch.setattr(live, "_zap_container", lambda scan: "secscan-run-run")
    monkeypatch.setattr(
        live, "inspect", lambda name: {"Image": "sha256:test", "Config": {"Image": "test"}}
    )
    monkeypatch.setattr(live, "_all_observations", lambda *args: [])
    monkeypatch.setattr(live, "requests_since", lambda started: [])
    monkeypatch.setattr(live, "scan_runs", lambda scan: [{"id": "run", "engine": "zap"}])
    monkeypatch.setattr(live, "frozen_scan_snapshot", lambda scan: {"operations": []})
    monkeypatch.setattr(live, "volume_file", lambda *args: b"{}")

    def lifecycle(
        store: support.EvidenceStore, label: str, name: str, started: float
    ) -> dict[str, Any]:
        store.write(label + "-inspect.stdout.log", b'{"State":{"ExitCode":1}}')
        store.write(label + "-logs.stdout.log", b"synthetic-target-crash")
        store.write(label + "-events.stdout.log", b'{"Action":"die"}')
        return {"recorded": True}

    monkeypatch.setattr(live, "container_diagnostics", lifecycle, raising=False)
    item = Mock()
    item.scan.return_value = "scan"
    item.finished_zap.return_value = {}
    item.operator.data.return_value = {"id": "scan"}
    if api_fails:
        item.operator.data.side_effect = RuntimeError("synthetic API unavailable")

    expected = {
        "scan.json",
        "frozen-scan.json",
        "guard-decisions.jsonl",
        "telemetry.jsonl",
        "summary.json",
        "report.json",
        "zap.log",
        "manifest.json",
        "target-inspect.stdout.log",
        "target-logs.stdout.log",
        "target-events.stdout.log",
    }

    def reject_capture() -> None:
        assert all((store.directory / (name + ".fernet")).exists() for name in expected)
        raise EvidenceError("capture incomplete")

    capture.finish.side_effect = reject_capture
    with pytest.raises(EvidenceError, match="capture incomplete"):
        live._measure("strict-1", "failure-test", item, TARGET)

    manifest = json.loads(_read(store, "evidence-manifest.json"))
    assert {name + ".fernet" for name in expected} <= manifest.keys()
    capture.cleanup.assert_called_once()
    errors = json.loads(_read(store, "collection-errors.json"))
    assert bool(errors) is api_fails


@pytest.mark.parametrize(
    ("returncode", "events"),
    [
        (1, [{"kind": "complete", "dropped": 0, "limit_reached": False}]),
        (0, []),
        (0, [{"kind": "ready"}]),
        (0, [{"kind": "error"}, {"kind": "complete", "dropped": 0, "limit_reached": False}]),
        (0, [{"kind": "complete", "dropped": 1, "limit_reached": False}]),
        (0, [{"kind": "complete", "dropped": 0, "limit_reached": True}]),
    ],
)
def test_capture_never_accepts_partial_or_failed_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    events: list[dict[str, Any]],
) -> None:
    store = _store(tmp_path, monkeypatch)
    capture = support.Capture(TARGET, store)
    capture.process = Mock(returncode=returncode)
    capture.output = io.BytesIO()
    monkeypatch.setattr(capture, "_settle", lambda: None)
    monkeypatch.setattr(capture, "events", lambda: events)

    with pytest.raises(EvidenceError):
        capture.finish()

    assert json.loads(_read(store, "capture-validation.json"))["valid"] is False


def test_command_failure_keeps_stdout_stderr_and_exit_code_encrypted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path, monkeypatch)
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(
            return_value=subprocess.CompletedProcess(
                ["docker", "inspect"], 1, b"synthetic-private-output", b"synthetic-private-error"
            )
        ),
    )

    result = support.docker_evidence(store, "target-inspect", "inspect", TARGET.container)

    assert result["returncode"] == 1
    assert _read(store, "target-inspect.stdout.log") == b"synthetic-private-output"
    assert _read(store, "target-inspect.stderr.log") == b"synthetic-private-error"
    assert all(b"synthetic-private" not in path.read_bytes() for path in store.directory.iterdir())
