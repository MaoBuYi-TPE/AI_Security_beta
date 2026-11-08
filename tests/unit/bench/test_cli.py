"""bench 的離線指令與結果目錄的讀回（BENCH-03、12；make bench-check、make bench-evaluate）。"""

import hashlib
import json
import runpy
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from benchmarks.batch import (
    SPEC_FILE,
    comparison_document,
    comparison_file,
    labeled_scan,
    load_batch,
    scan_document,
    scan_file,
)
from benchmarks.cli import main
from benchmarks.collect import CollectError, normalize_comparison
from benchmarks.manifest import MANIFEST_FILE, REQUIRED_PROVENANCE, build_manifest
from benchmarks.results import reserve, seal, write_bytes, write_json
from benchmarks.schedule import build_schedule
from benchmarks.spec import parse_spec
from benchmarks.stats import SMOKE_NOTICE
from tests.unit.bench.records import TRUTH
from tests.unit.bench.samples import comparison_json, finding_json, scan_json

SMOKE = Path(__file__).resolve().parents[3] / "benchmarks" / "experiments" / "t31-smoke.yaml"


def _write_batch(root: Path, name: str, *, complete: bool = True) -> Path:
    """和 Live 的 harness 相同的寫法（benchmarks.batch 與 results），只是 scan 來自樣本。"""
    content = SMOKE.read_bytes()
    spec = parse_spec(content)
    directory = reserve(root, name)
    files = {SPEC_FILE: write_bytes(directory, SPEC_FILE, content)}
    digest = hashlib.sha256(content).hexdigest()
    scans, comparisons, baseline = [], [], None
    schedule = build_schedule(spec)
    for item in schedule if complete else schedule[:1]:
        sqli = finding_json(
            "sql-injection", route="/search", parameter_location="query", parameter_name="q"
        )
        document = scan_document(
            item, target_kind="fixture", scan=scan_json(), findings=[sqli], observation_count=4
        )
        files[scan_file(item.position)] = write_json(directory, scan_file(item.position), document)
        labeled = labeled_scan(document)
        scans.append(labeled)
        if item.role == "baseline":
            baseline = labeled
        elif item.role == "current" and baseline is not None and item.comparison is not None:
            snapshot, findings = comparison_json(
                baseline.scan.id, labeled.scan.id, [(baseline.scan.findings[0].id, "inconclusive")]
            )
            name_ = comparison_file(item.comparison)
            files[name_] = write_json(
                directory, name_, comparison_document(item.comparison, snapshot, findings)
            )
            comparisons.append((item.comparison, normalize_comparison(snapshot, findings)))
    manifest = build_manifest(
        spec=spec,
        spec_sha256=digest,
        schedule=schedule,
        scans=scans,
        comparisons=comparisons,
        provenance=dict.fromkeys(REQUIRED_PROVENANCE, "unit"),
        files=files,
        complete=complete,
        stopped_reason=None if complete else "AssertionError",
    )
    write_json(directory, MANIFEST_FILE, manifest)
    seal(directory)
    return directory


def _truth(tmp_path: Path) -> Path:
    path = tmp_path / "truth.yaml"
    path.write_text(json.dumps(TRUTH), encoding="utf-8")
    return path


def test_check_spec_reports_the_schedule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check-spec", str(SMOKE), "t31-smoke", "--results-root", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "t31-smoke（smoke）：4 個 scan" in output


@pytest.mark.parametrize("name", ["../escape", "a b", ""])
def test_check_spec_refuses_names_with_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    assert main(["check-spec", str(SMOKE), name, "--results-root", str(tmp_path)]) == 2
    assert "BENCH_NAME" in capsys.readouterr().err


def test_check_spec_refuses_an_existing_results_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "taken").mkdir()

    assert main(["check-spec", str(SMOKE), "taken", "--results-root", str(tmp_path)]) == 2
    assert "已經存在" in capsys.readouterr().err


def test_check_spec_refuses_an_invalid_or_missing_spec(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: a\nname: b\n", encoding="utf-8")

    assert main(["check-spec", str(bad), "x", "--results-root", str(tmp_path)]) == 2
    assert (
        main(["check-spec", str(tmp_path / "none.yaml"), "x", "--results-root", str(tmp_path)]) == 2
    )
    errors = capsys.readouterr().err
    assert "重複的鍵" in errors


def test_evaluate_reads_a_complete_batch_and_writes_json_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _write_batch(tmp_path / "results", "run-1")
    before = sorted(path.name for path in directory.iterdir())

    code = main(
        [
            "evaluate",
            "run-1",
            "--results-root",
            str(tmp_path / "results"),
            "--truth",
            str(_truth(tmp_path)),
        ]
    )

    assert code == 0
    document: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert document["name"] == "run-1"
    assert document["notices"][0] == SMOKE_NOTICE
    assert len(document["scans"]) == 4
    assert len(document["inputs"]["ground_truth"]["fixture"]) == 64
    assert document["rescans"][0]["false_repair"] == 0
    assert document["scans"][0]["detection"]["detected_cases"] == ["SQLI-1"]
    # 只讀：結果目錄沒有多出任何檔案。
    assert sorted(path.name for path in directory.iterdir()) == before


def test_evaluate_without_ground_truth_reports_resources_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_batch(tmp_path, "run-2")

    assert main(["evaluate", "run-2", "--results-root", str(tmp_path)]) == 0

    document = json.loads(capsys.readouterr().out)
    assert document["scans"][0]["detection"] is None
    assert document["scans"][0]["resources"]["requests_sent"] == 900


def test_evaluate_passes_the_label_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_batch(tmp_path, "run-3")
    adjudications = tmp_path / "adjudications.yaml"
    adjudications.write_text(json.dumps({"version": 1, "items": []}), encoding="utf-8")
    pairs = tmp_path / "pairs.yaml"
    pairs.write_text(json.dumps({"version": 1, "complete": False}), encoding="utf-8")

    code = main(
        [
            "evaluate",
            "run-3",
            "--results-root",
            str(tmp_path),
            "--adjudications",
            str(adjudications),
            "--pair-labels",
            str(pairs),
        ]
    )

    assert code == 0
    inputs = json.loads(capsys.readouterr().out)["inputs"]
    assert len(inputs["adjudications"]) == len(inputs["pair_labels"]) == 64


def test_evaluate_refuses_an_incomplete_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_batch(tmp_path, "run-4", complete=False)

    assert main(["evaluate", "run-4", "--results-root", str(tmp_path)]) == 2
    assert "整批作廢" in capsys.readouterr().err


def test_evaluate_refuses_a_modified_batch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _write_batch(tmp_path, "run-5")
    path = directory / scan_file(1)
    path.chmod(0o600)
    path.write_text("{}", encoding="utf-8")

    assert main(["evaluate", "run-5", "--results-root", str(tmp_path)]) == 2
    assert "SHA256SUMS" in capsys.readouterr().err


def test_evaluate_needs_holdout_on_a_frozen_truth(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_batch(tmp_path, "run-6")

    code = main(
        [
            "evaluate",
            "run-6",
            "--results-root",
            str(tmp_path),
            "--truth",
            str(_truth(tmp_path)),
            "--include-holdout",
        ]
    )

    assert code == 2
    assert "凍結" in capsys.readouterr().err


def test_load_batch_checks_the_spec_copy(tmp_path: Path) -> None:
    directory = _write_batch(tmp_path, "run-7")
    manifest = json.loads((directory / MANIFEST_FILE).read_text(encoding="utf-8"))
    batch = load_batch(directory)

    assert len(batch.scans) == len(manifest["scans"]) == 4
    assert batch.comparisons[0][0] == "c-fixture"


@pytest.mark.parametrize(
    ("document", "problem"),
    [
        ({"scan": {}, "findings": [], "observation_count": 0}, "labels"),
        ({"labels": {}, "scan": {}, "findings": {}, "observation_count": 0}, "findings"),
        ({"labels": {}, "findings": [], "observation_count": 0}, "scan"),
        (
            {"labels": {}, "scan": {}, "findings": [], "observation_count": True},
            "observation_count",
        ),
    ],
)
def test_a_malformed_scan_file_is_refused(document: dict[str, Any], problem: str) -> None:
    with pytest.raises(CollectError, match=problem):
        labeled_scan(document)


def _rewrite(directory: Path, name: str, change: Any) -> None:
    """改寫一個檔案並重新封存（模擬內容一致、但彼此對不上的批次）。"""
    document = json.loads((directory / name).read_text(encoding="utf-8"))
    change(document)
    for path in (directory / name, directory / "SHA256SUMS"):
        path.chmod(0o600)
        path.unlink()
    write_json(directory, name, document)
    seal(directory)


def test_load_batch_refuses_files_that_disagree_with_the_manifest(tmp_path: Path) -> None:
    directory = _write_batch(tmp_path, "run-8")
    _rewrite(directory, MANIFEST_FILE, lambda m: m["scans"][0].update(scan_id=str(uuid4())))

    with pytest.raises(CollectError, match="scan 檔和 manifest"):
        load_batch(directory)


def test_load_batch_refuses_a_comparison_that_disagrees(tmp_path: Path) -> None:
    directory = _write_batch(tmp_path, "run-9")
    _rewrite(directory, MANIFEST_FILE, lambda m: m["comparisons"][0].update(id=str(uuid4())))

    with pytest.raises(CollectError, match="比較檔"):
        load_batch(directory)


def test_load_batch_refuses_a_replaced_spec(tmp_path: Path) -> None:
    directory = _write_batch(tmp_path, "run-10")
    _rewrite(directory, MANIFEST_FILE, lambda m: m.update(spec_sha256="0" * 64))

    with pytest.raises(CollectError, match=r"spec\.yaml"):
        load_batch(directory)


def test_the_module_runs_as_a_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """make bench-check 以 python -m benchmarks.cli 執行：結束碼就是 main 的回傳值。"""
    monkeypatch.setattr(
        sys,
        "argv",
        ["benchmarks.cli", "check-spec", str(SMOKE), "x", "--results-root", str(tmp_path)],
    )

    monkeypatch.delitem(sys.modules, "benchmarks.cli", raising=False)

    with pytest.raises(SystemExit) as stopped:
        runpy.run_module("benchmarks.cli", run_name="__main__", alter_sys=True)

    assert stopped.value.code == 0
    assert "4 個 scan" in capsys.readouterr().out
