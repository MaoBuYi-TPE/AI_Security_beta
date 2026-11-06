"""校準輸出只可新增，不覆寫先前量測。"""

import json
from pathlib import Path

import pytest

from tests.live.recordings import reserve_recording_directory, write_measurement


def test_unconfigured_recording_does_not_create_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SECSCAN_RECORD_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    reserve_recording_directory()
    write_measurement("patched", {"checked": True})
    assert not list(tmp_path.iterdir())


def test_recording_uses_an_exclusive_file_and_distinct_ground_truth_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "new-calibration"
    monkeypatch.setenv("SECSCAN_RECORD_DIR", str(root))
    reserve_recording_directory()
    write_measurement("patched", {"notice": "不等於已修補"})
    write_measurement("patched", {"checked": []}, filename="ground-truth.json")
    comparison = root / "patched" / "comparison.json"
    assert json.loads(comparison.read_text()) == {"notice": "不等於已修補"}
    assert json.loads((comparison.parent / "ground-truth.json").read_text()) == {"checked": []}
    before = comparison.read_bytes()
    with pytest.raises(FileExistsError):
        write_measurement("patched", {"notice": "replacement"})
    assert comparison.read_bytes() == before


def test_reusing_a_calibration_directory_fails_before_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECSCAN_RECORD_DIR", str(tmp_path))
    with pytest.raises(FileExistsError):
        reserve_recording_directory()


def test_invalid_json_does_not_reserve_an_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECSCAN_RECORD_DIR", str(tmp_path))
    with pytest.raises(ValueError, match="Out of range float"):
        write_measurement("patched", {"invalid": float("nan")})
    assert not (tmp_path / "patched" / "comparison.json").exists()
