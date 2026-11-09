"""bench 測試的金鑰檔：pytest 暫存目錄中的新金鑰（不讀預設的 ~/.config/secscan/bench-keys）。"""

from pathlib import Path

import pytest

from benchmarks.sealing import KEY_FILE_VARIABLE, BenchKeys, create_key_file


@pytest.fixture
def bench_keys(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> BenchKeys:
    """建立暫存的金鑰檔並以 BENCH_KEY_FILE 指向它（CLI 與 harness 都從這裡讀）。"""
    path: Path = tmp_path_factory.mktemp("bench-key") / "bench-keys"
    create_key_file(path)
    monkeypatch.setenv(KEY_FILE_VARIABLE, str(path))
    return BenchKeys.load(path)
