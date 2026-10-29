"""worker 讀 guard 的 telemetry（docs/DECISIONS.md §16.6）：每個轉送的請求一行，嚴格解析。

讀不到、格式不符、symlink 或超過上限都回傳 None（這個 run 的 coverage 不算有量測依據）；
沒有檔案也是 None（由呼叫端依轉送數判斷是不是沒有流量）。回應依序號配對到請求；對不到請求或重複
的回應代表格式不符。
"""

import os
from pathlib import Path
from uuid import UUID

import pytest

from secscan.guard.domain.telemetry import (
    ForwardedRequest,
    UpstreamResponse,
    encode_line,
    telemetry_file_name,
)
from secscan.scans.domain.coverage import Exchange
from secscan.worker.telemetry import TelemetryReader

RUN = UUID(int=3)
REQUEST = ForwardedRequest(sequence=1, at=1.0, method="GET", path="/me", authenticated=True)


def _write(directory: Path, content: bytes) -> None:
    (directory / telemetry_file_name(RUN)).write_bytes(content)


def test_requests_are_paired_with_their_responses(tmp_path: Path) -> None:
    second = ForwardedRequest(
        sequence=2, at=2.0, method="GET", path="/items/1", authenticated=False
    )
    _write(
        tmp_path,
        encode_line(REQUEST)
        + encode_line(second)
        + encode_line(UpstreamResponse(sequence=1, at=1.1, status=401)),
    )

    assert TelemetryReader(tmp_path).exchanges(RUN) == (
        Exchange(method="GET", path="/me", authenticated=True, status=401),
        Exchange(method="GET", path="/items/1", authenticated=False, status=None),
    )


@pytest.mark.parametrize("sequence", [2, 1])
def test_unpaired_or_repeated_responses_make_the_run_unmeasured(
    tmp_path: Path, sequence: int
) -> None:
    response = encode_line(UpstreamResponse(sequence=1, at=1.1, status=200))
    other = encode_line(UpstreamResponse(sequence=sequence, at=1.2, status=200))
    _write(tmp_path, encode_line(REQUEST) + response + other)

    assert TelemetryReader(tmp_path).exchanges(RUN) is None


def test_a_missing_file_is_none(tmp_path: Path) -> None:
    assert TelemetryReader(tmp_path).exchanges(RUN) is None


def test_malformed_lines_make_the_run_unmeasured(tmp_path: Path) -> None:
    _write(tmp_path, encode_line(REQUEST) + b'{"e":"request"}\n')

    assert TelemetryReader(tmp_path).exchanges(RUN) is None


def test_a_truncated_last_line_makes_the_run_unmeasured(tmp_path: Path) -> None:
    _write(tmp_path, encode_line(REQUEST)[:-1])

    assert TelemetryReader(tmp_path).exchanges(RUN) is None


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(encode_line(REQUEST))
    os.symlink(elsewhere, tmp_path / telemetry_file_name(RUN))

    assert TelemetryReader(tmp_path).exchanges(RUN) is None


def test_files_over_the_limit_are_none(tmp_path: Path) -> None:
    _write(tmp_path, encode_line(REQUEST) * 3)

    assert TelemetryReader(tmp_path, max_bytes=len(encode_line(REQUEST)) * 2).exchanges(RUN) is None
