"""guard 的 telemetry 格式（docs/DECISIONS.md §16）：runner 讀 summary、worker 讀每一行。

- summary（`<run_id>.summary.json`）：轉送與拒絕的計數、是否用盡預算；guard 原子寫入。
- `<run_id>.jsonl`：每個轉送的請求一行（method、不含 query 的 path、是否帶認證 header），回應一行
  （status）。拒絕的請求只計數，不逐行記（數量不受預算限制）。
兩者都是 guard 寫的，讀的一方仍嚴格解析（key 完全相符、型別、canonical），訊息不含內容。
"""

import json
from dataclasses import replace
from typing import Any
from uuid import UUID

import pytest

from secscan.guard.domain.telemetry import (
    MAX_TELEMETRY_LINE_BYTES,
    ForwardedRequest,
    RunSummary,
    TelemetryError,
    UpstreamResponse,
    decode_line,
    decode_summary,
    encode_line,
    encode_summary,
    summary_file_name,
    telemetry_file_name,
)

RUN = UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")
SCAN = UUID("0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d")
BOOT = UUID("3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b")
SUMMARY = RunSummary(
    run_id=RUN,
    scan_id=SCAN,
    boot_id=BOOT,
    forwarded=3,
    denied={"PATH_EXCLUDED": 2, "RATE_LIMITED": 1},
    exhausted=False,
    first_at=1_767_598_800.25,
    last_at=1_767_598_801.75,
)


def test_file_names_are_derived_from_the_run() -> None:
    assert summary_file_name(RUN) == f"{RUN}.summary.json"
    assert telemetry_file_name(RUN) == f"{RUN}.jsonl"


def test_summary_round_trip() -> None:
    assert decode_summary(encode_summary(SUMMARY), run_id=RUN) == SUMMARY
    empty = replace(SUMMARY, forwarded=0, denied={}, first_at=None, last_at=None)
    assert decode_summary(encode_summary(empty), run_id=RUN) == empty
    assert SUMMARY.denied_total == 3


def _summary(**overrides: Any) -> bytes:
    document: dict[str, Any] = json.loads(encode_summary(SUMMARY))
    document.update(overrides)
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    "raw",
    [
        _summary(schema=2),
        _summary(extra=1),
        _summary(forwarded=-1),
        _summary(forwarded=True),
        _summary(exhausted="no"),
        _summary(run_id=str(RUN).upper()),
        _summary(denied={"PATH_EXCLUDED": -1}),
        _summary(denied={"NOT_A_REASON": 1}),
        _summary(denied=[]),
        _summary(first_at="x"),
        _summary(first_at=-1.0),
        b"{",
        b" " * 70_000,
    ],
)
def test_malformed_summaries_are_rejected(raw: bytes) -> None:
    with pytest.raises(TelemetryError):
        decode_summary(raw, run_id=RUN)


def test_summary_must_belong_to_the_run() -> None:
    with pytest.raises(TelemetryError, match="run_id"):
        decode_summary(encode_summary(SUMMARY), run_id=SCAN)


# --- 每一行 ----------------------------------------------------------------------------------

REQUEST = ForwardedRequest(
    sequence=1, at=1_767_598_800.5, method="GET", path="/api/items/7", authenticated=True
)
RESPONSE = UpstreamResponse(sequence=1, at=1_767_598_800.6, status=200)


def test_lines_round_trip() -> None:
    for record in (REQUEST, RESPONSE):
        line = encode_line(record)
        assert line.endswith(b"\n")
        assert line.count(b"\n") == 1
        assert decode_line(line) == record


@pytest.mark.parametrize(
    "line",
    [
        b'{"e":"request"}\n',
        b'{"e":"other","seq":1}\n',
        b"not json\n",
        encode_line(REQUEST).replace(b'"GET"', b'"TRACE"'),
        encode_line(REQUEST).replace(b'"/api/items/7"', b'"/api/items?x=1"'),
        encode_line(REQUEST).replace(b'"/api/items/7"', b'"api"'),
        encode_line(RESPONSE).replace(b"200", b"99"),
        encode_line(REQUEST).replace(b'"seq":1', b'"seq":0'),
        b"{" + b" " * MAX_TELEMETRY_LINE_BYTES + b"}\n",
    ],
)
def test_malformed_lines_are_rejected(line: bytes) -> None:
    with pytest.raises(TelemetryError):
        decode_line(line)


@pytest.mark.parametrize(
    "build",
    [
        lambda: replace(REQUEST, path="/a b"),
        lambda: replace(REQUEST, authenticated=1),  # type: ignore[arg-type]
        lambda: replace(REQUEST, at=-1.0),
        lambda: replace(RESPONSE, status=600),
        lambda: replace(SUMMARY, last_at=-0.5),
        lambda: replace(SUMMARY, first_at=True),
    ],
)
def test_records_validate_their_fields(build: Any) -> None:
    with pytest.raises(TelemetryError):
        build()


def test_deeply_nested_documents_are_malformed_not_crashes() -> None:
    """RecursionError 也轉成 TelemetryError（審查建議）：summary 的上限 64 KiB 放得下很深的巢狀。"""
    with pytest.raises(TelemetryError):
        decode_summary(b"[" * 30_000 + b"]" * 30_000, run_id=RUN)
