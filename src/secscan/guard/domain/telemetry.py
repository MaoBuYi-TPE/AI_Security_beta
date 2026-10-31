"""guard 的 telemetry 格式（docs/DECISIONS.md §16）：guard 寫，runner 讀 summary、worker 讀每一行。

- `<run_id>.summary.json`：轉送的請求數、各原因的拒絕數、是否用盡預算、第一個與最後一個轉送的時間。
- `<run_id>.jsonl`：每個轉送的請求一行（序號、時間、method、不含 query 的 path、是否帶認證
  header），上游的回應一行（序號、時間、status）。拒絕的請求只計數：數量不受預算限制，不逐行記。
「實際的請求數」以這裡轉送的請求為準（不採用工具自報的數字，contract §8）。讀的一方嚴格解析。
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from uuid import UUID

from secscan.grants.domain.scope import HttpMethod, path_problem
from secscan.guard.domain.requests import Reason
from secscan.guard.domain.strict import StrictDocument, dump_canonical, load_object

TELEMETRY_SCHEMA = 1
MAX_SUMMARY_BYTES = 64 * 1024
MAX_TELEMETRY_LINE_BYTES = 2048
# 讀的一方把時間轉成日期（9999-12-31 之前）、把計數寫進有大小上限的 result_details（T16 的審查）。
MAX_EPOCH_SECONDS = 253_402_300_799
MAX_COUNT = 10**12
_SUMMARY_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "scan_id",
        "boot_id",
        "forwarded",
        "denied",
        "exhausted",
        "first_at",
        "last_at",
    }
)
_REQUEST_FIELDS = frozenset({"e", "seq", "t", "method", "path", "auth"})
_RESPONSE_FIELDS = frozenset({"e", "seq", "t", "status"})
_REASONS = frozenset(reason.value for reason in Reason)
_METHODS = frozenset(method.value for method in HttpMethod)


class TelemetryError(ValueError):
    """telemetry 不合格式。訊息不含內容。"""


def summary_file_name(run_id: UUID) -> str:
    return f"{run_id}.summary.json"


def telemetry_file_name(run_id: UUID) -> str:
    return f"{run_id}.jsonl"


@dataclass(frozen=True, slots=True)
class RunSummary:
    run_id: UUID
    scan_id: UUID
    boot_id: UUID
    forwarded: int
    denied: Mapping[str, int] = field(default_factory=dict)
    exhausted: bool = False
    first_at: float | None = None
    last_at: float | None = None

    def __post_init__(self) -> None:
        if not _count(self.forwarded):
            raise TelemetryError("forwarded 必須是非負整數（有上限）")
        if not all(key in _REASONS and _count(value) for key, value in self.denied.items()):
            raise TelemetryError("denied 必須是 guard 的拒絕原因與非負整數")
        for value in (self.first_at, self.last_at):
            if value is not None and not _timestamp(value):
                raise TelemetryError("時間必須是非負的 epoch 秒")

    @property
    def denied_total(self) -> int:
        return sum(self.denied.values())


def encode_summary(summary: RunSummary) -> bytes:
    return dump_canonical(
        {
            "schema": TELEMETRY_SCHEMA,
            "run_id": str(summary.run_id),
            "scan_id": str(summary.scan_id),
            "boot_id": str(summary.boot_id),
            "forwarded": summary.forwarded,
            "denied": dict(sorted(summary.denied.items())),
            "exhausted": summary.exhausted,
            "first_at": summary.first_at,
            "last_at": summary.last_at,
        }
    )


def decode_summary(raw: bytes, *, run_id: UUID) -> RunSummary:
    document = load_object(
        raw,
        fields=_SUMMARY_FIELDS,
        max_bytes=MAX_SUMMARY_BYTES,
        label="summary",
        error=TelemetryError,
        floats=True,
    )
    if document.integer("schema") != TELEMETRY_SCHEMA:
        raise TelemetryError(f"schema 必須是 {TELEMETRY_SCHEMA}")
    if document.uuid("run_id") != run_id:
        raise TelemetryError("run_id 與檔名不同")
    denied = document.raw("denied")
    if not isinstance(denied, dict):
        raise TelemetryError("denied 必須是物件")
    return RunSummary(
        run_id=run_id,
        scan_id=document.uuid("scan_id"),
        boot_id=document.uuid("boot_id"),
        forwarded=document.integer("forwarded"),
        denied=dict(denied),
        exhausted=document.boolean("exhausted"),
        first_at=_optional_time(document.raw("first_at")),
        last_at=_optional_time(document.raw("last_at")),
    )


@dataclass(frozen=True, slots=True)
class ForwardedRequest:
    sequence: int
    at: float
    method: str
    path: str
    authenticated: bool

    def __post_init__(self) -> None:
        _check_sequence(self.sequence, self.at)
        if self.method not in _METHODS:
            raise TelemetryError("method 必須是 grant 可以允許的 method")
        if path_problem(self.path) is not None:
            raise TelemetryError("path 必須是合規則、不含 query 的 path")
        if type(self.authenticated) is not bool:
            raise TelemetryError("auth 必須是布林值")


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    sequence: int
    at: float
    status: int

    def __post_init__(self) -> None:
        _check_sequence(self.sequence, self.at)
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise TelemetryError("status 必須是 100 到 599")


TelemetryRecord = ForwardedRequest | UpstreamResponse


def encode_line(record: TelemetryRecord) -> bytes:
    if isinstance(record, ForwardedRequest):
        document: dict[str, object] = {
            "e": "request",
            "seq": record.sequence,
            "t": record.at,
            "method": record.method,
            "path": record.path,
            "auth": record.authenticated,
        }
    else:
        document = {
            "e": "response",
            "seq": record.sequence,
            "t": record.at,
            "status": record.status,
        }
    return dump_canonical(document) + b"\n"


def decode_line(line: bytes) -> TelemetryRecord:
    raw = line.removesuffix(b"\n")
    kind = _kind(raw)
    if kind == "request":
        document = _load_line(raw, _REQUEST_FIELDS)
        return ForwardedRequest(
            sequence=document.integer("seq"),
            at=_time(document.raw("t")),
            method=document.string("method"),
            path=document.string("path"),
            authenticated=document.boolean("auth"),
        )
    if kind == "response":
        document = _load_line(raw, _RESPONSE_FIELDS)
        return UpstreamResponse(
            sequence=document.integer("seq"),
            at=_time(document.raw("t")),
            status=document.integer("status"),
        )
    raise TelemetryError("telemetry 的一行必須是 request 或 response")


def _kind(raw: bytes) -> object:
    if len(raw) > MAX_TELEMETRY_LINE_BYTES:
        raise TelemetryError("telemetry 的一行太長")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise TelemetryError("telemetry 的一行不是 UTF-8 的 JSON") from None
    return document.get("e") if isinstance(document, dict) else None


def _load_line(raw: bytes, fields: frozenset[str]) -> StrictDocument:
    return load_object(
        raw,
        fields=fields,
        max_bytes=MAX_TELEMETRY_LINE_BYTES,
        label="telemetry",
        error=TelemetryError,
        floats=True,
    )


def _check_sequence(sequence: int, at: float) -> None:
    if type(sequence) is not int or sequence < 1:
        raise TelemetryError("seq 必須是正整數")
    if not _timestamp(at):
        raise TelemetryError("t 必須是非負的 epoch 秒")


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_COUNT


def _timestamp(value: object) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_EPOCH_SECONDS
    )


def _time(value: object) -> float:
    if not _timestamp(value):
        raise TelemetryError("時間必須是非負的 epoch 秒")
    return float(value)  # type: ignore[arg-type]


def _optional_time(value: object) -> float | None:
    return None if value is None else _time(value)
