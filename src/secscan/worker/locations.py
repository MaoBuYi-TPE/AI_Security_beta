"""把嚴格讀取的 guard telemetry 彙總，不保存參數名稱或未遮罩的 path。"""

from collections.abc import Sequence
from itertools import groupby
from uuid import UUID

from secscan.scans.domain.coverage import REJECTED_CREDENTIALS, Exchange
from secscan.scans.domain.locations import Location, LocationSummary, RuleLocation
from secscan.security.redaction import redact_url
from secscan.worker.telemetry import TelemetryReader


def summarize_locations(exchanges: Sequence[Exchange]) -> LocationSummary:
    """未歸屬規則的請求不一定來自 discovery；帶規則的請求也不證明規則已完成。"""
    safe = tuple(exchange for exchange in exchanges if redact_url(exchange.path) == exchange.path)
    ordered = sorted(safe, key=lambda exchange: (exchange.method, exchange.path))
    locations = tuple(
        _location(method, path, tuple(group))
        for (method, path), group in groupby(ordered, key=lambda item: (item.method, item.path))
    )
    with_rule = sorted(
        (exchange for exchange in safe if exchange.rule is not None),
        key=lambda exchange: (exchange.method, exchange.path, exchange.rule or ""),
    )
    rules = tuple(
        _rule(method, path, rule, tuple(group))
        for (method, path, rule), group in groupby(
            with_rule, key=lambda item: (item.method, item.path, item.rule or "")
        )
    )
    return LocationSummary(locations, rules, len(safe) != len(exchanges))


def _location(method: str, path: str, exchanges: tuple[Exchange, ...]) -> Location:
    return Location(
        method=method,
        path=path,
        answered=any(item.status is not None for item in exchanges),
        discovery_answered=False,
        authenticated=any(
            item.authenticated
            and item.status is not None
            and item.status not in REJECTED_CREDENTIALS
            for item in exchanges
        ),
        unanswered=any(item.status is None for item in exchanges),
    )


def _rule(method: str, path: str, rule: str, exchanges: tuple[Exchange, ...]) -> RuleLocation:
    return RuleLocation(
        method=method,
        path=path,
        rule=rule,
        answered=any(item.status is not None for item in exchanges),
        parameters_unknown=True,
        parameters_truncated=any(item.parameters_truncated for item in exchanges),
    )


def read_comparison_locations(
    reader: TelemetryReader, run_id: UUID, scan_id: UUID, *, forwarded: int
) -> LocationSummary | None:
    """同時核對 summary 的 scan 與明細的精確筆數；缺檔不推論為零流量。"""
    summary = reader.summary(run_id)
    if summary is None or summary.scan_id != scan_id or summary.forwarded != forwarded:
        return None
    exchanges = reader.comparison_exchanges(run_id, forwarded=forwarded)
    if exchanges is None:
        return None
    result = summarize_locations(exchanges)
    return None if result.has_unusable_paths else result
