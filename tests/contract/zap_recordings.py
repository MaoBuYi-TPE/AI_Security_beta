"""錄製的 ZAP 輸出以錄製時的 scope 重建成 ZapOutput（test_zap_fixtures 與去重的契約測試共用）。"""

import json
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.domain.telemetry import ForwardedRequest, UpstreamResponse, decode_line
from secscan.scanners.domain.zap.results import ZapOutput
from secscan.scans.domain.coverage import Exchange
from secscan.targets.domain import Origin, parse_origin

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
ZAP = FIXTURES / "zap"


def output(scenario: str) -> ZapOutput:
    directory = ZAP / scenario
    [entry] = [item for item in MANIFEST["fixtures"] if item["path"] == f"zap/{scenario}/zap.log"]
    origin = parse_origin(entry["target"])
    telemetry = directory / "telemetry.jsonl"
    exchanges = _exchanges(telemetry) if telemetry.exists() else None
    report = directory / "report.json"
    return ZapOutput(
        exit_code=entry["exit_code"],
        report=report.read_bytes() if report.exists() else None,
        report_listed=report.exists(),
        log=(directory / "zap.log").read_bytes(),
        origin=origin,
        rules=ScopeRules.of(_scope(entry, origin)),
        forwarded=len(exchanges) if exchanges is not None else 0,
        exchanges=exchanges,
    )


def _scope(entry: dict[str, Any], origin: Origin) -> Scope:
    """錄製時的 grant：T15 的情境是固定的 GET／HEAD、排除 /admin；T30 的錄製登錄在 manifest。"""
    grant = entry.get("grant")
    if grant is None:
        return Scope(
            origins=(origin,),
            ips=(IPv4Address("10.89.10.210"),),
            paths=(),
            allow_all_paths=True,
            excluded_paths=("/admin",),
            methods=(HttpMethod.GET, HttpMethod.HEAD),
        )
    paths = tuple(grant.get("paths", ()))
    return Scope(
        origins=(origin,),
        ips=(IPv4Address("10.89.10.210"),),
        paths=paths,
        allow_all_paths=bool(grant.get("allow_all_paths", False)),
        excluded_paths=(),
        methods=tuple(HttpMethod(method) for method in grant["methods"]),
    )


def _exchanges(path: Path) -> tuple[Exchange, ...]:
    records = [decode_line(line) for line in path.read_bytes().splitlines(keepends=True)]
    statuses = {r.sequence: r.status for r in records if isinstance(r, UpstreamResponse)}
    return tuple(
        Exchange(r.method, r.path, r.authenticated, statuses.get(r.sequence))
        for r in records
        if isinstance(r, ForwardedRequest)
    )
