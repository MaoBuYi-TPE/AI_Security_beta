"""真實的 ZAP 輸出對 parser 的契約（docs/DECISIONS.md §19.9）；不碰網路、Docker 或 DB。

每份錄製的輸出判讀的結果固定下來：映像或 parser 改了，差異會出現在這裡，而不是線上。fixture 只能由
make record-fixtures 重新錄製、人工審查之後更新。
"""

import json
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.guard.domain.telemetry import ForwardedRequest, UpstreamResponse, decode_line
from secscan.scanners.domain.zap.report import ZapReport, parse_report
from secscan.scanners.domain.zap.results import ZapOutput, interpret
from secscan.scans.domain.coverage import Exchange
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.observation import Exclusion
from secscan.targets.domain import parse_origin

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
ZAP = FIXTURES / "zap"


def _output(scenario: str) -> ZapOutput:
    directory = ZAP / scenario
    [entry] = [item for item in MANIFEST["fixtures"] if item["path"] == f"zap/{scenario}/zap.log"]
    origin = parse_origin(entry["target"])
    telemetry = directory / "telemetry.jsonl"
    exchanges = _exchanges(telemetry) if telemetry.exists() else None
    report = directory / "report.json"
    return ZapOutput(
        policy_version=GuardPolicyVersion.STRICT,
        telemetry_trusted=True,
        exit_code=entry["exit_code"],
        report=report.read_bytes() if report.exists() else None,
        report_listed=report.exists(),
        log=(directory / "zap.log").read_bytes(),
        origin=origin,
        rules=ScopeRules.of(
            Scope(
                origins=(origin,),
                ips=(IPv4Address("10.89.10.210"),),
                paths=(),
                allow_all_paths=True,
                excluded_paths=("/admin",),
                methods=(HttpMethod.GET, HttpMethod.HEAD),
            )
        ),
        forwarded=len(exchanges) if exchanges is not None else 0,
        exchanges=exchanges,
    )


def _exchanges(path: Path) -> tuple[Exchange, ...]:
    records = [decode_line(line) for line in path.read_bytes().splitlines(keepends=True)]
    statuses = {r.sequence: r.status for r in records if isinstance(r, UpstreamResponse)}
    return tuple(
        Exchange(r.method, r.path, r.authenticated, statuses.get(r.sequence))
        for r in records
        if isinstance(r, ForwardedRequest)
    )


@pytest.mark.parametrize(
    ("scenario", "status", "error_code", "observations", "not_answered", "time_limit"),
    [
        ("clean", RunStatus.SUCCEEDED, None, 0, 0, False),
        ("findings", RunStatus.SUCCEEDED, None, 11, 0, False),
        ("timeout", RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT, 11, 0, True),
        ("unanswered", RunStatus.FAILED, RunErrorCode.NO_TARGET_TRAFFIC, 0, 9, False),
        ("unreachable", RunStatus.FAILED, RunErrorCode.ENGINE_REPORTED_ERRORS, 0, 0, False),
        ("engine-error", RunStatus.FAILED, RunErrorCode.ENGINE_FAILED, 0, 0, False),
    ],
)
def test_recorded_output_keeps_its_meaning(
    scenario: str,
    status: RunStatus,
    error_code: RunErrorCode | None,
    observations: int,
    not_answered: int,
    time_limit: bool,
) -> None:
    parsed = interpret(_output(scenario))

    assert (parsed.outcome.status, parsed.outcome.error_code) == (status, error_code)
    assert len(parsed.observations) == observations
    assert parsed.excluded.get(Exclusion.NOT_ANSWERED, 0) == not_answered
    assert parsed.time_limit_reached is time_limit


@pytest.mark.parametrize("name", ["zap-juice-shop.json", "zap-vampi-vuln.json"])
def test_the_t03_reports_are_still_accepted(name: str) -> None:
    assert isinstance(parse_report((ZAP / name).read_bytes()), ZapReport)
