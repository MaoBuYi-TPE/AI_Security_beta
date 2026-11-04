"""真實的 ZAP 輸出對 parser 的契約（docs/DECISIONS.md §19.9）；不碰網路、Docker 或 DB。

每份錄製的輸出判讀的結果固定下來：映像或 parser 改了，差異會出現在這裡，而不是線上。fixture 只能由
make record-fixtures 重新錄製、人工審查之後更新。
"""

import pytest

from secscan.scanners.domain.zap.report import ZapReport, parse_report
from secscan.scanners.domain.zap.results import interpret
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.observation import Exclusion
from tests.contract.zap_recordings import ZAP, output


@pytest.mark.parametrize(
    ("scenario", "status", "error_code", "observations", "not_answered", "time_limit"),
    [
        ("clean", RunStatus.SUCCEEDED, None, 0, 0, False),
        ("findings", RunStatus.SUCCEEDED, None, 11, 0, False),
        ("timeout", RunStatus.TIMED_OUT, RunErrorCode.ENGINE_TIMEOUT, 11, 0, True),
        ("unanswered", RunStatus.FAILED, RunErrorCode.NO_TARGET_TRAFFIC, 0, 9, False),
        ("unreachable", RunStatus.FAILED, RunErrorCode.ENGINE_REPORTED_ERRORS, 0, 0, False),
        ("engine-error", RunStatus.FAILED, RunErrorCode.ENGINE_FAILED, 0, 0, False),
        # T30 的 fixture app 弱點版（T20 升為 golden）：觀察數等於平台當時寫入的數量。
        ("fixture-vuln-web", RunStatus.SUCCEEDED, None, 23, 0, False),
        ("fixture-vuln-api", RunStatus.SUCCEEDED, None, 11, 0, False),
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
    parsed = interpret(output(scenario))

    assert (parsed.outcome.status, parsed.outcome.error_code) == (status, error_code)
    assert len(parsed.observations) == observations
    assert parsed.excluded.get(Exclusion.NOT_ANSWERED, 0) == not_answered
    assert parsed.time_limit_reached is time_limit


@pytest.mark.parametrize("name", ["zap-juice-shop.json", "zap-vampi-vuln.json"])
def test_the_t03_reports_are_still_accepted(name: str) -> None:
    assert isinstance(parse_report((ZAP / name).read_bytes()), ZapReport)
