"""T33：同一份 telemetry 的信任判斷供 parser、coverage 與流量摘要共用。

JSONL 只有 method/path，這裡不宣稱驗證 origin、query、header 或實際收包。
不一致優先於零流量；strict 保留舊的最後一行容忍，實驗版必須完整。
"""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from secscan.grants.domain.matching import ScopeRules
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.guard.domain.requests import scope_reason
from secscan.guard.domain.telemetry import RunSummary
from secscan.scans.domain.coverage import Exchange, telemetry_complete


class EvidenceState(StrEnum):
    TRUSTED = "trusted"
    MISSING = "missing"
    INCONSISTENT = "inconsistent"


@dataclass(frozen=True, slots=True)
class TelemetryEvidence:
    state: EvidenceState
    summary: RunSummary | None
    exchanges: tuple[Exchange, ...] | None
    problem: str | None = None

    @property
    def trusted(self) -> bool:
        return self.state is EvidenceState.TRUSTED


def verify_telemetry(
    *,
    run_id: UUID,
    scan_id: UUID,
    policy_version: GuardPolicyVersion,
    requests_sent: int | None,
    rules: ScopeRules,
    summary: RunSummary | None,
    exchanges: tuple[Exchange, ...] | None,
) -> TelemetryEvidence:
    problem = _inconsistency(
        run_id, scan_id, policy_version, requests_sent, rules, summary, exchanges
    )
    if problem is not None:
        # 別的 scan 的摘要不屬於這個 run，連其用量也不能寫入本 run。
        if problem == "summary_identity":
            summary = None
        return TelemetryEvidence(EvidenceState.INCONSISTENT, summary, exchanges, problem)
    experimental = policy_version is GuardPolicyVersion.ENCODED_PARAMS
    if requests_sent is None or (experimental and summary is None):
        return TelemetryEvidence(
            EvidenceState.MISSING, summary, exchanges, "summary_or_usage_missing"
        )
    if requests_sent == 0:
        return TelemetryEvidence(EvidenceState.TRUSTED, summary, ())
    complete = exchanges is not None and (
        len(exchanges) == requests_sent
        if experimental
        else telemetry_complete(exchanges, forwarded=requests_sent)
    )
    state = EvidenceState.TRUSTED if complete else EvidenceState.MISSING
    return TelemetryEvidence(state, summary, exchanges, None if complete else "requests_incomplete")


def _inconsistency(
    run_id: UUID,
    scan_id: UUID,
    version: GuardPolicyVersion,
    sent: int | None,
    rules: ScopeRules,
    summary: RunSummary | None,
    exchanges: tuple[Exchange, ...] | None,
) -> str | None:
    if summary is not None:
        if summary.run_id != run_id or summary.scan_id != scan_id:
            return "summary_identity"
        if summary.policy_version is not version:
            return "policy_version"
        if sent is not None and summary.forwarded != sent:
            return "forwarded_count"
    if exchanges is not None:
        if sent is not None and len(exchanges) > sent:
            return "request_count"
        if any(scope_reason(item.method, item.path, rules, version.encoding) for item in exchanges):
            return "request_not_authorized"
    return None
