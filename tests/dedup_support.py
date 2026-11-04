"""去重的不變式（T20；docs/SECURITY_AND_TESTING.md §4.3 的 DEDUP）。

unit、contract、integration、live 共用。
一個 finding 的每個觀察都必須在 fingerprint 的每個身分維度上相同；不同的 (engine, rule, variant)
只能是同一個審查過的群組的成員；跨引擎只限佐證群組，而且佐證的觀察在同一次 scan、同一個 method
與 path 有錨點的觀察（§25.14）。檢查以目前的 taxonomy 進行：只用在以目前版本連結的資料。
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from uuid import UUID

from secscan.findings.domain.taxonomy import MemberKey, Taxonomy, member_key
from secscan.scans.domain.catalog import Engine


@dataclass(frozen=True, slots=True)
class ObservationView:
    engine: Engine
    source_rule: str
    rule_variant: str | None
    method: str
    path: str
    parameter_location: str
    parameter: str | None
    auth_role: str
    scan_id: UUID | None = None

    @property
    def member(self) -> MemberKey:
        return member_key(self.engine, self.source_rule, self.rule_variant)


@dataclass(frozen=True, slots=True)
class FindingView:
    rule_group: str
    method: str
    route: str
    route_templated: bool
    parameter_location: str | None
    parameter_name: str | None
    auth_role: str
    resource: str | None
    observations: tuple[ObservationView, ...]


def violations(finding: FindingView, taxonomy: Taxonomy) -> list[str]:
    """違反的不變式（空的清單表示沒有誤合併的跡象）。"""
    problems = [*_identity(finding), *_members(finding, taxonomy)]
    if not finding.observations:
        problems.append("沒有觀察")
    return problems


def assert_no_false_merges(findings: Iterable[FindingView], taxonomy: Taxonomy) -> None:
    problems = {
        f"{finding.rule_group} {finding.method} {finding.route}": found
        for finding in findings
        if (found := violations(finding, taxonomy))
    }
    assert not problems, problems


def _identity(finding: FindingView) -> list[str]:
    rows = finding.observations
    checks = {
        "method": all(row.method == finding.method for row in rows),
        "auth_role": all(row.auth_role == finding.auth_role for row in rows),
        # 字面的 route 就是 path；樣板的 route 由 coverage 的規則決定（另外以 resource 限定物件）。
        "route": finding.route_templated or all(row.path == finding.route for row in rows),
        "resource": finding.resource is None or all(row.path == finding.resource for row in rows),
        # v2：沒有審查過的規則（fallback 的 `engine:rule`）在樣板 route 下以字面 path 區分物件。
        "fallback_object": ":" not in finding.rule_group
        or not finding.route_templated
        or finding.resource is not None,
        "parameter": finding.parameter_name is None
        or all(
            (row.parameter, row.parameter_location)
            == (finding.parameter_name, finding.parameter_location)
            for row in rows
        ),
    }
    return [f"觀察的 {name} 不一致" for name, ok in checks.items() if not ok]


def _members(finding: FindingView, taxonomy: Taxonomy) -> list[str]:
    keys = {row.member for row in finding.observations}
    group = _group(finding.rule_group, taxonomy)
    if group is None:
        # fallback（或技術識別的 `群組/技術名`）：只有一個 (engine, rule, variant)。
        return [] if len(keys) == 1 else [f"未審查的群組合併了不同的規則：{sorted(map(str, keys))}"]
    own, corroborating = set(group.members), set(group.corroborated_by)
    problems = [f"不是群組的成員：{key}" for key in keys if key not in own | corroborating]
    if keys & corroborating:
        problems.extend(_anchored(finding.observations, own, corroborating))
    return problems


def _group(rule_group: str, taxonomy: Taxonomy) -> "_Group | None":
    for group in taxonomy.groups:
        if group.id == rule_group and all(member[2] != "*" for member in group.members):
            return _Group(group.members, group.corroborated_by)
    return None


@dataclass(frozen=True, slots=True)
class _Group:
    members: Sequence[MemberKey]
    corroborated_by: Sequence[MemberKey]


def _anchored(
    rows: Sequence[ObservationView], own: set[MemberKey], corroborating: set[MemberKey]
) -> list[str]:
    anchors = {(row.scan_id, row.method, row.path) for row in rows if row.member in own}
    return [
        f"佐證的觀察沒有同一次 scan、同一個位置的錨點：{row.method} {row.path}"
        for row in rows
        if row.member in corroborating and (row.scan_id, row.method, row.path) not in anchors
    ]
