"""一個 run 的觀察 → finding 的規劃（docs/DECISIONS.md §25.7）；純函式，DB 的寫入在 service。

每個觀察：正規化等級與信心 → 對應群組（或 fallback）→ fingerprint。fingerprint 相同的觀察是同一個
finding 的來源。聚合（使用者決定，2026-11-03）：
- severity 是所有來源正規化之後的最高值；來源數本身不加分。
- 來源的等級不一致時 severity_conflict（只會由 false 變成 true）；各來源的原值另外保留。
- needs_review：任何一個來源需要人工確認（等級對不上、fallback、provisional 的群組）。
- confidence 不聚合（多個工具同時命中不提高信心）。
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from uuid import UUID

from secscan.core.json_types import JsonValue
from secscan.findings.domain.fingerprint import (
    FingerprintInputs,
    Position,
    RouteIndex,
    RouteSource,
    fingerprint,
    position,
)
from secscan.findings.domain.normalization import Confidence, Severity, highest, normalize
from secscan.findings.domain.owasp import top10_category
from secscan.findings.domain.taxonomy import (
    Classification,
    CweSource,
    FindingCategory,
    Granularity,
    Taxonomy,
    classify,
    group_classification,
)
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.coverage import FrozenOperation, operation_routes
from secscan.scans.domain.model import ANONYMOUS_ROLE
from secscan.scans.domain.observation import ParameterLocation
from secscan.scans.domain.preflight import PreflightResult


@dataclass(frozen=True, slots=True)
class ObservationRow:
    """還沒有連結的觀察（依入庫的順序）。"""

    id: UUID
    engine: Engine
    source_rule: str
    rule_variant: str | None
    title: str
    raw_severity: str
    raw_confidence: str
    cwe_id: int | None
    method: str
    path: str
    parameter: str | None
    parameter_location: ParameterLocation
    auth_role: str


@dataclass(frozen=True, slots=True)
class LinkContext:
    target_id: UUID
    # anonymous，或帶認證而且這個 run 的身分確實有效（§25.6）。
    auth_verified: bool
    # scan 有規格時範圍內的 operation（route 樣板化）；沒有規格是空的。
    operations: tuple[FrozenOperation, ...] = ()
    # 同一次 scan 中錨點群組的觀察：(群組 id, method, path)。佐證成員只有在這裡找得到同一個位置的
    # 錨點時才併入錨點群組（使用者簽核，§25.14）。
    anchors: frozenset[tuple[str, str, str]] = frozenset()


@dataclass(frozen=True, slots=True)
class Link:
    observation_id: UUID
    severity: Severity
    confidence: Confidence
    needs_review: bool


@dataclass(frozen=True, slots=True)
class Aggregate:
    severity: Severity
    severity_conflict: bool
    needs_review: bool


@dataclass(frozen=True, slots=True)
class FindingDraft:
    fingerprint: str
    inputs: FingerprintInputs
    route_source: RouteSource
    title: str
    category: FindingCategory
    cwe_id: int | None
    cwe_source: CweSource | None
    owasp_top10_2025: str | None
    owasp_api_2023: str | None
    links: tuple[Link, ...]

    @property
    def aggregate(self) -> Aggregate:
        """只看這一批來源的聚合（新的 finding 以它寫入）。"""
        severities = {link.severity for link in self.links}
        return Aggregate(
            severity=highest(severities),
            severity_conflict=len(severities) > 1,
            needs_review=any(link.needs_review for link in self.links),
        )


def identity_verified(
    auth_role: str, preflight: PreflightResult | None, details: Mapping[str, JsonValue] | None
) -> bool:
    """觀察的身分是否確實有效（T16 的交接；§25.6）：anonymous，或 preflight 通過、guard 記下
    帶認證的請求被接受過，而且**沒有任何**被拒絕、退化或探針被拒絕的請求（`lost` 也是 false）。

    比 `lost` 嚴格：`lost` 是揭露用的門檻（退化 2 個以上），中途過期、之後只打新端點的 run 不會
    觸發它（安全審查發現）。T16 的真實資料中，健康的已認證 run 都沒有被拒絕的請求。角色本來就會
    碰到 401／403 時只是多一個未驗證的 finding，不會漏報。不明的一律當成沒有驗證。
    """
    if auth_role == ANONYMOUS_ROLE:
        return True
    if preflight is not PreflightResult.PASSED or details is None:
        return False
    traffic = details.get("guard_traffic")
    auth = traffic.get("auth") if isinstance(traffic, dict) else None
    if not isinstance(auth, dict) or auth.get("lost") is not False:
        return False
    names = ("accepted", "rejected", "regressed", "probe_rejected")
    counts = [
        count
        for count in (auth.get(name) for name in names)
        if isinstance(count, int) and not isinstance(count, bool)
    ]
    if len(counts) != len(names):
        return False
    accepted, rejected, regressed, probe_rejected = counts
    return accepted > 0 and rejected == regressed == probe_rejected == 0


def merge(existing: Aggregate, draft: FindingDraft) -> Aggregate:
    """已存在的 finding 加上新的來源：最高值、衝突與需要確認都只會往上（不會被新的來源蓋掉）。"""
    severities = [link.severity for link in draft.links]
    return Aggregate(
        severity=highest([existing.severity, *severities]),
        # 新來源的等級和既有的最高值不同就是衝突（這一批內部不一致也一定和它不同）。
        severity_conflict=existing.severity_conflict
        or any(severity is not existing.severity for severity in severities),
        needs_review=existing.needs_review or draft.aggregate.needs_review,
    )


def plan_links(
    context: LinkContext, observations: Sequence[ObservationRow], taxonomy: Taxonomy
) -> tuple[FindingDraft, ...]:
    """依 fingerprint 排序（寫入與加鎖的順序固定，避免兩個 run 同時連結時死鎖）。"""
    routes = RouteIndex.of(operation_routes(context.operations))
    grouped: dict[str, list[tuple[ObservationRow, Classification, FingerprintInputs, Link]]] = {}
    sources: dict[str, RouteSource] = {}
    for row in observations:
        normalized = normalize(row.engine, row.raw_severity, row.raw_confidence)
        classification = _classify(context, row, taxonomy, normalized.severity)
        located = position(routes, row.method, row.path)
        inputs = _inputs(context, row, classification, located)
        link = Link(
            observation_id=row.id,
            severity=normalized.severity,
            confidence=normalized.confidence,
            needs_review=normalized.needs_review or classification.needs_review,
        )
        key = fingerprint(inputs)
        grouped.setdefault(key, []).append((row, classification, inputs, link))
        sources.setdefault(key, located.source)
    return tuple(_draft(key, grouped[key], sources[key]) for key in sorted(grouped))


def _classify(
    context: LinkContext, row: ObservationRow, taxonomy: Taxonomy, severity: Severity
) -> Classification:
    """群組（或 fallback）；佐證成員在同一次 scan、同一個 method 與 path 有錨點時改屬錨點群組。"""
    anchor = taxonomy.anchor_for(row.engine, row.source_rule, row.rule_variant)
    if anchor is not None and (anchor.id, row.method, row.path) in context.anchors:
        return group_classification(anchor)
    return classify(
        taxonomy,
        row.engine,
        row.source_rule,
        row.rule_variant,
        tool_cwe=row.cwe_id,
        severity=severity,
    )


def _inputs(
    context: LinkContext, row: ObservationRow, classification: Classification, located: Position
) -> FingerprintInputs:
    by_parameter = classification.granularity is Granularity.PARAMETER and row.parameter is not None
    return FingerprintInputs(
        target_id=context.target_id,
        kind=classification.kind,
        rule_group=classification.rule_group,
        method=row.method,
        route=located.route,
        route_templated=located.templated,
        parameter_location=row.parameter_location.value if by_parameter else None,
        parameter_name=row.parameter if by_parameter else None,
        auth_role=row.auth_role,
        auth_verified=context.auth_verified,
        resource=row.path if classification.resource_scoped else None,
    )


def _draft(
    key: str,
    members: list[tuple[ObservationRow, Classification, FingerprintInputs, Link]],
    source: RouteSource,
) -> FindingDraft:
    first, classification, inputs, _ = members[0]
    cwe_id, cwe_source = classification.cwe_id, classification.cwe_source
    if classification.fallback:
        # fallback：同一個 engine:rule 的觀察，取第一個有回報的 CWE。
        cwe_id = _first(row.cwe_id for row, _, _, _ in members)
        cwe_source = CweSource.TOOL if cwe_id is not None else None
    return FindingDraft(
        fingerprint=key,
        inputs=inputs,
        route_source=source,
        title=classification.title or first.title,
        category=classification.category,
        cwe_id=cwe_id,
        cwe_source=cwe_source,
        owasp_top10_2025=top10_category(cwe_id),
        owasp_api_2023=classification.owasp_api_2023,
        links=tuple(link for _, _, _, link in members),
    )


def _first(values: Iterable[int | None]) -> int | None:
    return next((value for value in values if value is not None), None)
