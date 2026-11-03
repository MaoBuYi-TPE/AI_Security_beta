"""一個 run 的觀察 → finding 的規劃與聚合（T19；docs/DECISIONS.md §25.7）。

以 T18 的真實同時命中（fixture 弱點版 GET /）為例：ZAP 10098（Medium）與 nuclei cors-misconfig
（info）是同一個 finding，取最高值並標衝突；不在審查過的群組裡的規則不跨工具合併。
"""

from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.domain.linking import (
    Aggregate,
    FindingDraft,
    LinkContext,
    ObservationRow,
    identity_verified,
    merge,
    plan_links,
)
from secscan.findings.domain.normalization import Confidence, Severity
from secscan.findings.domain.taxonomy import CweSource, FindingKind, load_taxonomy
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.coverage import FrozenOperation
from secscan.scans.domain.observation import ParameterLocation
from secscan.scans.domain.preflight import PreflightResult

TARGET = UUID("11111111-2222-4333-8444-555555555555")
CONTEXT = LinkContext(target_id=TARGET, auth_verified=True)


def _row(engine: Engine, rule: str, variant: str | None = None, **over: object) -> ObservationRow:
    base = ObservationRow(
        id=uuid4(),
        engine=engine,
        source_rule=rule,
        rule_variant=variant,
        title=f"{engine.value} {rule}",
        raw_severity="2" if engine is Engine.ZAP else "info",
        raw_confidence="2" if engine is Engine.ZAP else "unknown",
        cwe_id=None,
        method="GET",
        path="/",
        parameter=None,
        parameter_location=ParameterLocation.UNKNOWN,
        auth_role="anonymous",
    )
    return replace(base, **over)  # type: ignore[arg-type]


ZAP_CORS = _row(Engine.ZAP, "10098", "10098", cwe_id=264)
NUCLEI_CORS = _row(Engine.NUCLEI, "cors-misconfig", "arbitrary-origin", cwe_id=346)


def _plan(*rows: ObservationRow, context: LinkContext = CONTEXT) -> tuple[FindingDraft, ...]:
    return plan_links(context, rows, load_taxonomy())


def test_co_located_hits_of_a_reviewed_group_are_one_finding() -> None:
    [draft] = _plan(ZAP_CORS, NUCLEI_CORS)

    assert draft.inputs.rule_group == "cors-permissive-policy"
    assert [link.observation_id for link in draft.links] == [ZAP_CORS.id, NUCLEI_CORS.id]
    # 最高值是 ZAP 的 Medium；等級不一致是衝突；兩個工具同時命中不提高等級或信心。
    assert draft.aggregate == Aggregate(Severity.MEDIUM, severity_conflict=True, needs_review=False)
    assert [link.confidence for link in draft.links] == [Confidence.MEDIUM, Confidence.UNKNOWN]
    # 群組審查後的 CWE（不是 ZAP 的 264 或 nuclei 的 346）→ 官方的 A02:2025；API 2023 是 curated。
    assert (draft.cwe_id, draft.cwe_source) == (942, CweSource.RULE_GROUP)
    assert (draft.owasp_top10_2025, draft.owasp_api_2023) == ("A02:2025", "API8:2023")
    assert draft.title == "Permissive cross-origin resource sharing (CORS) policy"
    assert draft.route_source is RouteSource.LITERAL


def test_header_groups_ignore_the_tools_differing_parameters() -> None:
    """ZAP 把缺的 header 名放在參數、nuclei 沒有參數：endpoint 粒度的群組照樣合併。"""
    zap = _row(Engine.ZAP, "10021", "10021", raw_severity="1", parameter="x-content-type-options")
    nuclei = _row(Engine.NUCLEI, "http-missing-security-headers", "x-content-type-options")

    [draft] = _plan(zap, nuclei)

    assert draft.inputs.rule_group == "x-content-type-options-missing"
    assert (draft.inputs.parameter_location, draft.inputs.parameter_name) == (None, None)
    assert draft.aggregate.severity is Severity.LOW
    assert draft.owasp_top10_2025 == "A06:2025"


def test_a_reviewed_group_without_a_cwe_ignores_the_tools_cwe() -> None:
    """code review：群組刻意不填 cwe 時，工具的 CWE 不流進官方的 OWASP 對應（只有 fallback 用）。"""
    [draft] = _plan(_row(Engine.ZAP, "10109", "10109", raw_severity="0", cwe_id=79))

    assert draft.inputs.rule_group == "zap-modern-web-application"
    assert (draft.cwe_id, draft.cwe_source, draft.owasp_top10_2025) == (None, None, None)


def test_a_different_endpoint_is_a_different_finding() -> None:
    drafts = _plan(ZAP_CORS, replace(NUCLEI_CORS, path="/api/users"))

    assert len(drafts) == 2
    assert all(len(draft.links) == 1 for draft in drafts)
    assert all(not draft.aggregate.severity_conflict for draft in drafts)


def test_unreviewed_rules_never_merge_across_engines() -> None:
    """同一個位置、同樣的 CWE、相似的標題：不在審查過的群組裡就各自獨立（fallback）。"""
    zap = _row(Engine.ZAP, "90022", "90022", cwe_id=209, title="Application Error Disclosure")
    nuclei = _row(
        Engine.NUCLEI, "error-disclosure", cwe_id=209, title="Application Error Disclosure"
    )

    drafts = _plan(zap, nuclei)

    assert sorted(draft.inputs.rule_group for draft in drafts) == [
        "nuclei:error-disclosure",
        "zap:90022",
    ]
    assert all(draft.aggregate.needs_review for draft in drafts)
    assert all(draft.cwe_source is CweSource.TOOL for draft in drafts)
    assert {draft.owasp_top10_2025 for draft in drafts} == {"A10:2025"}


def test_parameters_separate_findings_of_parameter_groups() -> None:
    by_q = _row(Engine.ZAP, "40018", raw_severity="3", parameter="q", path="/search")
    by_user = replace(by_q, id=uuid4(), parameter="username")
    again = replace(by_q, id=uuid4())

    drafts = _plan(by_q, by_user, again)

    assert sorted(len(draft.links) for draft in drafts) == [1, 2]
    names = {draft.inputs.parameter_name for draft in drafts}
    assert names == {"q", "username"}


def test_fallback_keeps_the_variant_and_the_tools_title() -> None:
    python = _row(Engine.NUCLEI, "tech-detect", "python", title="Wappalyzer Technology Detection")
    fonts = replace(python, id=uuid4(), rule_variant="google-font-api")

    drafts = _plan(python, fonts)

    assert {draft.inputs.rule_group for draft in drafts} == {
        "nuclei:tech-detect:python",
        "nuclei:tech-detect:google-font-api",
    }
    assert {draft.title for draft in drafts} == {"Wappalyzer Technology Detection"}
    assert {draft.inputs.kind for draft in drafts} == {FindingKind.INFORMATIONAL}


def test_an_unknown_tool_severity_needs_review() -> None:
    [draft] = _plan(replace(NUCLEI_CORS, raw_severity="unknown"))

    assert draft.aggregate == Aggregate(Severity.INFO, severity_conflict=False, needs_review=True)


def test_unverified_identity_never_merges_with_a_verified_one() -> None:
    authed = replace(ZAP_CORS, auth_role="standard_user")
    [verified] = _plan(authed)
    [unverified] = _plan(authed, context=replace(CONTEXT, auth_verified=False))

    assert verified.fingerprint != unverified.fingerprint
    assert unverified.inputs.auth_verified is False


def test_a_spec_templates_the_route() -> None:
    context = replace(CONTEXT, operations=(FrozenOperation(0, "GET", "/api/orders/{id}"),))
    first = _row(Engine.ZAP, "10098", "10098", path="/api/orders/1001")
    second = replace(first, id=uuid4(), path="/api/orders/1002")

    [draft] = _plan(first, second, context=context)

    assert (draft.inputs.route, draft.route_source) == ("/api/orders/{id}", RouteSource.OPENAPI)
    assert len(draft.links) == 2


def test_a_literal_path_with_braces_does_not_join_the_template() -> None:
    """安全審查：工具保留大括號的字面 path，和規格樣板的文字相同，仍是不同的 finding。"""
    context = replace(CONTEXT, operations=(FrozenOperation(0, "GET", "/api/orders/{id}"),))
    templated = _row(Engine.ZAP, "10098", "10098", path="/api/orders/1001")
    literal = replace(templated, id=uuid4(), path="/api/orders/{id}")

    drafts = _plan(templated, literal, context=context)

    assert sorted(draft.route_source for draft in drafts) == [
        RouteSource.LITERAL,
        RouteSource.OPENAPI,
    ]
    assert {draft.inputs.route for draft in drafts} == {"/api/orders/{id}"}


def test_drafts_are_sorted_by_fingerprint() -> None:
    rows = [_row(Engine.ZAP, "10098", path=f"/p{index}") for index in range(8)]

    drafts = _plan(*rows)

    assert [draft.fingerprint for draft in drafts] == sorted(draft.fingerprint for draft in drafts)
    assert _plan() == ()


@pytest.mark.parametrize(
    ("existing", "incoming", "expected"),
    [
        # 同等級的新來源：不變。
        (Aggregate(Severity.MEDIUM, False, False), ["2"], Aggregate(Severity.MEDIUM, False, False)),
        # 較低的新來源：最高值不變，但等級不一致。
        (Aggregate(Severity.MEDIUM, False, False), ["1"], Aggregate(Severity.MEDIUM, True, False)),
        # 較高的新來源：升到它的等級（不是因為來源變多）。
        (Aggregate(Severity.LOW, False, False), ["3"], Aggregate(Severity.HIGH, True, False)),
        # 已經衝突、需要確認的不會被清掉。
        (Aggregate(Severity.HIGH, True, True), ["3"], Aggregate(Severity.HIGH, True, True)),
        (Aggregate(Severity.INFO, False, False), ["x"], Aggregate(Severity.INFO, False, True)),
    ],
)
def test_merge_only_moves_upwards(
    existing: Aggregate, incoming: list[str], expected: Aggregate
) -> None:
    rows = [replace(ZAP_CORS, id=uuid4(), raw_severity=raw) for raw in incoming]
    [draft] = _plan(*rows)

    assert merge(existing, draft) == expected


# --- 身分是否驗證過（T16 的交接；§25.6）---------------------------------------------------------


def _details(auth: object) -> dict[str, object]:
    return {"guard_traffic": {"forwarded": 3, "auth": auth}}


HEALTHY = {"accepted": 4, "rejected": 0, "regressed": 0, "probe_rejected": 0, "lost": False}


@pytest.mark.parametrize(
    ("role", "preflight", "details", "verified"),
    [
        # anonymous 沒有要驗證的身分。
        ("anonymous", None, None, True),
        ("standard_user", PreflightResult.PASSED, _details(HEALTHY), True),
        # preflight 沒有通過、沒有 guard 的明細、身分失效或從未被接受：都不是驗證過的身分。
        ("standard_user", PreflightResult.FAILED, _details(HEALTHY), False),
        ("standard_user", PreflightResult.INCONCLUSIVE, _details(HEALTHY), False),
        ("standard_user", None, _details(HEALTHY), False),
        ("standard_user", PreflightResult.PASSED, None, False),
        ("standard_user", PreflightResult.PASSED, {"guard_traffic": None}, False),
        ("standard_user", PreflightResult.PASSED, _details(None), False),
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "lost": True}), False),
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "lost": None}), False),
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "accepted": 0}), False),
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "accepted": True}), False),
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "accepted": "4"}), False),
        # 中途過期、之後只打新端點：regressed 0、lost 仍是 false，但有被拒絕的請求（安全審查）。
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "rejected": 74}), False),
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "regressed": 1}), False),
        (
            "standard_user",
            PreflightResult.PASSED,
            _details({**HEALTHY, "probe_rejected": 1}),
            False,
        ),
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "rejected": None}), False),
        ("standard_user", PreflightResult.PASSED, _details({**HEALTHY, "rejected": False}), False),
    ],
)
def test_identity_is_verified_only_with_positive_evidence(
    role: str, preflight: PreflightResult | None, details: object, verified: bool
) -> None:
    assert identity_verified(role, preflight, details) is verified  # type: ignore[arg-type]
