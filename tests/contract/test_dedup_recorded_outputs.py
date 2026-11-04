"""真實錄製的 ZAP 輸出 → parser → plan_links 的分群（T20 去重的回歸）；不碰網路、Docker 或 DB。

golden fixture 是 T30 的 fixture app 弱點版（`tests/fixtures/zap/fixture-vuln-{web,api}/`）：parser
以錄製時的 scope 重建（觀察數等於平台當時寫入的數量），再以目前的 taxonomy 連結。斷言實際的分群：
同 CWE 的不同參數、同一個 path 的不同弱點與不同的 path 都不合併；只有 query 不同的同一個問題合併。
"""

from collections import Counter
from uuid import UUID, uuid4

from secscan.findings.domain.linking import FindingDraft, LinkContext, ObservationRow, plan_links
from secscan.findings.domain.taxonomy import load_taxonomy
from secscan.scanners.domain.zap.results import interpret
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.coverage import FrozenOperation
from secscan.scans.domain.observation import ObservationInput
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.openapi import normalize_spec
from secscan.targets.domain import parse_origin
from tests.contract.zap_recordings import FIXTURES, MANIFEST, output
from tests.dedup_support import FindingView, ObservationView, assert_no_false_merges

TARGET = UUID("0b7c8f3e-5d61-4f2a-9c84-3e1f6a2d9b70")


def _role(scenario: str) -> str:
    [entry] = [item for item in MANIFEST["fixtures"] if item["path"] == f"zap/{scenario}/zap.log"]
    role: str = entry["auth_role"]
    return role


def _operations(scenario: str) -> tuple[FrozenOperation, ...]:
    """api 的 scan 有規格：fixture app 的 6 個 operation 都在 grant 的範圍內（錄製時 eligible）。"""
    if scenario != "fixture-vuln-api":
        return ()
    spec = normalize_spec(
        (FIXTURES / "openapi" / "fixture-app-openapi3.yml").read_bytes(),
        SpecFormat.YAML,
        origin=parse_origin("http://lab-fixture-vuln-2fa2af:8080"),
    )
    return tuple(
        FrozenOperation(index, item.method, item.path) for index, item in enumerate(spec.operations)
    )


def _row(item: ObservationInput, role: str) -> ObservationRow:
    return ObservationRow(
        id=uuid4(),
        engine=Engine.ZAP,
        source_rule=item.source_rule,
        rule_variant=item.rule_variant,
        title=item.title,
        raw_severity=item.raw_severity,
        raw_confidence=item.raw_confidence,
        cwe_id=item.cwe_id,
        method=item.method,
        path=item.path,
        parameter=item.parameter,
        parameter_location=item.parameter_location,
        auth_role=role,
    )


def _linked(scenario: str) -> tuple[tuple[FindingDraft, ...], dict[UUID, ObservationInput]]:
    parsed = interpret(output(scenario))
    role = _role(scenario)
    rows = {_row(item, role): item for item in parsed.observations}
    context = LinkContext(target_id=TARGET, auth_verified=True, operations=_operations(scenario))
    drafts = plan_links(context, tuple(rows), load_taxonomy())
    return drafts, {row.id: item for row, item in rows.items()}


def _views(
    drafts: tuple[FindingDraft, ...], items: dict[UUID, ObservationInput], role: str
) -> list[FindingView]:
    return [
        FindingView(
            rule_group=draft.inputs.rule_group,
            method=draft.inputs.method,
            route=draft.inputs.route,
            route_templated=draft.inputs.route_templated,
            parameter_location=draft.inputs.parameter_location,
            parameter_name=draft.inputs.parameter_name,
            auth_role=draft.inputs.auth_role,
            resource=draft.inputs.resource,
            observations=tuple(
                ObservationView(
                    engine=Engine.ZAP,
                    source_rule=items[link.observation_id].source_rule,
                    rule_variant=items[link.observation_id].rule_variant,
                    method=items[link.observation_id].method,
                    path=items[link.observation_id].path,
                    parameter_location=items[link.observation_id].parameter_location.value,
                    parameter=items[link.observation_id].parameter,
                    auth_role=role,
                )
                for link in draft.links
            ),
        )
        for draft in drafts
    ]


def _at(drafts: tuple[FindingDraft, ...], method: str, route: str) -> list[FindingDraft]:
    return [d for d in drafts if (d.inputs.method, d.inputs.route) == (method, route)]


def test_the_web_recording_keeps_distinct_issues_apart() -> None:
    drafts, items = _linked("fixture-vuln-web")

    assert (len(items), len(drafts)) == (23, 22)
    assert_no_false_merges(_views(drafts, items, "anonymous"), load_taxonomy())
    # 同 CWE-89、同一個 path 的兩個參數（DEDUP-01 的真實版本）。
    login = [d for d in _at(drafts, "POST", "/login") if d.inputs.rule_group == "zap-sql-injection"]
    assert sorted(d.inputs.parameter_name or "" for d in login) == ["password", "username"]
    # 同一個參數上的三種弱點（DEDUP-10）。
    redirect = _at(drafts, "GET", "/go")
    assert {d.inputs.parameter_name for d in redirect} == {"next"}
    assert sorted(d.inputs.rule_group for d in redirect) == [
        "zap-crlf-injection",
        "zap-external-redirect",
        "zap-path-traversal",
    ]
    # GET / 的五個不同群組（含 CWE-693 的 CSP 與 XCTO，DEDUP-03）。
    assert sorted(d.inputs.rule_group for d in _at(drafts, "GET", "/")) == [
        "anti-clickjacking-header-missing",
        "csp-header-missing",
        "x-content-type-options-missing",
        "zap-anti-csrf-tokens-absent",
        "zap-cors-wildcard-origin",
    ]
    # 同一個規則在不同的 path 是不同的 finding。
    cors = [d for d in drafts if d.inputs.rule_group == "zap-cors-wildcard-origin"]
    assert len(cors) == len({d.inputs.route for d in cors}) == 5


def test_the_only_merge_in_the_web_recording_differs_only_in_the_query() -> None:
    """合併的對照：/search 的兩個 X-Content-Type-Options 觀察只有 query 不同（query 不是身分）。"""
    drafts, items = _linked("fixture-vuln-web")

    [merged] = [d for d in drafts if len(d.links) > 1]
    members = [items[link.observation_id] for link in merged.links]

    assert (merged.inputs.rule_group, merged.inputs.route) == (
        "x-content-type-options-missing",
        "/search",
    )
    assert len(members) == 2
    assert len({member.query for member in members}) == 2
    assert len({(m.source_rule, m.rule_variant, m.method, m.path) for m in members}) == 1


def test_the_api_recording_uses_templates_and_keeps_methods_apart() -> None:
    drafts, items = _linked("fixture-vuln-api")

    assert (len(items), len(drafts)) == (11, 11)
    assert_no_false_merges(_views(drafts, items, "standard_user"), load_taxonomy())
    assert {d.inputs.auth_role for d in drafts} == {"standard_user"}
    templated = {d.inputs.route for d in drafts if d.inputs.route_templated}
    assert templated == {"/api/orders/{id}", "/api/users/{id}", "/users/{username}"}
    # 審查過的群組不加物件（只有 fallback 加，這份錄製沒有 fallback）。
    assert {d.inputs.resource for d in drafts} == {None}
    by_method = Counter(d.inputs.method for d in _at(drafts, "GET", "/api/users"))
    by_post = Counter(d.inputs.method for d in _at(drafts, "POST", "/api/users"))
    assert (by_method["GET"], by_post["POST"]) == (2, 3)
