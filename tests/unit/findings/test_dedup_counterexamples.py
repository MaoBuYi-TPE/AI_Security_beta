"""去重的反例（T20 DoD；docs/SECURITY_AND_TESTING.md §4.3 的 DEDUP 表）。

以真的 taxonomy 與 `plan_links` 比較 fingerprint：不應合併的成對觀察（同 CWE 不同參數、同 route 不同
身分或物件、不同的弱點）一定拆開；合併的對照組（只有標題、等級、信心、工具 CWE 不同；佐證的 header；
審查過的參數群組跨物件）一定合併，避免反例只靠「什麼都不合併」通過。
"""

from dataclasses import dataclass, replace
from uuid import UUID, uuid4

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secscan.findings.domain.linking import FindingDraft, LinkContext, ObservationRow, plan_links
from secscan.findings.domain.taxonomy import (
    RULE_GROUPS_PATH,
    MemberKey,
    Taxonomy,
    load_taxonomy,
    parse_taxonomy,
)
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.coverage import FrozenOperation
from secscan.scans.domain.observation import ParameterLocation
from tests.dedup_support import FindingView, ObservationView, assert_no_false_merges

TARGET = UUID("11111111-2222-4333-8444-555555555555")
OTHER_TARGET = UUID("66666666-7777-4888-8999-aaaaaaaaaaaa")
SPEC = (
    FrozenOperation(0, "GET", "/api/orders/{id}"),
    FrozenOperation(1, "GET", "/items/{id}"),
)
PLAIN = LinkContext(target_id=TARGET, auth_verified=True)
WITH_SPEC = replace(PLAIN, operations=SPEC)


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


@dataclass(frozen=True, slots=True)
class Side:
    row: ObservationRow
    context: LinkContext = PLAIN


@dataclass(frozen=True, slots=True)
class Case:
    id: str
    why: str
    first: Side
    second: Side


def _drafts(side: Side, taxonomy: Taxonomy | None = None) -> tuple[FindingDraft, ...]:
    return plan_links(side.context, (side.row,), taxonomy or load_taxonomy())


def _key(side: Side, taxonomy: Taxonomy | None = None) -> str:
    [draft] = _drafts(side, taxonomy)
    return draft.fingerprint


SQLI = _row(Engine.ZAP, "40018", "40018", raw_severity="3", cwe_id=89)
LOGIN_SQLI = replace(SQLI, method="POST", path="/login", parameter_location=ParameterLocation.QUERY)
UNKNOWN_RULE = _row(Engine.ZAP, "90022", "90022", cwe_id=200)
ORDER = replace(UNKNOWN_RULE, path="/api/orders/1001")
XCTO = _row(Engine.ZAP, "10021", "10021", raw_severity="1", parameter="x-content-type-options")
CSP = _row(Engine.ZAP, "10038", "10038-1", parameter="Content-Security-Policy", cwe_id=693)
NUCLEI_XCTO = _row(Engine.NUCLEI, "http-missing-security-headers", "x-content-type-options")
XCTO_ANCHOR = frozenset({("x-content-type-options-missing", "GET", "/")})


SPLIT = (
    Case(
        "DEDUP-01",
        "同 CWE-89、不同參數（T30 的 POST /login username 與 password）",
        Side(replace(LOGIN_SQLI, parameter="username")),
        Side(replace(LOGIN_SQLI, id=uuid4(), parameter="password")),
    ),
    Case(
        "DEDUP-02",
        "同一個參數名、位置不同（query 與不明）",
        Side(replace(SQLI, parameter="id", parameter_location=ParameterLocation.QUERY)),
        Side(replace(SQLI, id=uuid4(), parameter="id")),
    ),
    Case(
        "DEDUP-03",
        "同 CWE-693、不同群組（CSP 與 X-Content-Type-Options）",
        Side(CSP),
        Side(replace(XCTO, cwe_id=693)),
    ),
    Case(
        "DEDUP-04",
        "未審查的規則、不同參數",
        Side(replace(UNKNOWN_RULE, parameter="a")),
        Side(replace(UNKNOWN_RULE, id=uuid4(), parameter="b")),
    ),
    Case(
        "DEDUP-05",
        "同 route、不同身分（anonymous 與 standard_user）",
        Side(SQLI),
        Side(replace(SQLI, id=uuid4(), auth_role="standard_user")),
    ),
    Case(
        "DEDUP-06",
        "同 route、不同的已認證身分（standard_user 與 admin）",
        Side(replace(SQLI, auth_role="standard_user")),
        Side(replace(SQLI, id=uuid4(), auth_role="admin")),
    ),
    Case(
        "DEDUP-07",
        "同一個身分、驗證有效與失效（§25.6）",
        Side(replace(SQLI, auth_role="standard_user")),
        Side(
            replace(SQLI, id=uuid4(), auth_role="standard_user"),
            replace(PLAIN, auth_verified=False),
        ),
    ),
    Case(
        "DEDUP-08",
        "同一個規格樣板、不同物件（未審查的規則，T20 的 v2）",
        Side(ORDER, WITH_SPEC),
        Side(replace(ORDER, id=uuid4(), path="/api/orders/1002"), WITH_SPEC),
    ),
    Case(
        "DEDUP-09",
        "沒有規格時不同物件是不同的字面 route",
        Side(replace(SQLI, path="/api/orders/1001", parameter="q")),
        Side(replace(SQLI, id=uuid4(), path="/api/orders/1002", parameter="q")),
    ),
    Case(
        "DEDUP-10",
        "同一個參數、不同的弱點（SQL injection 與 reflected XSS）",
        Side(replace(SQLI, parameter="q")),
        Side(_row(Engine.ZAP, "40012", "40012", raw_severity="3", parameter="q", cwe_id=79)),
    ),
    Case(
        "DEDUP-11",
        "同一個規則、不同的 variant（審查過的 10055-13 與未審查的 10055-6）",
        Side(_row(Engine.ZAP, "10055", "10055-13", cwe_id=693)),
        Side(_row(Engine.ZAP, "10055", "10055-6", cwe_id=693)),
    ),
    Case(
        "DEDUP-12",
        "未審查的規則不跨引擎合併（同 CWE、同位置）",
        Side(UNKNOWN_RULE),
        Side(_row(Engine.NUCLEI, "exposed-info", cwe_id=200)),
    ),
    Case(
        "DEDUP-13",
        "CORS：兩個工具的偵測行為不同，只標示相關（使用者簽核）",
        Side(_row(Engine.ZAP, "10098", "10098", cwe_id=264)),
        Side(_row(Engine.NUCLEI, "cors-misconfig", "arbitrary-origin", cwe_id=346)),
    ),
    Case(
        "DEDUP-14",
        "技術識別以技術名區分",
        Side(_row(Engine.NUCLEI, "tech-detect", "python")),
        Side(_row(Engine.NUCLEI, "tech-detect", "nginx")),
    ),
    Case(
        "DEDUP-15",
        "佐證只限同一次 scan：沒有 ZAP 錨點的 nuclei header 告警留在自己的群組",
        Side(XCTO),
        Side(NUCLEI_XCTO),
    ),
    Case(
        "DEDUP-16",
        "同一個 path、不同 method",
        Side(replace(SQLI, parameter="q")),
        Side(replace(SQLI, id=uuid4(), method="POST", parameter="q")),
    ),
    Case(
        "DEDUP-17",
        "不同的 target",
        Side(SQLI),
        Side(replace(SQLI, id=uuid4()), replace(PLAIN, target_id=OTHER_TARGET)),
    ),
    Case(
        "DEDUP-18",
        "同一個規格樣板、不同物件，未審查的規則帶參數也不合併",
        Side(replace(ORDER, parameter="q"), WITH_SPEC),
        Side(replace(ORDER, id=uuid4(), path="/api/orders/1002", parameter="q"), WITH_SPEC),
    ),
)

MERGE = (
    Case(
        "MERGE-01",
        "只有標題、等級、信心與工具的 CWE 不同（不能靠相似的文字合併，也不能因為不同而拆開）",
        Side(replace(SQLI, parameter="q")),
        Side(
            replace(
                SQLI,
                id=uuid4(),
                parameter="q",
                title="another title",
                raw_severity="2",
                raw_confidence="3",
                cwe_id=943,
            )
        ),
    ),
    Case(
        "MERGE-02",
        "佐證的 header：同一次 scan、同一個位置有 ZAP 錨點（§25.14）",
        Side(XCTO, replace(PLAIN, anchors=XCTO_ANCHOR)),
        Side(NUCLEI_XCTO, replace(PLAIN, anchors=XCTO_ANCHOR)),
    ),
    Case(
        "MERGE-03",
        "審查過的參數群組在同一個樣板的不同物件上（同一段程式）",
        Side(replace(SQLI, path="/items/5", parameter="q"), WITH_SPEC),
        Side(replace(SQLI, id=uuid4(), path="/items/6", parameter="q"), WITH_SPEC),
    ),
    Case(
        "MERGE-04",
        "endpoint 粒度的群組不看參數（ZAP 給 header 名，nuclei 沒有參數）",
        Side(XCTO),
        Side(replace(XCTO, id=uuid4(), parameter=None)),
    ),
    Case(
        "MERGE-05",
        "同一個 role label 的不同 auth profile（auth role 是身分；記為刻意的合併）",
        Side(replace(SQLI, auth_role="standard_user")),
        Side(replace(SQLI, id=uuid4(), auth_role="standard_user")),
    ),
    Case(
        "MERGE-06",
        "同一個物件在不同次 scan 的未審查規則（複掃時仍是同一個 finding）",
        Side(ORDER, WITH_SPEC),
        Side(replace(ORDER, id=uuid4(), title="changed"), WITH_SPEC),
    ),
)


@pytest.mark.parametrize("case", SPLIT, ids=[case.id for case in SPLIT])
def test_counterexamples_never_merge(case: Case) -> None:
    assert _key(case.first) != _key(case.second), case.why


@pytest.mark.parametrize("case", MERGE, ids=[case.id for case in MERGE])
def test_controls_merge(case: Case) -> None:
    assert _key(case.first) == _key(case.second), case.why


def test_split_cases_in_one_run_stay_apart() -> None:
    """同一個 run 的同一批觀察：每對反例在 plan_links 中也是兩個 draft（不只是雜湊不同）。"""
    for case in SPLIT:
        if case.first.context != case.second.context:
            continue
        drafts = plan_links(case.first.context, (case.first.row, case.second.row), load_taxonomy())
        assert len(drafts) == 2, case.why


def test_a_resource_scoped_group_keeps_objects_apart() -> None:
    """審查成 resource_scoped 的群組：同一個樣板的不同物件不合併，同一個物件合併。"""
    taxonomy = _resource_scoped("zap-sql-injection")
    first = Side(replace(SQLI, path="/items/5", parameter="q"), WITH_SPEC)
    other = Side(replace(SQLI, id=uuid4(), path="/items/6", parameter="q"), WITH_SPEC)
    again = Side(replace(SQLI, id=uuid4(), path="/items/5", parameter="q"), WITH_SPEC)

    assert _key(first, taxonomy) != _key(other, taxonomy)
    assert _key(first, taxonomy) == _key(again, taxonomy)
    [draft] = _drafts(first, taxonomy)
    assert (draft.inputs.route, draft.inputs.resource) == ("/items/{id}", "/items/5")


def _resource_scoped(group_id: str) -> Taxonomy:
    content = RULE_GROUPS_PATH.read_bytes().decode()
    marker = f"  - id: {group_id}\n"
    assert content.count(marker) == 1
    return parse_taxonomy(content.replace(marker, f"{marker}    resource_scoped: true\n").encode())


# --- 性質：從真實的 taxonomy 成員與 fallback 產生觀察 ---


def _members() -> list[MemberKey]:
    taxonomy = load_taxonomy()
    members = [
        (engine, rule, "python" if variant == "*" else variant)
        for group in taxonomy.groups
        for engine, rule, variant in group.members
    ]
    return members


# 沒有審查過的規則（fallback）：和審查過的成員各佔一半，樣板 route 下的物件規則才會被涵蓋。
FALLBACKS: list[MemberKey] = [
    (Engine.ZAP, "90022", None),
    (Engine.NUCLEI, "unknown-template", None),
]


ROLES = st.sampled_from(["anonymous", "standard_user", "admin"])
NAMES = st.sampled_from(["q", "id", "username", "next"])
PATHS = st.sampled_from(["/", "/login", "/api/orders/1001", "/items/5", "/go"])


@st.composite
def _sides(draw: st.DrawFn) -> Side:
    engine, rule, variant = draw(st.sampled_from(_members()) | st.sampled_from(FALLBACKS))
    row = _row(
        engine,
        rule,
        variant,
        method=draw(st.sampled_from(["GET", "POST"])),
        path=draw(PATHS),
        parameter=draw(st.none() | NAMES),
        parameter_location=draw(st.sampled_from(list(ParameterLocation))),
        auth_role=draw(ROLES),
    )
    context = draw(st.sampled_from([PLAIN, WITH_SPEC]))
    return Side(row, context)


IDENTITY_CHANGES = st.sampled_from(["method", "auth_role", "target", "verified", "plain_path"])


@settings(derandomize=True, max_examples=300)
@given(side=_sides(), change=IDENTITY_CHANGES)
def test_changing_one_identity_dimension_splits(side: Side, change: str) -> None:
    base, changed = _identity_change(side, change)

    assert _key(base) != _key(changed)


def _identity_change(side: Side, change: str) -> tuple[Side, Side]:
    """(基準, 只改一個身分維度)。"""
    row, context = side.row, side.context
    match change:
        case "method":
            return side, Side(replace(row, id=uuid4(), method="PUT"), context)
        case "auth_role":
            return side, Side(replace(row, id=uuid4(), auth_role=f"{row.auth_role}-other"), context)
        case "target":
            return side, Side(replace(row, id=uuid4()), replace(context, target_id=OTHER_TARGET))
        case "verified":
            unverified = replace(context, auth_verified=not context.auth_verified)
            return side, Side(replace(row, id=uuid4()), unverified)
        case _:
            # 沒有規格時 path 就是 route（有規格時樣板可能相同，由 resource 的案例另外涵蓋）。
            plain = Side(row, PLAIN)
            return plain, Side(replace(row, id=uuid4(), path=f"{row.path}x"), PLAIN)


@settings(derandomize=True, max_examples=300)
@given(side=_sides(), title=st.text(min_size=1, max_size=20), cwe=st.none() | st.integers(1, 999))
def test_changing_only_non_identity_fields_merges(side: Side, title: str, cwe: int | None) -> None:
    """標題、信心與工具 CWE 不是身分（fallback 的 kind 依等級，所以這裡不改等級）。"""
    confidence = "3" if side.row.engine is Engine.ZAP else "high"
    changed = Side(
        replace(side.row, id=uuid4(), title=title, raw_confidence=confidence, cwe_id=cwe),
        side.context,
    )

    assert _key(side) == _key(changed)


@settings(derandomize=True, max_examples=200)
@given(
    sides=st.lists(_sides(), min_size=1, max_size=12), context=st.sampled_from([PLAIN, WITH_SPEC])
)
def test_every_planned_finding_satisfies_the_invariants(
    sides: list[Side], context: LinkContext
) -> None:
    """同一個 context 的一批觀察：每個 draft 的成員在每個身分維度上都相同（dedup_support）。"""
    rows = tuple(side.row for side in sides)
    by_id = {row.id: row for row in rows}

    drafts = plan_links(context, rows, load_taxonomy())

    assert_no_false_merges((_view(draft, by_id) for draft in drafts), load_taxonomy())
    assert sum(len(draft.links) for draft in drafts) == len(rows)


def _view(draft: FindingDraft, rows: dict[UUID, ObservationRow]) -> FindingView:
    inputs = draft.inputs
    members = [rows[link.observation_id] for link in draft.links]
    return FindingView(
        rule_group=inputs.rule_group,
        method=inputs.method,
        route=inputs.route,
        route_templated=inputs.route_templated,
        parameter_location=inputs.parameter_location,
        parameter_name=inputs.parameter_name,
        auth_role=inputs.auth_role,
        resource=inputs.resource,
        observations=tuple(
            ObservationView(
                engine=row.engine,
                source_rule=row.source_rule,
                rule_variant=row.rule_variant,
                method=row.method,
                path=row.path,
                parameter_location=row.parameter_location.value,
                parameter=row.parameter,
                auth_role=row.auth_role,
            )
            for row in members
        ),
    )
