"""語意規則群組的解析、驗證與查找（T19；docs/DECISIONS.md §25.3、§25.14）。

「不可信的映射不跨工具合併」的機制在這裡：一個群組只有一個引擎；跨引擎只經審查過的佐證成員
（同一次 scan、同一個位置有錨點的觀察時才併入，判斷在 linking）；related 只標示相關。對不到群組的
觀察是單一引擎、unclassified 的 fallback。
"""

import hashlib
import re
from pathlib import Path

import pytest

from secscan.findings.domain import taxonomy as taxonomy_module
from secscan.findings.domain.normalization import Severity
from secscan.findings.domain.taxonomy import (
    FINGERPRINT_VERSION,
    KIND_CATEGORIES,
    RULE_GROUPS_PATH,
    RULE_GROUPS_SHA256,
    Classification,
    CweSource,
    FindingCategory,
    FindingKind,
    Granularity,
    ReviewStatus,
    Taxonomy,
    TaxonomyError,
    classify,
    fallback_group,
    group_classification,
    load_taxonomy,
    mapping_identity,
    member_key,
    parse_taxonomy,
)
from secscan.scans.domain.catalog import Engine

ZAP, NUCLEI = Engine.ZAP, Engine.NUCLEI

VALID = """\
schema: 2
version: "3"
groups:
  - id: xcto-missing
    title: XCTO missing
    kind: security
    category: misconfiguration
    cwe: 693
    granularity: endpoint
    owasp_api_2023:
      category: API8:2023
      rationale: listed in API8
    review:
      status: reviewed
      evidence: both tools hit GET / in the same scan
    members:
      - engine: zap
        rule: "10021"
    corroborated_by:
      - engine: nuclei
        rule: headers
        variant: xcto
  - id: nuclei-xcto-missing
    title: XCTO missing (nuclei)
    kind: security
    category: misconfiguration
    cwe: 693
    granularity: endpoint
    review:
      status: reviewed
    members:
      - engine: nuclei
        rule: headers
        variant: xcto
    related:
      - zap-sql-injection
  - id: zap-sql-injection
    title: SQL injection
    kind: security
    category: vulnerability
    cwe: 89
    review:
      status: provisional
    members:
      - engine: zap
        rule: "40018"
  - id: tech
    title: Technology detected
    kind: informational
    category: technology
    review:
      status: reviewed
    members:
      - engine: nuclei
        rule: tech-detect
        variant: "*"
"""


def _parse(text: str = VALID) -> Taxonomy:
    return parse_taxonomy(text.encode("utf-8"))


def _replace(old: str, new: str, *, count: int = 1) -> str:
    assert old in VALID, old
    return VALID.replace(old, new, count)


def test_a_valid_document_is_indexed_by_member() -> None:
    taxonomy = _parse()

    xcto = taxonomy.lookup(ZAP, "10021", None)
    assert xcto is not None
    assert (xcto.id, xcto.cwe, xcto.granularity, xcto.review, xcto.category) == (
        "xcto-missing",
        693,
        Granularity.ENDPOINT,
        ReviewStatus.REVIEWED,
        FindingCategory.MISCONFIGURATION,
    )
    assert xcto.engine is ZAP
    sqli = taxonomy.lookup(ZAP, "40018", None)
    assert sqli is not None
    assert (sqli.granularity, sqli.resource_scoped, sqli.owasp_api_2023) == (
        Granularity.PARAMETER,
        False,
        None,
    )
    assert taxonomy.version == "3"


def test_a_corroborating_member_keeps_its_own_group_and_knows_its_anchor() -> None:
    """nuclei 的成員單獨命中時留在自己的群組；同一次 scan 有錨點時才併入（linking 判斷）。"""
    taxonomy = _parse()

    own = taxonomy.lookup(NUCLEI, "headers", "xcto")
    anchor = taxonomy.anchor_for(NUCLEI, "headers", "xcto")

    assert own is not None
    assert own.id == "nuclei-xcto-missing"
    assert anchor is not None
    assert anchor.id == "xcto-missing"
    assert taxonomy.anchor_for(ZAP, "10021", None) is None
    assert dict(taxonomy.anchor_members) == {(ZAP, "10021", None): "xcto-missing"}
    # 只有 nuclei 有佐證成員：ZAP 的 run 連結時不必查錨點。
    assert (taxonomy.corroborates(NUCLEI), taxonomy.corroborates(ZAP)) == (True, False)


def test_related_groups_are_symmetric() -> None:
    taxonomy = _parse()

    assert taxonomy.related["nuclei-xcto-missing"] == {"zap-sql-injection"}
    assert taxonomy.related["zap-sql-injection"] == {"nuclei-xcto-missing"}


def test_a_variant_equal_to_the_rule_means_no_variant() -> None:
    """ZAP 的 alertRef 等於 pluginid 時沒有 variant。"""
    taxonomy = _parse()

    assert member_key(ZAP, "10021", "10021") == (ZAP, "10021", None)
    assert taxonomy.lookup(ZAP, "10021", "10021") is taxonomy.lookup(ZAP, "10021", None)


def test_lookup_is_exact_except_for_technology_names() -> None:
    taxonomy = _parse()

    assert taxonomy.lookup(ZAP, "10021", "10021-1") is None
    assert taxonomy.lookup(NUCLEI, "headers", None) is None
    assert taxonomy.lookup(NUCLEI, "headers", "csp") is None
    technology = taxonomy.lookup(NUCLEI, "tech-detect", "python")
    assert technology is not None
    assert technology.id == "tech"
    # 沒有技術名的觀察不是技術識別（走 fallback）。
    assert taxonomy.lookup(NUCLEI, "tech-detect", None) is None


def test_technology_names_stay_in_the_identity() -> None:
    """技術識別：python 與 google-font-api 各自一個 finding，分類是 technology。"""
    taxonomy = _parse()

    python, fonts = (
        classify(taxonomy, NUCLEI, "tech-detect", name, tool_cwe=None, severity=Severity.INFO)
        for name in ("python", "google-font-api")
    )

    assert (python.rule_group, fonts.rule_group) == ("tech/python", "tech/google-font-api")
    assert python.title == "Technology detected: python"
    assert (python.kind, python.category, python.needs_review) == (
        FindingKind.INFORMATIONAL,
        FindingCategory.TECHNOLOGY,
        False,
    )


@pytest.mark.parametrize("name", ["has space", "a/b", "\ufffd", "-leading", "x" * 65])
def test_a_technology_name_outside_the_rule_charset_falls_back(name: str) -> None:
    """parser 只截斷長度；字元集不符的技術名不放進審查過的群組（安全審查）。"""
    classification = classify(
        _parse(), NUCLEI, "tech-detect", name, tool_cwe=None, severity=Severity.INFO
    )

    assert (classification.category, classification.needs_review) == (
        FindingCategory.UNCLASSIFIED,
        True,
    )
    assert classification.rule_group == f"nuclei:tech-detect:{name}"


def test_technology_identities_fit_the_columns() -> None:
    """`群組/技術名` 與「標題: 技術名」不超過 rule_group（160）與 title（512）的長度。"""
    longest_id, longest_variant = 64, 64
    assert longest_id + 1 + longest_variant <= taxonomy_module.RULE_GROUP_MAX_LENGTH
    assert (
        taxonomy_module._WILDCARD_TITLE_MAX_LENGTH + len(": ") + longest_variant
        <= taxonomy_module.TITLE_MAX_LENGTH
    )


@pytest.mark.parametrize(
    ("engine", "rule", "variant", "expected"),
    [
        (ZAP, "10021", None, "zap:10021"),
        (ZAP, "10021", "10021", "zap:10021"),
        (ZAP, "10020", "10020-1", "zap:10020:10020-1"),
        (NUCLEI, "tech-detect", "python", "nuclei:tech-detect:python"),
        (NUCLEI, "robots-txt", None, "nuclei:robots-txt"),
    ],
)
def test_fallback_groups_keep_the_engine_rule_and_variant(
    engine: Engine, rule: str, variant: str | None, expected: str
) -> None:
    assert fallback_group(engine, rule, variant) == expected


def test_classify_takes_the_groups_reviewed_attributes() -> None:
    classification = classify(_parse(), ZAP, "10021", None, tool_cwe=16, severity=Severity.LOW)

    # 群組的 CWE 取代工具的；kind 與 category 來自群組，不是等級。
    assert classification == Classification(
        rule_group="xcto-missing",
        title="XCTO missing",
        kind=FindingKind.SECURITY,
        category=FindingCategory.MISCONFIGURATION,
        cwe_id=693,
        cwe_source=CweSource.RULE_GROUP,
        owasp_api_2023="API8:2023",
        granularity=Granularity.ENDPOINT,
        resource_scoped=False,
        needs_review=False,
    )


def test_the_anchor_classification_is_the_anchor_groups() -> None:
    anchor = _parse().anchor_for(NUCLEI, "headers", "xcto")
    assert anchor is not None

    assert group_classification(anchor).rule_group == "xcto-missing"


def test_a_provisional_group_needs_review() -> None:
    classification = classify(_parse(), ZAP, "40018", None, tool_cwe=89, severity=Severity.HIGH)

    assert (classification.rule_group, classification.needs_review) == ("zap-sql-injection", True)


@pytest.mark.parametrize(
    ("severity", "kind"),
    [(Severity.INFO, FindingKind.INFORMATIONAL), (Severity.LOW, FindingKind.SECURITY)],
)
def test_fallback_is_unclassified_and_needs_review(severity: Severity, kind: FindingKind) -> None:
    """kind 暫時依工具的等級；一律 unclassified、needs_review（人工確認前分開統計）。"""
    classification = classify(_parse(), ZAP, "90022", None, tool_cwe=209, severity=severity)

    assert classification == Classification(
        rule_group="zap:90022",
        title=None,
        kind=kind,
        category=FindingCategory.UNCLASSIFIED,
        cwe_id=209,
        cwe_source=CweSource.TOOL,
        owasp_api_2023=None,
        granularity=Granularity.PARAMETER,
        resource_scoped=False,
        needs_review=True,
        fallback=True,
    )


def test_fallback_without_a_tool_cwe_has_no_cwe_source() -> None:
    classification = classify(_parse(), NUCLEI, "x", None, tool_cwe=None, severity=Severity.INFO)

    assert (classification.cwe_id, classification.cwe_source) == (None, None)


_EVIDENCE = "      evidence: both tools hit GET / in the same scan\n"
_CORROBORATOR = "        variant: xcto\n  - id: nuclei-xcto"
_SQLI = '      - engine: zap\n        rule: "40018"\n'
_SQLI_KIND = "    kind: security\n    category: vulnerability\n"
_RELATED = "      - zap-sql-injection\n"
_TECH = '        rule: tech-detect\n        variant: "*"\n'
_NUCLEI_XCTO = (
    "    review:\n      status: reviewed\n    members:\n      - engine: nuclei\n"
    "        rule: headers\n        variant: xcto\n    related:\n"
)
_INVALID = {
    "corroboration needs review": (
        _replace("      status: reviewed\n" + _EVIDENCE, "      status: provisional\n"),
        "reviewed",
    ),
    "corroboration needs evidence": (_replace(_EVIDENCE, ""), "evidence"),
    "two engines in one group": (
        _replace(_SQLI, _SQLI + "      - engine: nuclei\n        rule: sqli\n"),
        "同一個引擎",
    ),
    "corroborator of the same engine": (
        _replace(
            "      - engine: nuclei\n        rule: headers\n" + _CORROBORATOR,
            '      - engine: zap\n        rule: "40018"\n  - id: nuclei-xcto',
        ),
        "其他引擎",
    ),
    "corroborator without a group": (
        _replace(_CORROBORATOR, "        variant: hsts\n  - id: nuclei-xcto"),
        "不屬於任何群組",
    ),
    "wildcard corroborator": (
        _replace(_CORROBORATOR, '        variant: "*"\n  - id: nuclei-xcto'),
        "variant",
    ),
    "wildcard outside technology": (
        _replace(_SQLI, _SQLI + '        variant: "*"\n'),
        "技術識別",
    ),
    "wildcard mixed with exact": (
        _replace(_TECH, _TECH + "      - engine: nuclei\n        rule: tech-exact\n"),
        "精確成員",
    ),
    "technology with related": (
        _replace(
            "    category: technology\n",
            "    category: technology\n    related:\n      - zap-sql-injection\n",
        ),
        "不能有 related",
    ),
    "related to a technology group": (_replace(_RELATED, "      - tech\n"), "技術識別群組"),
    "corroborator in another anchor": (
        _replace(
            _NUCLEI_XCTO,
            "    review:\n      status: reviewed\n      evidence: e\n    members:\n"
            "      - engine: nuclei\n        rule: headers\n        variant: xcto\n"
            '    corroborated_by:\n      - engine: zap\n        rule: "40018"\n    related:\n',
        ),
        "也是錨點",
    ),
    "related to nothing": (_replace(_RELATED, "      - nowhere\n"), "不存在"),
    "related to itself": (_replace(_RELATED, "      - nuclei-xcto-missing\n"), "自己"),
    "related not a list": (
        _replace("    related:\n" + _RELATED, "    related: zap-sql-injection\n"),
        "related",
    ),
    "corroborators not a list": (
        _replace(
            "    corroborated_by:\n      - engine: nuclei\n        rule: headers\n"
            "        variant: xcto\n",
            "    corroborated_by: nuclei\n",
        ),
        "corroborated_by",
    ),
    "category against kind": (
        _replace(_SQLI_KIND, "    kind: security\n    category: technology\n"),
        "不一致",
    ),
    "unclassified is for fallback": (
        _replace(_SQLI_KIND, "    kind: security\n    category: unclassified\n"),
        "不一致",
    ),
    "contract has no category yet": (
        _replace(_SQLI_KIND, "    kind: contract\n    category: vulnerability\n"),
        "不一致",
    ),
    "missing category": (_replace(_SQLI_KIND, "    kind: security\n"), "category"),
    "bad kind": (_replace(_SQLI_KIND, "    kind: finding\n    category: vulnerability\n"), "kind"),
    "kind not text": (_replace(_SQLI_KIND, "    kind: 7\n    category: vulnerability\n"), "kind"),
    "schema 1": (_replace("schema: 2", "schema: 1"), "schema"),
    "schema true": (_replace("schema: 2", "schema: true"), "schema"),
    "bad version": (_replace('version: "3"', "version: three"), "version"),
    "cwe zero": (_replace("cwe: 89", "cwe: 0"), "cwe"),
    "cwe bool": (_replace("cwe: 89", "cwe: true"), "cwe"),
    "cwe text": (_replace("cwe: 89", "cwe: '89'"), "cwe"),
    "bad granularity": (_replace("granularity: endpoint", "granularity: origin"), "granularity"),
    "api 11": (_replace("category: API8:2023", "category: API11:2023"), "category"),
    "api from top 10": (_replace("category: API8:2023", "category: A02:2025"), "category"),
    "api without rationale": (_replace("      rationale: listed in API8\n", ""), "rationale"),
    "api not an object": (
        _replace(
            "    owasp_api_2023:\n      category: API8:2023\n      rationale: listed in API8",
            "    owasp_api_2023: API8:2023",
        ),
        "owasp_api_2023",
    ),
    "group id with colon": (_replace("id: zap-sql-injection", "id: zap:40018"), "id"),
    "group id with slash": (_replace("id: zap-sql-injection", "id: zap/40018"), "id"),
    "duplicate group": (_replace("id: zap-sql-injection", "id: xcto-missing"), "重複"),
    "shared member": (_replace('rule: "40018"', 'rule: "10021"'), "相同的成員"),
    "fake engine": (
        _replace('engine: zap\n        rule: "40018"', "engine: fake\n        rule: x"),
        "引擎",
    ),
    "variant equal to rule": (
        _replace(
            'rule: tech-detect\n        variant: "*"',
            "rule: tech-detect\n        variant: tech-detect",
        ),
        "省略",
    ),
    "bad variant": (_replace('variant: "*"', "variant: ../x"), "variant"),
    "missing title": (_replace("    title: SQL injection\n", ""), "title"),
    "blank title": (_replace("    title: SQL injection", "    title: '   '"), "title"),
    "long title": (_replace("    title: SQL injection", "    title: " + "x" * 600), "title"),
    "long technology title": (
        _replace("    title: Technology detected", "    title: " + "x" * 500),
        "太長",
    ),
    "unknown field": (
        _replace("    title: SQL injection\n", "    title: SQL injection\n    tag: x\n"),
        "tag",
    ),
    "flag not bool": (
        _replace(
            "    granularity: endpoint\n", "    granularity: endpoint\n    resource_scoped: 1\n"
        ),
        "resource_scoped",
    ),
    "unknown top field": (VALID + "extra: 1\n", "extra"),
    "empty groups": (VALID.split("groups:")[0] + "groups: []\n", "groups"),
    "group not an object": (_replace("groups:\n", "groups:\n  - not-a-group\n"), "物件"),
    "review not an object": (
        _replace("    review:\n      status: provisional", "    review: yes"),
        "review",
    ),
    "empty members": (
        _replace('    members:\n      - engine: zap\n        rule: "40018"', "    members: []"),
        "members",
    ),
    "member not an object": (_replace(_SQLI, "      - zap\n"), "物件"),
    "yaml alias": ("schema: &a 1\nversion: '1'\ngroups: *a\n", "YAML"),
    "not a mapping": ("- not a mapping\n", "YAML"),
}


@pytest.mark.parametrize(("text", "reason"), list(_INVALID.values()), ids=list(_INVALID))
def test_invalid_documents_are_rejected(text: str, reason: str) -> None:
    with pytest.raises(TaxonomyError, match=re.escape(reason)):
        _parse(text)


def test_duplicate_members_are_rejected() -> None:
    with pytest.raises(TaxonomyError, match="重複的成員"):
        _parse(_replace(_SQLI, _SQLI + _SQLI))


def test_a_member_corroborates_only_one_anchor() -> None:
    second = """\
  - id: xcto-again
    title: XCTO again
    kind: security
    category: misconfiguration
    review:
      status: reviewed
      evidence: e
    members:
      - engine: zap
        rule: "10022"
    corroborated_by:
      - engine: nuclei
        rule: headers
        variant: xcto
"""

    with pytest.raises(TaxonomyError, match="兩個錨點"):
        _parse(VALID + second)


def test_two_wildcard_groups_for_one_rule_are_rejected() -> None:
    second = """\
  - id: tech-again
    title: Technology again
    kind: informational
    category: technology
    review:
      status: reviewed
    members:
      - engine: nuclei
        rule: tech-detect
        variant: "*"
"""

    with pytest.raises(TaxonomyError, match="萬用"):
        _parse(VALID + second)


def test_every_kind_with_groups_has_categories() -> None:
    assert set(KIND_CATEGORIES) == {FindingKind.SECURITY, FindingKind.INFORMATIONAL}
    assert FindingCategory.UNCLASSIFIED not in set().union(*KIND_CATEGORIES.values())


# --- 已提交的 rule_groups.yaml --------------------------------------------------------------


def test_the_committed_groups_match_their_pin() -> None:
    assert hashlib.sha256(RULE_GROUPS_PATH.read_bytes()).hexdigest() == RULE_GROUPS_SHA256
    assert load_taxonomy().version == "2"


def test_only_the_three_header_groups_take_corroboration() -> None:
    """使用者簽核（2026-11-04）：以 ZAP 為準、Nuclei 在同一次 scan 同一個位置佐證時併入。"""
    taxonomy = load_taxonomy()
    anchors = {group.id: group for group in taxonomy.anchors.values()}

    assert set(anchors) == {
        "csp-header-missing",
        "x-content-type-options-missing",
        "anti-clickjacking-header-missing",
    }
    for group in anchors.values():
        assert group.engine is ZAP
        assert group.review is ReviewStatus.REVIEWED
        assert group.evidence
        assert group.granularity is Granularity.ENDPOINT
    assert all(len({engine for engine, _, _ in group.members}) == 1 for group in taxonomy.groups)


def test_cors_is_related_but_never_merged() -> None:
    """使用者簽核：兩個工具偵測的 CORS 行為不同（`*` 對反射任意 Origin 並允許 credentials）。"""
    taxonomy = load_taxonomy()
    zap = taxonomy.lookup(ZAP, "10098", "10098")
    nuclei = taxonomy.lookup(NUCLEI, "cors-misconfig", "arbitrary-origin")

    assert zap is not None
    assert nuclei is not None
    assert zap.id != nuclei.id
    assert taxonomy.anchor_for(NUCLEI, "cors-misconfig", "arbitrary-origin") is None
    assert taxonomy.related[zap.id] == {nuclei.id}
    assert (zap.cwe, zap.category) == (264, FindingCategory.MISCONFIGURATION)
    assert (nuclei.cwe, nuclei.category) == (942, FindingCategory.VULNERABILITY)


def test_nuclei_alone_keeps_its_weaker_conditions() -> None:
    taxonomy = load_taxonomy()
    headers = "http-missing-security-headers"

    def group_of(variant: str) -> str | None:
        found = taxonomy.lookup(NUCLEI, headers, variant)
        return None if found is None else found.id

    assert group_of("x-frame-options") == "nuclei-x-frame-options-missing"
    xfo = taxonomy.lookup(NUCLEI, headers, "x-frame-options")
    assert xfo is not None
    # 只看 X-Frame-Options、不看 frame-ancestors：不能證明缺 anti-clickjacking 防護。
    assert (xfo.kind, xfo.category) == (FindingKind.INFORMATIONAL, FindingCategory.HARDENING)
    assert group_of("content-security-policy") == "nuclei-csp-header-missing"
    assert group_of("referrer-policy") == "nuclei-referrer-policy-missing"


def test_technology_and_debugger_detections_are_reviewed() -> None:
    taxonomy = load_taxonomy()

    tech = classify(
        taxonomy, NUCLEI, "tech-detect", "python", tool_cwe=None, severity=Severity.INFO
    )
    debugger = classify(
        taxonomy, NUCLEI, "werkzeug-debugger-detect", None, tool_cwe=None, severity=Severity.INFO
    )

    assert (tech.rule_group, tech.category) == (
        "nuclei-tech-detect/python",
        FindingCategory.TECHNOLOGY,
    )
    # 模板標 info，但不因此當成低風險：security、待人工確認。
    assert (debugger.kind, debugger.needs_review) == (FindingKind.SECURITY, True)


def test_mapping_identity_names_every_versioned_table() -> None:
    version, digest = mapping_identity()

    assert version == f"rules-2+owasp2025-57db8ec5ddbc+norm-1+fp-{FINGERPRINT_VERSION}"
    assert re.fullmatch("[0-9a-f]{64}", digest)
    assert len(version) <= 64


def test_a_modified_file_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """執行期核對 sha256：檔案被改動時不載入未知的群組（worker 啟動就失敗）。"""
    changed = tmp_path / "rule_groups.yaml"
    changed.write_bytes(RULE_GROUPS_PATH.read_bytes() + b"\n")
    monkeypatch.setattr(taxonomy_module, "RULE_GROUPS_PATH", changed)

    with pytest.raises(TaxonomyError, match="sha256"):
        taxonomy_module.load_taxonomy.__wrapped__()
