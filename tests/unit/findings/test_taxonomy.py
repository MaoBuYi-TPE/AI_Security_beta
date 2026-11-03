"""語意規則群組的解析、驗證與查找（T19；docs/DECISIONS.md §25.3）。

「不可信的映射不跨工具合併」的機制在這裡：跨引擎的群組必須 reviewed 並有 evidence；對不到群組的
觀察是單一引擎的 fallback。
"""

import hashlib
import re
from pathlib import Path

import pytest

from secscan.findings.domain import taxonomy as taxonomy_module
from secscan.findings.domain.normalization import Severity
from secscan.findings.domain.taxonomy import (
    FINGERPRINT_VERSION,
    RULE_GROUPS_PATH,
    RULE_GROUPS_SHA256,
    Classification,
    CweSource,
    FindingKind,
    Granularity,
    ReviewStatus,
    Taxonomy,
    TaxonomyError,
    classify,
    fallback_group,
    load_taxonomy,
    mapping_identity,
    member_key,
    parse_taxonomy,
)
from secscan.scans.domain.catalog import Engine

ZAP, NUCLEI = Engine.ZAP, Engine.NUCLEI

VALID = """\
schema: 1
version: "3"
groups:
  - id: cors-permissive-policy
    title: Permissive CORS policy
    kind: security
    cwe: 942
    granularity: endpoint
    owasp_api_2023:
      category: API8:2023
      rationale: listed in API8
    review:
      status: reviewed
      evidence: both tools hit GET / on the same response
    members:
      - engine: zap
        rule: "10098"
      - engine: nuclei
        rule: cors-misconfig
        variant: arbitrary-origin
  - id: zap-sql-injection
    title: SQL injection
    kind: security
    cwe: 89
    review:
      status: provisional
    members:
      - engine: zap
        rule: "40018"
"""


def _parse(text: str = VALID) -> Taxonomy:
    return parse_taxonomy(text.encode("utf-8"))


def test_a_valid_document_is_indexed_by_member() -> None:
    taxonomy = _parse()

    cors = taxonomy.lookup(ZAP, "10098", None)
    assert cors is not None
    assert (cors.id, cors.cwe, cors.granularity, cors.review) == (
        "cors-permissive-policy",
        942,
        Granularity.ENDPOINT,
        ReviewStatus.REVIEWED,
    )
    assert cors.engines == frozenset({ZAP, NUCLEI})
    assert taxonomy.lookup(NUCLEI, "cors-misconfig", "arbitrary-origin") is cors
    sqli = taxonomy.lookup(ZAP, "40018", None)
    assert sqli is not None
    assert (sqli.granularity, sqli.resource_scoped, sqli.owasp_api_2023) == (
        Granularity.PARAMETER,
        False,
        None,
    )
    assert taxonomy.version == "3"


def test_a_variant_equal_to_the_rule_means_no_variant() -> None:
    """ZAP 的 alertRef 等於 pluginid 時沒有 variant。"""
    taxonomy = _parse()

    assert member_key(ZAP, "10098", "10098") == (ZAP, "10098", None)
    assert taxonomy.lookup(ZAP, "10098", "10098") is taxonomy.lookup(ZAP, "10098", None)


def test_lookup_is_exact() -> None:
    taxonomy = _parse()

    assert taxonomy.lookup(ZAP, "10098", "10098-1") is None
    assert taxonomy.lookup(NUCLEI, "cors-misconfig", None) is None
    assert taxonomy.lookup(NUCLEI, "10098", None) is None


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
    classification = classify(
        _parse(), NUCLEI, "cors-misconfig", "arbitrary-origin", tool_cwe=346, severity=Severity.INFO
    )

    # 審查後的 CWE 取代工具的；kind 來自群組，不是等級。
    assert classification == Classification(
        rule_group="cors-permissive-policy",
        title="Permissive CORS policy",
        kind=FindingKind.SECURITY,
        cwe_id=942,
        cwe_source=CweSource.RULE_GROUP,
        owasp_api_2023="API8:2023",
        granularity=Granularity.ENDPOINT,
        resource_scoped=False,
        needs_review=False,
    )


def test_a_provisional_group_needs_review() -> None:
    classification = classify(_parse(), ZAP, "40018", None, tool_cwe=89, severity=Severity.HIGH)

    assert (classification.rule_group, classification.needs_review) == ("zap-sql-injection", True)


@pytest.mark.parametrize(
    ("severity", "kind"),
    [(Severity.INFO, FindingKind.INFORMATIONAL), (Severity.LOW, FindingKind.SECURITY)],
)
def test_fallback_is_single_engine_and_needs_review(severity: Severity, kind: FindingKind) -> None:
    classification = classify(_parse(), ZAP, "90022", None, tool_cwe=209, severity=severity)

    assert classification == Classification(
        rule_group="zap:90022",
        title=None,
        kind=kind,
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


_CROSS_ENGINE_PROVISIONAL = VALID.replace(
    "      status: reviewed\n      evidence: both tools hit GET / on the same response\n",
    "      status: provisional\n",
)
_CROSS_ENGINE_NO_EVIDENCE = VALID.replace(
    "      evidence: both tools hit GET / on the same response\n", ""
)


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (_CROSS_ENGINE_PROVISIONAL, "跨引擎"),
        (_CROSS_ENGINE_NO_EVIDENCE, "跨引擎"),
        (VALID.replace("schema: 1", "schema: 2"), "schema"),
        (VALID.replace('version: "3"', "version: three"), "version"),
        (
            VALID.replace("    kind: security\n    cwe: 89", "    kind: finding\n    cwe: 89"),
            "kind",
        ),
        (VALID.replace("cwe: 89", "cwe: 0"), "cwe"),
        (VALID.replace("cwe: 89", "cwe: true"), "cwe"),
        (VALID.replace("cwe: 89", "cwe: '89'"), "cwe"),
        (VALID.replace("granularity: endpoint", "granularity: origin"), "granularity"),
        (VALID.replace("category: API8:2023", "category: API11:2023"), "category"),
        (VALID.replace("category: API8:2023", "category: A02:2025"), "category"),
        (VALID.replace("      rationale: listed in API8\n", ""), "rationale"),
        (VALID.replace("id: zap-sql-injection", "id: zap:40018"), "id"),
        (VALID.replace("id: zap-sql-injection", "id: cors-permissive-policy"), "重複"),
        (VALID.replace('rule: "40018"', 'rule: "10098"'), "相同的成員"),
        (
            VALID.replace('engine: zap\n        rule: "40018"', "engine: fake\n        rule: x"),
            "引擎",
        ),
        (VALID.replace("variant: arbitrary-origin", "variant: cors-misconfig"), "省略"),
        (VALID.replace("variant: arbitrary-origin", "variant: ../x"), "variant"),
        (VALID.replace("    title: SQL injection\n", ""), "title"),
        (
            VALID.replace("    title: SQL injection\n", "    title: SQL injection\n    tag: x\n"),
            "tag",
        ),
        (VALID + "extra: 1\n", "extra"),
        (VALID.split("groups:")[0] + "groups: []\n", "groups"),
        ("schema: &a 1\nversion: '1'\ngroups: *a\n", "YAML"),
        ("- not a mapping\n", "YAML"),
    ],
)
def test_invalid_documents_are_rejected(text: str, reason: str) -> None:
    with pytest.raises(TaxonomyError, match=re.escape(reason)):
        _parse(text)


def test_duplicate_members_within_a_group_are_rejected() -> None:
    text = VALID.replace(
        '      - engine: zap\n        rule: "40018"\n',
        '      - engine: zap\n        rule: "40018"\n      - engine: zap\n        rule: "40018"\n',
    )

    with pytest.raises(TaxonomyError, match="重複的成員"):
        _parse(text)


# --- 已提交的 rule_groups.yaml --------------------------------------------------------------


def test_the_committed_groups_match_their_pin() -> None:
    assert hashlib.sha256(RULE_GROUPS_PATH.read_bytes()).hexdigest() == RULE_GROUPS_SHA256
    assert load_taxonomy().version == "1"


def test_only_the_reviewed_co_located_rules_merge_across_engines() -> None:
    """跨引擎的群組只有 T18 實證的四個（fixture 弱點版 GET / 的同一個回應）。"""
    cross = {group.id: group for group in load_taxonomy().groups if len(group.engines) > 1}

    assert set(cross) == {
        "cors-permissive-policy",
        "csp-header-missing",
        "x-content-type-options-missing",
        "anti-clickjacking-header-missing",
    }
    for group in cross.values():
        assert group.review is ReviewStatus.REVIEWED
        assert group.evidence
        assert group.granularity is Granularity.ENDPOINT


def test_the_cross_engine_members_are_the_observed_rules() -> None:
    taxonomy = load_taxonomy()

    def group_of(engine: Engine, rule: str, variant: str | None) -> str | None:
        found = taxonomy.lookup(engine, rule, variant)
        return None if found is None else found.id

    assert group_of(ZAP, "10098", "10098") == group_of(NUCLEI, "cors-misconfig", "arbitrary-origin")
    assert group_of(ZAP, "10038", "10038-1") == group_of(
        NUCLEI, "http-missing-security-headers", "content-security-policy"
    )
    assert group_of(ZAP, "10021", "10021") == group_of(
        NUCLEI, "http-missing-security-headers", "x-content-type-options"
    )
    assert group_of(ZAP, "10020", "10020-1") == group_of(
        NUCLEI, "http-missing-security-headers", "x-frame-options"
    )
    # 其他缺少的 header 不和任何 ZAP 規則合併；動態的 variant 走 fallback。
    assert group_of(NUCLEI, "http-missing-security-headers", "referrer-policy") == (
        "nuclei-referrer-policy-missing"
    )
    assert group_of(NUCLEI, "tech-detect", "python") is None
    assert group_of(NUCLEI, "werkzeug-debugger-detect", None) is None


def test_mapping_identity_names_every_versioned_table() -> None:
    version, digest = mapping_identity()

    assert version == f"rules-1+owasp2025-57db8ec5ddbc+norm-1+fp-{FINGERPRINT_VERSION}"
    assert re.fullmatch("[0-9a-f]{64}", digest)
    assert len(version) <= 64


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (VALID.replace("groups:\n  - id: cors", "groups:\n  - not-a-group\n  - id: cors"), "物件"),
        (VALID.replace("    review:\n      status: provisional", "    review: yes"), "review"),
        (
            VALID.replace(
                '    members:\n      - engine: zap\n        rule: "40018"', "    members: []"
            ),
            "members",
        ),
        (VALID.replace('      - engine: zap\n        rule: "40018"', "      - zap"), "物件"),
        (
            VALID.replace(
                "    owasp_api_2023:\n      category: API8:2023\n      rationale: listed in API8",
                "    owasp_api_2023: API8:2023",
            ),
            "owasp_api_2023",
        ),
        (VALID.replace("    title: SQL injection", "    title: '   '"), "title"),
        (VALID.replace("    title: SQL injection", "    title: " + "x" * 600), "title"),
        (
            VALID.replace(
                "    granularity: endpoint", "    granularity: endpoint\n    resource_scoped: 1"
            ),
            "resource_scoped",
        ),
        (VALID.replace("    kind: security\n    cwe: 89", "    kind: 7\n    cwe: 89"), "kind"),
    ],
)
def test_malformed_fields_are_rejected(text: str, reason: str) -> None:
    with pytest.raises(TaxonomyError, match=re.escape(reason)):
        _parse(text)


def test_a_modified_file_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """執行期核對 sha256：檔案被改動時不載入未知的群組（worker 啟動就失敗）。"""
    changed = tmp_path / "rule_groups.yaml"
    changed.write_bytes(RULE_GROUPS_PATH.read_bytes() + b"\n")
    monkeypatch.setattr(taxonomy_module, "RULE_GROUPS_PATH", changed)

    with pytest.raises(TaxonomyError, match="sha256"):
        taxonomy_module.load_taxonomy.__wrapped__()
