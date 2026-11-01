"""T17：Nuclei 凍結清單純函式的單元測試（解析 nuclei -tl、擷取 id、內容閘門、lock 讀寫與對帳）。

不連網、不碰容器：產生器（tools/freeze_nuclei_templates.py）才實際跑 nuclei；這裡只測純邏輯。
"""

import pytest

from secscan.scanners.domain.nuclei.selection import (
    Template,
    extract_template_id,
    format_lock,
    parse_lock,
    parse_tl_paths,
    reconcile,
    template_violations,
)

_SHA = "a" * 64
_SHB = "b" * 64

# 真實 nuclei -tl 的輸出樣貌（v3.11.1）：banner、讀不到 nuclei-ignore 的 ERR、「Listing available」
# 標題，然後每行一個絕對模板路徑。解析器只收 /templates/http/*.yaml，其餘一律丟掉。
_TL_SAMPLE = """\

                     __     _
/_/ /_/\\__,_/\\___/_/\\___/_/   v3.11.1

[ERR] Could not read nuclei-ignore file: open /root/.config/nuclei/.nuclei-ignore: no such file
Listing available  nuclei templates for /root/nuclei-templates
/templates/http/misconfiguration/http-missing-security-headers.yaml
/templates/http/miscellaneous/robots-txt.yaml
/templates/http/misconfiguration/http-missing-security-headers.yaml
/templates/http/technologies/tech-detect.yaml
/templates/dns/caa-fingerprint.yaml
/templates/http/../../etc/hosts.yaml
"""


def test_parse_tl_paths_keeps_only_http_yaml_paths_sorted_and_deduped() -> None:
    paths = parse_tl_paths(_TL_SAMPLE)
    # 去掉 banner/ERR/標題、非 http 的 dns 行與含 `..` 的穿越行；重複的只留一次；依字典序排序。
    assert paths == (
        "http/miscellaneous/robots-txt.yaml",
        "http/misconfiguration/http-missing-security-headers.yaml",
        "http/technologies/tech-detect.yaml",
    )


def test_parse_tl_paths_rejects_traversal_and_empty_segments() -> None:
    sample = (
        "/templates/http/../../etc/hosts.yaml\n"
        "/templates/http/a//b.yaml\n"
        "/templates/http/./x.yaml\n"
    )
    assert parse_tl_paths(sample) == ()


def test_parse_tl_paths_returns_empty_for_banner_only_output() -> None:
    assert parse_tl_paths("\n\nprojectdiscovery.io\n[ERR] nope\n") == ()


def test_extract_template_id_reads_top_level_id() -> None:
    yaml_text = "id: tech-detect\ninfo:\n  name: Technology Detection\n  severity: info\n"
    assert extract_template_id(yaml_text) == "tech-detect"


def test_extract_template_id_ignores_indented_id_keys() -> None:
    yaml_text = "info:\n  metadata:\n    id: not-this\nid: real-template-id\n"
    assert extract_template_id(yaml_text) == "real-template-id"


def test_extract_template_id_handles_crlf_line_endings() -> None:
    # nuclei-templates 用 CRLF；id 後面的 \r 不能讓擷取失敗。
    assert extract_template_id("id: flask-detect\r\n\r\ninfo:\r\n") == "flask-detect"


@pytest.mark.parametrize(
    "yaml_text",
    [
        "info:\n  name: no id here\n",  # 沒有 id
        'id: "quoted"\n',  # 加引號，不是裸純量
        "id: foo bar\n",  # 一行多個 token（避免靜默截成 foo）
    ],
)
def test_extract_template_id_returns_none_when_not_a_bare_scalar(yaml_text: str) -> None:
    assert extract_template_id(yaml_text) is None


def test_template_violations_passes_plain_http_template() -> None:
    yaml_text = "id: x\ninfo:\n  tags: misc,generic\nhttp:\n  - method: GET\n"
    assert template_violations(yaml_text) == ()


@pytest.mark.parametrize(
    ("yaml_text", "expected"),
    [
        ("id: x\nhttp: []\njavascript:\n  - code: f\n", ("protocol:javascript",)),
        ("id: x\nflow: http() javascript()\nhttp: []\n", ("protocol:flow",)),
        ("id: x\ncode:\n  - engine: [sh]\n", ("protocol:code",)),
        ("id: x\ntcp:\n  - inputs: []\n", ("protocol:tcp",)),
        ("id: x\ninfo:\n  tags: misc,fuzz,generic\nhttp: []\n", ("tag:fuzz",)),
        ("id: x\nflow: a\ninfo:\n  tags: dos\nhttp: []\n", ("protocol:flow", "tag:dos")),
    ],
)
def test_template_violations_flags_non_http_blocks_and_risky_tags(
    yaml_text: str, expected: tuple[str, ...]
) -> None:
    assert template_violations(yaml_text) == expected


def test_format_lock_sorts_by_id_not_path() -> None:
    # path 排序與 id 排序相反，釘住「依 id 排序」：把排序鍵改成 path 這個測試就會失敗。
    templates = [
        Template(id="zeta", sha256=_SHA, path="http/a/zeta.yaml"),
        Template(id="alpha", sha256=_SHB, path="http/z/alpha.yaml"),
    ]
    assert format_lock(templates) == (
        f"alpha {_SHB} http/z/alpha.yaml\nzeta {_SHA} http/a/zeta.yaml\n"
    )


def test_parse_lock_round_trips_format_lock() -> None:
    templates = (
        Template(id="alpha", sha256=_SHB, path="http/miscellaneous/alpha.yaml"),
        Template(id="zeta", sha256=_SHA, path="http/misconfiguration/zeta.yaml"),
    )
    assert parse_lock(format_lock(templates)) == templates


def test_parse_lock_reports_the_offending_line_number() -> None:
    text = f"\nalpha {_SHB} http/x/alpha.yaml\nBADLINE\n"
    with pytest.raises(ValueError, match="第 3 行"):
        parse_lock(text)


@pytest.mark.parametrize(
    "bad_line",
    [
        "alpha b http/x/alpha.yaml",  # sha256 太短
        "alpha " + _SHB,  # 缺 path
        "alpha " + _SHB + " ../etc/passwd",  # path 不在 http/ 底下
        "alpha " + _SHB + " http/../x.yaml",  # path 含 `..`（穿越）
        "alpha " + _SHB + " http/a//b.yaml",  # path 有空段
        "alpha " + "G" * 64 + " http/x/alpha.yaml",  # sha256 非十六進位
    ],
)
def test_parse_lock_rejects_malformed_lines(bad_line: str) -> None:
    with pytest.raises(ValueError, match="lock"):
        parse_lock(bad_line + "\n")


def test_parse_lock_rejects_duplicate_id() -> None:
    text = f"alpha {_SHB} http/x/one.yaml\nalpha {_SHA} http/x/two.yaml\n"
    with pytest.raises(ValueError, match="id 重複"):
        parse_lock(text)


def test_parse_lock_rejects_duplicate_path() -> None:
    text = f"alpha {_SHB} http/x/one.yaml\nbeta {_SHA} http/x/one.yaml\n"
    with pytest.raises(ValueError, match="path 重複"):
        parse_lock(text)


def test_reconcile_passes_when_id_sets_match() -> None:
    templates = (
        Template(id="alpha", sha256=_SHB, path="http/x/alpha.yaml"),
        Template(id="zeta", sha256=_SHA, path="http/y/zeta.yaml"),
    )
    reconcile(("alpha", "zeta"), templates)  # 不拋例外即通過


def test_reconcile_flags_missing_id_with_label() -> None:
    templates = (Template(id="alpha", sha256=_SHB, path="http/x/alpha.yaml"),)
    with pytest.raises(ValueError, match=r"缺少=\['zeta'\]"):
        reconcile(("alpha", "zeta"), templates)


def test_reconcile_flags_extra_id_with_label() -> None:
    templates = (
        Template(id="alpha", sha256=_SHB, path="http/x/alpha.yaml"),
        Template(id="surprise", sha256=_SHA, path="http/x/surprise.yaml"),
    )
    with pytest.raises(ValueError, match=r"多出=\['surprise'\]"):
        reconcile(("alpha",), templates)


def test_reconcile_flags_duplicate_id() -> None:
    templates = (
        Template(id="alpha", sha256=_SHB, path="http/x/one.yaml"),
        Template(id="alpha", sha256=_SHA, path="http/x/two.yaml"),
    )
    with pytest.raises(ValueError, match=r"重複=\['alpha'\]"):
        reconcile(("alpha",), templates)
