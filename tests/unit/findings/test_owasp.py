"""OWASP Top 10:2025 的官方 CWE 對應表（T19；docs/DECISIONS.md §25.5）：解析、驗證與凍結。

不連網：產生器（tools/freeze_owasp_top10.py）讀鎖定 commit 的官方 markdown；這裡測純函式，並核對
已提交的 JSON 與它的 sha256 釘選。
"""

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from secscan.findings.domain import owasp as owasp_module
from secscan.findings.domain.owasp import (
    CATEGORY_IDS,
    OWASP_TOP10_2025_SHA256,
    TABLE_PATH,
    Category,
    Source,
    build_table,
    load_top10,
    parse_category,
    read_table,
    table_json,
    top10_category,
)

SHA = "a" * 64
COMMIT = "b" * 40
SOURCE = Source("https://github.com/OWASP/Top10", COMMIT, "2025/docs/en")

PAGE = """\
# A02:2025 Security Misconfiguration ![icon](../assets/x.png){: style="height:80px"}

## Background.

Text that mentions CWE-1 but is not part of the list.

## List of Mapped CWEs

* [CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

* [CWE-942 Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
"""


def _parse(text: str, file: str = "A02_2025-Security_Misconfiguration.md") -> Category:
    return parse_category(text, file=file, sha256=SHA)


def _categories() -> list[Category]:
    return [
        Category(category_id, "Title", f"{category_id[:3]}_2025-Title.md", SHA, (index + 1,))
        for index, category_id in enumerate(CATEGORY_IDS)
    ]


def test_parse_reads_the_heading_and_the_mapped_list_only() -> None:
    category = _parse(PAGE)

    assert (category.id, category.title, category.cwes) == (
        "A02:2025",
        "Security Misconfiguration",
        (16, 942),
    )


def test_parse_accepts_tab_separators_and_crlf() -> None:
    page = "#  A10:2025 Mishandling of Exceptional Conditions\r\n\r\n## List of Mapped CWEs\r\n"
    page += "* [CWE-209\tGeneration of Error](https://cwe.mitre.org/data/definitions/209.html)\r\n"

    category = _parse(page, "A10_2025-Mishandling_of_Exceptional_Conditions.md")

    assert (category.id, category.cwes) == ("A10:2025", (209,))


@pytest.mark.parametrize(
    ("page", "reason"),
    [
        (PAGE.replace("# A02:2025", "# A11:2025"), "標題"),
        (PAGE.replace("## List of Mapped CWEs", "## Mapped"), "剛好一個"),
        (PAGE + "\n## List of Mapped CWEs\n", "剛好一個"),
        (PAGE + "\n## Next section\n", "CWE 項目"),
        (PAGE + "* CWE-20 without a link\n", "CWE 項目"),
        # 連結的編號和文字不同：不猜哪個才對。
        (PAGE + "* [CWE-20 X](https://cwe.mitre.org/data/definitions/21.html)\n", "CWE 項目"),
        (PAGE + "* [CWE-20 X](https://example.com/data/definitions/20.html)\n", "CWE 項目"),
        (PAGE.split("* [")[0], "沒有對應"),
    ],
)
def test_parse_fails_closed_on_unexpected_pages(page: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        _parse(page)


def test_build_table_requires_all_ten_categories_in_order() -> None:
    categories = _categories()

    assert len(build_table(SOURCE, categories).categories) == 10
    with pytest.raises(ValueError, match="依序"):
        build_table(SOURCE, categories[:9])
    with pytest.raises(ValueError, match="依序"):
        build_table(SOURCE, [categories[1], categories[0], *categories[2:]])


@pytest.mark.parametrize("repeat_in", [0, 4])
def test_a_cwe_listed_twice_is_rejected(repeat_in: int) -> None:
    categories = _categories()
    categories[repeat_in] = replace(categories[repeat_in], cwes=(*categories[repeat_in].cwes, 1))

    with pytest.raises(ValueError, match="CWE-1: A01:2025"):
        build_table(SOURCE, categories)


@pytest.mark.parametrize(
    ("file", "sha256", "reason"),
    [
        ("A01_2025-../x.md", SHA, "檔名"),
        ("A02_2025-Title.md", SHA, "檔名"),
        ("A01_2025-Title.md", "XYZ", "sha256"),
    ],
)
def test_build_table_checks_each_source_file(file: str, sha256: str, reason: str) -> None:
    categories = _categories()
    categories[0] = replace(categories[0], file=file, sha256=sha256)

    with pytest.raises(ValueError, match=reason):
        build_table(SOURCE, categories)


def test_build_table_requires_a_pinned_commit() -> None:
    with pytest.raises(ValueError, match="commit"):
        build_table(replace(SOURCE, commit="master"), _categories())


def test_the_json_round_trips_and_rejects_anything_else() -> None:
    text = table_json(build_table(SOURCE, _categories()))

    assert table_json(read_table(text)) == text
    for broken in (
        "{}",
        "not json",
        text.replace('"edition": "2025"', '"edition": "2021"'),
        text.replace('"cwes": [\n        1\n      ]', '"cwes": [\n        true\n      ]'),
        text.replace("\n}", ',\n  "extra": 1\n}'),
        text.replace("  ", " "),
    ):
        with pytest.raises(ValueError):  # noqa: PT011 - 每種壞法的訊息不同
            read_table(broken)


# --- 已提交的官方對應表 -----------------------------------------------------------------------


def test_the_committed_table_matches_its_pin() -> None:
    assert hashlib.sha256(TABLE_PATH.read_bytes()).hexdigest() == OWASP_TOP10_2025_SHA256
    table = load_top10()
    assert tuple(category.id for category in table.categories) == CATEGORY_IDS
    assert table.source.repository == "https://github.com/OWASP/Top10"


def test_the_official_counts_are_recorded_as_published() -> None:
    """A05 的 Background 寫 37 個（介紹頁另寫 38 個）；以分類頁的清單為準（§25.5）。"""
    counts = {category.id: len(category.cwes) for category in load_top10().categories}

    assert counts == {
        "A01:2025": 40,
        "A02:2025": 16,
        "A03:2025": 6,
        "A04:2025": 32,
        "A05:2025": 37,
        "A06:2025": 39,
        "A07:2025": 36,
        "A08:2025": 14,
        "A09:2025": 5,
        "A10:2025": 24,
    }


@pytest.mark.parametrize(
    ("cwe", "category"),
    [
        (942, "A02:2025"),  # 寬鬆的跨網域政策（CORS）
        (89, "A05:2025"),
        (79, "A05:2025"),
        (113, "A05:2025"),
        (22, "A01:2025"),
        (601, "A01:2025"),
        (352, "A01:2025"),
        (497, "A01:2025"),
        # 缺安全 header 的 CWE-693 與 clickjacking 的 CWE-1021 在 A06（官方清單；不改 CWE 湊 A02）。
        (693, "A06:2025"),
        (1021, "A06:2025"),
        (346, "A07:2025"),
        # ZAP 10098 回報的 CWE-264 是 CWE 的分類節點，不在任何清單。
        (264, None),
        (None, None),
    ],
)
def test_lookup_follows_the_official_lists(cwe: int | None, category: str | None) -> None:
    assert top10_category(cwe) == category


def test_a_modified_table_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    changed = tmp_path / "owasp_top10_2025.json"
    changed.write_bytes(TABLE_PATH.read_bytes().replace(b"942", b"943"))
    monkeypatch.setattr(owasp_module, "TABLE_PATH", changed)

    with pytest.raises(ValueError, match="sha256"):
        owasp_module.load_top10.__wrapped__()


def test_string_fields_must_be_strings() -> None:
    text = table_json(build_table(SOURCE, _categories()))

    with pytest.raises(ValueError, match="格式"):
        read_table(text.replace('"title": "Title"', '"title": 1', 1))
