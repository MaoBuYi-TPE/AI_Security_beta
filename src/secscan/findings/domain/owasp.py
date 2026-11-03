"""OWASP Top 10:2025 的官方 CWE 對應表（docs/DECISIONS.md §25.5；CLAUDE.md §10）。

官方每個分類頁的「List of Mapped CWEs」是唯一來源：tools/freeze_owasp_top10.py 讀鎖定 commit 的
10 個分類 markdown，以這裡的純函式擷取、驗證之後寫成 taxonomy/owasp_top10_2025.json（含來源的
commit 與每檔 sha256）。執行期載入已提交的 JSON，sha256 必須等於 OWASP_TOP10_2025_SHA256，被改動
就 fail closed。查不到的 CWE 沒有分類（不改 CWE 去湊對應）。
"""

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import MappingProxyType

from secscan.core.json_types import JsonValue

EDITION = "2025"
CATEGORY_IDS = tuple(f"A{number:02d}:{EDITION}" for number in range(1, 11))
TABLE_PATH = Path(__file__).parents[1] / "taxonomy" / "owasp_top10_2025.json"
# 凍結守衛：已提交 JSON 的 sha256。重新凍結時由產生器印出新值、更新這裡（test_owasp.py 核對）。
OWASP_TOP10_2025_SHA256 = "449c055f5825748c615a0f4cb46b621fa3d1f611de887e9b6e033f54083e3a54"
MAPPED_CWES_HEADING = "## List of Mapped CWEs"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
# 第一行：`# A02:2025 Security Misconfiguration ![icon](...)`（A01 的 # 後面有兩個空白）。
_HEADING = re.compile(
    rf"#[ \t]+(A(?:0[1-9]|10):{EDITION})[ \t]+([A-Za-z][A-Za-z &,-]*?)[ \t]*(?:!\[.*)?"
)
# 清單的每一項：`* [CWE-942 名稱](https://cwe.mitre.org/data/definitions/942.html)`
# （A10 以 tab 分隔）。
_ITEM = re.compile(
    r"\* \[CWE-([1-9][0-9]{0,6})[ \t]+[^\]\n]+\]"
    r"\(https://cwe\.mitre\.org/data/definitions/([1-9][0-9]{0,6})\.html\)[ \t]*"
)
_FILE_NAME = re.compile(rf"A(?:0[1-9]|10)_{EDITION}-[A-Za-z_]+\.md")


@dataclass(frozen=True, slots=True)
class Source:
    """官方 repository 中鎖定的位置。"""

    repository: str
    commit: str
    directory: str


@dataclass(frozen=True, slots=True)
class Category:
    """一個分類：ID、官方頁面的標題、來源檔與它的 sha256、對應的 CWE（依頁面上的順序）。"""

    id: str
    title: str
    file: str
    sha256: str
    cwes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Top10Table:
    source: Source
    categories: tuple[Category, ...]


def parse_category(markdown: str, *, file: str, sha256: str) -> Category:
    """從分類頁的 markdown 擷取 ID、標題與「List of Mapped CWEs」。格式不符就拋 ValueError。"""
    lines = markdown.replace("\r\n", "\n").split("\n")
    heading = _HEADING.fullmatch(lines[0].rstrip())
    if heading is None:
        raise ValueError(f"{file}：第一行不是分類標題")
    starts = [index for index, line in enumerate(lines) if line.rstrip() == MAPPED_CWES_HEADING]
    if len(starts) != 1:
        raise ValueError(f"{file}：「{MAPPED_CWES_HEADING}」必須剛好一個")
    cwes: list[int] = []
    for number, line in enumerate(lines[starts[0] + 1 :], starts[0] + 2):
        if not line.strip():
            continue
        item = _ITEM.fullmatch(line)
        if item is None or item.group(1) != item.group(2):
            # 清單之後不應有其他內容：新的段落或格式改變都要人工確認，不猜。
            raise ValueError(f"{file}：第 {number} 行不是對應的 CWE 項目")
        cwes.append(int(item.group(1)))
    if not cwes:
        raise ValueError(f"{file}：沒有對應的 CWE")
    return Category(heading.group(1), heading.group(2), file, sha256, tuple(cwes))


def build_table(source: Source, categories: Sequence[Category]) -> Top10Table:
    """10 個分類依序齊全；同一個 CWE 不能出現兩次（同分類或跨分類都失敗，由人決定，不猜）。"""
    if not _COMMIT.fullmatch(source.commit):
        raise ValueError("來源的 commit 必須是 40 位小寫十六進位")
    if tuple(category.id for category in categories) != CATEGORY_IDS:
        raise ValueError(f"分類必須依序是 {', '.join(CATEGORY_IDS)}")
    owners: dict[int, list[str]] = {}
    for category in categories:
        if not _FILE_NAME.fullmatch(category.file) or not category.file.startswith(category.id[:3]):
            raise ValueError(f"{category.id}：來源檔名不符")
        if not _SHA256.fullmatch(category.sha256):
            raise ValueError(f"{category.id}：sha256 格式不符")
        for cwe in category.cwes:
            owners.setdefault(cwe, []).append(category.id)
    repeated = {cwe: ids for cwe, ids in owners.items() if len(ids) > 1}
    if repeated:
        detail = "; ".join(f"CWE-{cwe}: {', '.join(ids)}" for cwe, ids in sorted(repeated.items()))
        raise ValueError(f"CWE 重複出現：{detail}")
    return Top10Table(source, tuple(categories))


def table_json(table: Top10Table) -> str:
    """凍結的 JSON（固定的 key 順序與縮排，逐位元組可重現）。"""
    document = {
        "edition": EDITION,
        "source": {
            "repository": table.source.repository,
            "commit": table.source.commit,
            "directory": table.source.directory,
        },
        "categories": [
            {
                "id": category.id,
                "title": category.title,
                "file": category.file,
                "sha256": category.sha256,
                "cwes": list(category.cwes),
            }
            for category in table.categories
        ],
    }
    return json.dumps(document, ensure_ascii=True, indent=2) + "\n"


def read_table(text: str) -> Top10Table:
    """讀凍結的 JSON：結構嚴格檢查，而且必須是 table_json 產生的形式（多餘的欄位也會被發現）。"""
    try:
        document = json.loads(text)
        source = document["source"]
        table = build_table(
            Source(
                _string(source["repository"]),
                _string(source["commit"]),
                _string(source["directory"]),
            ),
            [_category(item) for item in document["categories"]],
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("OWASP 對應表的格式不符") from exc
    if document.get("edition") != EDITION or table_json(table) != text:
        raise ValueError("OWASP 對應表不是產生器的輸出")
    return table


@cache
def load_top10() -> Top10Table:
    """已提交的對應表；sha256 必須等於 OWASP_TOP10_2025_SHA256（被改動就 fail closed）。"""
    data = TABLE_PATH.read_bytes()
    if hashlib.sha256(data).hexdigest() != OWASP_TOP10_2025_SHA256:
        raise ValueError("owasp_top10_2025.json 的 sha256 與 OWASP_TOP10_2025_SHA256 不符")
    return read_table(data.decode("ascii"))


@cache
def _index() -> Mapping[int, str]:
    return MappingProxyType(
        {cwe: category.id for category in load_top10().categories for cwe in category.cwes}
    )


def top10_category(cwe: int | None) -> str | None:
    """CWE 在官方清單中的分類（例如 A02:2025）；沒有 CWE 或清單中沒有時是 None。"""
    return None if cwe is None else _index().get(cwe)


def _category(item: Mapping[str, JsonValue]) -> Category:
    cwes = item["cwes"]
    if not isinstance(cwes, list) or not all(
        isinstance(cwe, int) and not isinstance(cwe, bool) and cwe > 0 for cwe in cwes
    ):
        raise TypeError("cwes 必須是正整數的清單")
    return Category(
        _string(item["id"]),
        _string(item["title"]),
        _string(item["file"]),
        _string(item["sha256"]),
        tuple(int(cwe) for cwe in cwes if isinstance(cwe, int)),
    )


def _string(value: JsonValue) -> str:
    if not isinstance(value, str):
        raise TypeError("必須是字串")
    return value
