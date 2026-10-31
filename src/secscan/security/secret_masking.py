"""以已知的 secret 做位元組層級的遮罩（docs/DECISIONS.md §19.5）；只用標準函式庫的純函式。

工具的輸出（log、報告）可能以任何一種編碼寫出送出去的 secret：列舉每個值的完整形式（原樣、JSON
跳脫、HTML entity、百分比編碼與它們的組合），由左到右、同一個位置取最長的形式替換，替換之後的內容
不再比對。形式來自 auth_profiles 的字元集（沒有 CR、LF、NUL；最長 4096 個字元）。

串流處理：mask_chunk 只處理「開始的位置還有完整最長形式的空間」的比對，其餘留到下一塊，所以不論
怎麼切塊，結果都相同。以 bytes.find 搜尋（不用 regex）：最壞的情況也是線性時間；每個形式只有一個
搜尋位置，記憶體不隨比對的次數增加。值與形式都不會出現在 repr 中。
"""

import heapq
import json
import re
from collections.abc import Collection, Iterator, Mapping
from dataclasses import dataclass, field
from html import escape
from typing import Self
from urllib.parse import quote, quote_plus

TARGET_SECRET_MARK = "[REDACTED:target-secret]"  # noqa: S105 - 替換字串，不是密碼
PROXY_TOKEN_MARK = "[REDACTED:proxy-token]"  # noqa: S105 - 替換字串，不是密碼
# 百分比編碼時不編碼的字元：不同的工具與函式庫保留的字元不同。
_SAFE_CHARACTERS = ("", "/", "/+=", "/+=:;,")
_PERCENT = re.compile(r"%[0-9A-F]{2}")


def secret_variants(value: str) -> frozenset[bytes]:
    """這個值在輸出中可能出現的完整形式。"""
    html_forms = {
        value,
        escape(value),
        escape(value, quote=False),
        escape(value).replace("&#x27;", "&#39;"),
    }
    json_forms = {form for html_form in html_forms for form in _json_forms(html_form)}
    percent_forms = {quote(value, safe=safe) for safe in _SAFE_CHARACTERS}
    percent_forms |= {quote_plus(value, safe=safe) for safe in _SAFE_CHARACTERS}
    lowered = {_PERCENT.sub(lambda match: match.group().lower(), form) for form in percent_forms}
    return frozenset(
        form.encode("utf-8") for form in html_forms | json_forms | percent_forms | lowered
    )


def _json_forms(value: str) -> set[str]:
    forms = {json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]}
    return forms | {form.replace("/", "\\/") for form in forms}


@dataclass(frozen=True, slots=True)
class SecretMasker:
    # 形式與替換字串，由長到短；overlap 是一塊的結尾要留到下一塊的長度。
    _forms: tuple[tuple[bytes, bytes], ...] = field(repr=False)
    overlap: int = field(repr=False)

    @classmethod
    def of(cls, values: Mapping[str, Collection[str]]) -> Self:
        """values 是 {替換字串: 要遮罩的值}；同一個形式出現兩次時以先列出的為準。"""
        marks: dict[bytes, bytes] = {}
        for mark, group in values.items():
            for value in group:
                if value:
                    for form in secret_variants(value):
                        marks.setdefault(form, mark.encode("ascii"))
        if not marks:
            raise ValueError("沒有可以遮罩的值")
        forms = tuple(sorted(marks.items(), key=lambda item: (-len(item[0]), item[0])))
        return cls(forms, len(forms[0][0]) - 1)

    def mask_chunk(self, buffer: bytes, *, final: bool) -> tuple[bytes, bytes, int]:
        """回傳（可以寫出的內容, 留到下一塊的結尾, 這一塊遮罩的次數）。

        下一塊要接在留下的結尾之後；最後一塊（final）不留下任何東西。
        """
        limit = len(buffer) if final else len(buffer) - self.overlap
        if limit <= 0:
            return b"", buffer, 0
        output: list[bytes] = []
        position = 0
        count = 0
        for start, end, mark in self._matches(buffer, limit):
            output += (buffer[position:start], mark)
            position = end
            count += 1
        keep_from = max(position, limit)
        output.append(buffer[position:keep_from])
        return b"".join(output), buffer[keep_from:], count

    def _matches(self, buffer: bytes, limit: int) -> Iterator[tuple[int, int, bytes]]:
        """開始的位置在 limit 之前、不重疊的比對：由左到右，同一個位置取最長的形式。"""
        pending = [
            (start, -len(form), index)
            for index, (form, _) in enumerate(self._forms)
            if 0 <= (start := buffer.find(form)) < limit
        ]
        heapq.heapify(pending)
        position = 0
        while pending:
            start, negative_length, index = pending[0]
            form, mark = self._forms[index]
            if start >= position:
                position = start - negative_length
                yield start, position, mark
            following = buffer.find(form, position)
            if 0 <= following < limit:
                heapq.heapreplace(pending, (following, negative_length, index))
            else:
                heapq.heappop(pending)
