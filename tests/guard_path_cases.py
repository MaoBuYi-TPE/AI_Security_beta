"""T33 黃金語料：/a/{id}、GET、沒有排除；期望值獨立於分類實作。

unit/contract/live 共用資料，只有 live 證據能驗證線上的解析鏈。
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GoldenCase:
    path: str
    strict_reason: str | None
    strict_detail: str | None
    encoded_reason: str | None
    encoded_detail: str | None


PATH_CASES = (
    GoldenCase("/a/name", None, None, None, None),
    GoldenCase("/a/name+part", None, None, None, None),
    GoldenCase("/a/.hidden", None, None, None, None),
    GoldenCase("/a/name/", "PATH_NOT_AUTHORIZED", None, "PATH_NOT_AUTHORIZED", None),
    GoldenCase("/A/name", "PATH_NOT_AUTHORIZED", None, "PATH_NOT_AUTHORIZED", None),
    GoldenCase("/a/name/extra", "PATH_NOT_AUTHORIZED", None, "PATH_NOT_AUTHORIZED", None),
    GoldenCase("/b/name", "PATH_NOT_AUTHORIZED", None, "PATH_NOT_AUTHORIZED", None),
    GoldenCase("/a/name%27", "PATH_AMBIGUOUS", "percent-encoding", None, None),
    GoldenCase("/a/name%20part", "PATH_AMBIGUOUS", "percent-encoding", None, None),
    GoldenCase("/a/name%3c", "PATH_AMBIGUOUS", "percent-encoding", None, None),
    GoldenCase("/a/name%3C", "PATH_AMBIGUOUS", "percent-encoding", None, None),
    GoldenCase("/a/%7Bx%7D", "PATH_AMBIGUOUS", "percent-encoding", None, None),
    GoldenCase("/a/name%2Bpart", "PATH_AMBIGUOUS", "percent-encoding", None, None),
    GoldenCase("/a/%41", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "non-canonical"),
    GoldenCase("/a/%7E", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "non-canonical"),
    GoldenCase("/a/%2e", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "non-canonical"),
    GoldenCase(
        "/a/%2F", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-separator"
    ),
    GoldenCase(
        "/a/%5c", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-separator"
    ),
    GoldenCase(
        "/a/%3f", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-separator"
    ),
    GoldenCase(
        "/a/%23", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-separator"
    ),
    GoldenCase(
        "/a/%3b", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-separator"
    ),
    GoldenCase(
        "/a/%252F", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "double-encoding"
    ),
    GoldenCase(
        "/a/%252e", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "double-encoding"
    ),
    GoldenCase("/a/%00", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-control"),
    GoldenCase(
        "/a/%0d%0a", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-control"
    ),
    GoldenCase(
        "/a/%C0%AF", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-control"
    ),
    GoldenCase(
        "/a/%2a", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "encoded-wildcard"
    ),
    GoldenCase("/a/%", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "invalid-percent"),
    GoldenCase("/a/%2", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "invalid-percent"),
    GoldenCase("/a/%G1", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "invalid-percent"),
    GoldenCase("/a/%+2", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "invalid-percent"),
    GoldenCase(
        "/a/%u002e", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "invalid-percent"
    ),
    GoldenCase("/a/%20", "PATH_AMBIGUOUS", "percent-encoding", "PATH_AMBIGUOUS", "dot-segment"),
    GoldenCase("/a/..+", None, None, "PATH_AMBIGUOUS", "dot-segment"),
    GoldenCase("/a/+", None, None, "PATH_AMBIGUOUS", "dot-segment"),
    GoldenCase("/a/../b", "PATH_AMBIGUOUS", "syntax", "PATH_AMBIGUOUS", "syntax"),
    GoldenCase("/a//b", "PATH_AMBIGUOUS", "syntax", "PATH_AMBIGUOUS", "syntax"),
    GoldenCase("/a/{x}", "PATH_AMBIGUOUS", "syntax", "PATH_AMBIGUOUS", "syntax"),
)
