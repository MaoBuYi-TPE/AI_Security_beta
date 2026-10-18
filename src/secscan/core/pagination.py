"""清單分頁（page/limit，CLAUDE.md §11）。repository 以 PageRequest 查詢、回傳 Page。"""

from dataclasses import dataclass

from secscan.core.envelope import MAX_PAGE_LIMIT

DEFAULT_PAGE_LIMIT = 25
# 頁碼上限：offset 最多約一百萬筆。太大的頁碼會讓 OFFSET 溢位（bigint）或變成很慢的查詢。
MAX_PAGE = 10_000


@dataclass(frozen=True, slots=True)
class PageRequest:
    """第幾頁（從 1 起算）與每頁筆數。超出範圍時直接拒絕，不默默修正。"""

    page: int = 1
    limit: int = DEFAULT_PAGE_LIMIT

    def __post_init__(self) -> None:
        if not 1 <= self.page <= MAX_PAGE:
            raise ValueError(f"page 必須介於 1 與 {MAX_PAGE} 之間")
        if not 1 <= self.limit <= MAX_PAGE_LIMIT:
            raise ValueError(f"limit 必須介於 1 與 {MAX_PAGE_LIMIT} 之間")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.limit


@dataclass(frozen=True)
class Page[T]:
    """一頁結果：items 為不可變 tuple，total 為符合條件的總筆數。"""

    items: tuple[T, ...]
    total: int
    request: PageRequest

    def __post_init__(self) -> None:
        if self.total < 0:
            raise ValueError("total 不得為負數")
