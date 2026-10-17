"""統一的 API 回應 envelope（docs/API_CONTRACT.md §1、§12）。"""

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_PAGE_LIMIT = 100
"""清單分頁的 limit 上限（CLAUDE.md §11）。"""


class ErrorDetail(BaseModel):
    """失敗回應的 error 欄位。"""

    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    request_id: str


class PageMeta(BaseModel):
    """清單回應的分頁資訊。"""

    model_config = ConfigDict(frozen=True)

    page: int = Field(ge=1)
    limit: int = Field(ge=1, le=MAX_PAGE_LIMIT)
    total: int = Field(ge=0)


class Envelope[DataT](BaseModel):
    """所有回應共用的外層格式：{success, data, error, meta}。"""

    model_config = ConfigDict(frozen=True)

    success: bool
    data: DataT | None = None
    error: ErrorDetail | None = None
    meta: PageMeta | None = None

    @model_validator(mode="after")
    def _check_success_consistency(self) -> Self:
        if self.success:
            if self.error is not None:
                raise ValueError("成功回應不得包含 error")
            return self
        if self.error is None or self.data is not None or self.meta is not None:
            raise ValueError("失敗回應必須有 error，且 data 與 meta 必須為 null")
        return self


def ok[DataT](data: DataT) -> Envelope[DataT]:
    """包裝成功回應。"""
    return Envelope(success=True, data=data)
