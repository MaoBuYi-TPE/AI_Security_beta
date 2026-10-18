"""健康檢查的回應 schema。"""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class LiveStatus(BaseModel):
    """程序存活狀態；刻意不含版本、環境或依賴資訊。"""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok"]


class ReadyStatus(BaseModel):
    """可以接受請求；不回傳 DB 主機、版本等細節。"""

    model_config = ConfigDict(frozen=True)

    status: Literal["ready"]
