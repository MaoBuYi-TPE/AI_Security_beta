"""target 與 grant 共用的錯誤對應：domain 的例外轉成穩定錯誤碼（docs/API_CONTRACT.md §12）。

domain 的訊息只說明原因，不含輸入內容，可以直接回給 client。
"""

from http import HTTPStatus

from secscan.core.errors import AppError, ErrorCode
from secscan.targets.domain import InvalidOriginError, OutsideLabError


def invalid_target_error(exc: InvalidOriginError) -> AppError:
    return AppError(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        code=ErrorCode.INVALID_TARGET,
        message=f"{exc}。",
    )


def outside_lab_error(exc: OutsideLabError) -> AppError:
    return AppError(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        code=ErrorCode.SCOPE_OUTSIDE_LAB,
        message=f"{exc}。",
    )
