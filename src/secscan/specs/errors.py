"""規格的錯誤對應：domain 的例外轉成穩定錯誤碼（docs/DECISIONS.md §11.8）。

domain 的訊息只說明原因與位置，不含輸入的值，可以直接回給 client。
"""

from collections.abc import Mapping
from http import HTTPStatus
from types import MappingProxyType

from secscan.core.errors import AppError, ErrorCode
from secscan.specs.domain.documents import InvalidSpecError, SpecProblem

SPEC_ERRORS: Mapping[SpecProblem, tuple[HTTPStatus, ErrorCode]] = MappingProxyType(
    {
        SpecProblem.INVALID: (HTTPStatus.UNPROCESSABLE_ENTITY, ErrorCode.INVALID_SPEC),
        SpecProblem.UNSUPPORTED: (HTTPStatus.UNPROCESSABLE_ENTITY, ErrorCode.UNSUPPORTED_SCHEMA),
        SpecProblem.EXTERNAL_REF: (
            HTTPStatus.UNPROCESSABLE_ENTITY,
            ErrorCode.EXTERNAL_REF_FORBIDDEN,
        ),
        SpecProblem.TOO_LARGE: (HTTPStatus.REQUEST_ENTITY_TOO_LARGE, ErrorCode.SPEC_TOO_LARGE),
    }
)


def invalid_spec_error(exc: InvalidSpecError) -> AppError:
    status, code = SPEC_ERRORS[exc.problem]
    return AppError(status_code=status, code=code, message=f"{exc.message}。")
