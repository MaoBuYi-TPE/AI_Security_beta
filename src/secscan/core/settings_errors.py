"""設定驗證錯誤的安全表示（T23b-b2；docs/DECISIONS.md §32）。

pydantic 的 ValidationError 有三種表示，都可能帶著輸入值（例如密碼）：

- `str(e)`：`hide_input_in_errors=True` 時不含輸入（各設定類別都有設定，只是縱深防禦）；
- `e.errors()`、`e.json()`：含 `input` 與 `ctx`，pydantic 不保證它們不含輸入；
- `X` 與 `X_FILE` 同時設定時，原始的輸入本身就是秘密。

所以原始的 ValidationError 不離開建立設定的地方，對外一律只輸出 safe_summary：每一項的位置與訊息
（`loc`、`msg`），位置只保留已知的欄位名稱與整數索引；絕不輸出 `input`、`ctx`、`url`。我們自己拋出的
ValueError 都是固定的訊息。

會讓程序結束、印出 traceback 的邊界（API 的 create_app、alembic 的 env.py）改拋 SettingsError：
在 except 區塊之內只算出摘要，離開區塊之後才 raise，`__context__` 與 `__cause__` 都是 None，
traceback 只有安全的訊息（`raise … from None` 只設定 `__suppress_context__`，原本的錯誤仍留在
`__context__`）。
"""

from collections.abc import Sequence

from pydantic import BaseModel, ValidationError

UNKNOWN_LOCATION = "?"
WHOLE_MODEL = "設定"
_SEPARATOR = "；"


class SettingsError(RuntimeError):
    """設定不正確；訊息只有 safe_summary（欄位名稱與固定的原因）。"""


def safe_summary(error: ValidationError, model: type[BaseModel]) -> str:
    """只含欄位位置與訊息的摘要，例如 `db_port：Input should be a valid integer`。"""
    known = frozenset(model.model_fields)
    return _SEPARATOR.join(
        f"{_location(item['loc'], known)}：{item['msg']}" for item in error.errors()
    )


def build_settings[ModelT: BaseModel](model: type[ModelT], /, **values: object) -> ModelT:
    """建立設定；驗證失敗時拋出只含 safe_summary 的 SettingsError（不帶原本的例外）。"""
    try:
        return model(**values)
    except ValidationError as exc:
        summary = safe_summary(exc, model)
    raise SettingsError(f"設定不正確：{summary}")


def _location(parts: Sequence[int | str], known: frozenset[str]) -> str:
    if not parts:
        return WHOLE_MODEL
    return ".".join(_part(part, known) for part in parts)


def _part(part: int | str, known: frozenset[str]) -> str:
    if isinstance(part, int) and not isinstance(part, bool):
        return str(part)
    if isinstance(part, str) and part in known:
        return part
    return UNKNOWN_LOCATION
