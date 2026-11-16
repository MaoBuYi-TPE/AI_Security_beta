"""設定錯誤的安全表示（CSEC-10 的 safe_summary 與 SettingsError）。

原始的 ValidationError（errors()、json()）可能含輸入，這裡不對它做保證；只驗證對外的輸出。
"""

import logging
import secrets
import traceback
from typing import Literal, Self

import pytest
from pydantic import BaseModel, Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_core import PydanticCustomError

from secscan.core.settings_errors import (
    UNKNOWN_LOCATION,
    WHOLE_MODEL,
    SettingsError,
    build_settings,
    safe_summary,
)

# 比對的片段長度：pydantic 的 str() 會截斷輸入，只比對完整的值會漏掉部分洩漏。
FRAGMENT_LENGTH = 8


def _canary() -> str:
    return secrets.token_hex(24)


def _leaks(text: str, canary: str) -> bool:
    """text 含 canary 任何一段長度 FRAGMENT_LENGTH 的子字串（hex 不分大小寫）。"""
    lowered = text.lower()
    return any(
        canary[start : start + FRAGMENT_LENGTH] in lowered
        for start in range(len(canary) - FRAGMENT_LENGTH + 1)
    )


class _Model(BaseModel):
    """各種會失敗的欄位；不設定 hide_input_in_errors，str(e) 會帶出輸入（正向對照）。"""

    password: SecretStr = Field(min_length=64)
    port: int = 1
    mode: Literal["dev", "prod"] = "dev"
    name: str = Field(default="ok", max_length=4)
    tags: dict[str, int] = Field(default_factory=dict)
    note: str = "ok"

    @field_validator("note")
    @classmethod
    def _custom(cls, value: str) -> str:
        if value != "ok":
            # 訊息範本固定；ctx 帶著輸入：safe_summary 不得輸出 ctx。
            raise PydanticCustomError("note", "note 不正確", {"value": value})
        return value

    @model_validator(mode="after")
    def _whole(self) -> Self:
        if self.port == 2:
            raise ValueError("port 不可以是 2")
        return self


def _error(**values: object) -> ValidationError:
    with pytest.raises(ValidationError) as caught:
        _Model.model_validate(values)
    return caught.value


def _every_kind_of_failure(canary: str) -> dict[str, object]:
    return {
        "password": f"{canary}-too-short",
        "port": f"{canary}x",
        "mode": canary,
        "name": canary,
        "tags": {canary: canary},
        "note": canary,
    }


def test_raw_error_carries_the_input_positive_control() -> None:
    """偵測方式確實抓得到：未設定 hide_input_in_errors 時，str(e) 與 errors() 都含輸入。"""
    canary = _canary()

    error = _error(**_every_kind_of_failure(canary))

    assert _leaks(str(error), canary)
    assert _leaks(repr(error.errors()), canary)


def test_summary_has_only_locations_and_messages() -> None:
    canary = _canary()

    summary = safe_summary(_error(**_every_kind_of_failure(canary)), _Model)

    assert not _leaks(summary, canary)
    assert "errors.pydantic.dev" not in summary
    assert summary.split("；") == [
        "password：Value should have at least 64 items after validation, not 58",
        "port：Input should be a valid integer, unable to parse string as an integer",
        "mode：Input should be 'dev' or 'prod'",
        "name：String should have at most 4 characters",
        f"tags.{UNKNOWN_LOCATION}：Input should be a valid integer, unable to parse string as an "
        "integer",
        "note：note 不正確",
    ]


def test_canary_at_the_start_or_the_end_of_the_input_does_not_leak() -> None:
    canary = _canary()

    for value in (f"{canary}x", f"x{canary}", canary):
        summary = safe_summary(_error(port=value, mode=value), _Model)
        assert not _leaks(summary, canary)


def test_unknown_location_parts_are_replaced() -> None:
    canary = _canary()

    summary = safe_summary(_error(password="p" * 64, tags={canary: "x", "ok": 1}), _Model)

    assert summary == (
        f"tags.{UNKNOWN_LOCATION}：Input should be a valid integer, unable to parse string as an "
        "integer"
    )


def test_integer_indexes_are_kept() -> None:
    class _List(BaseModel):
        ports: list[int]

    with pytest.raises(ValidationError) as caught:
        _List(ports=[1, "x"])  # type: ignore[list-item]

    assert safe_summary(caught.value, _List) == (
        "ports.1：Input should be a valid integer, unable to parse string as an integer"
    )


def test_model_level_errors_use_a_fixed_location() -> None:
    assert safe_summary(_error(password="p" * 64, port=2), _Model) == (
        f"{WHOLE_MODEL}：Value error, port 不可以是 2"
    )


def test_build_settings_returns_the_model() -> None:
    model = build_settings(_Model, password="p" * 64)

    assert model.password.get_secret_value() == "p" * 64


def test_build_settings_raises_without_the_original_error(caplog: pytest.LogCaptureFixture) -> None:
    canary = _canary()
    caplog.set_level(logging.DEBUG)

    with pytest.raises(SettingsError) as caught:
        build_settings(_Model, **_every_kind_of_failure(canary))

    error = caught.value
    assert error.__context__ is None
    assert error.__cause__ is None
    assert str(error).startswith("設定不正確：password：")
    rendered = "".join(traceback.format_exception(error))
    for text in (str(error), repr(error), rendered, caplog.text):
        assert not _leaks(text, canary)
