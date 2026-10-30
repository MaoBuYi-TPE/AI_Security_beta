"""預覽開關的 dependency：app.state 的格式不對就失敗，不當成沒有開關（§18.9）。"""

from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import Request

from secscan.scans.dependencies import preview_engines
from secscan.scans.domain.catalog import Engine


def _request(**state: object) -> Request:
    return cast(Request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(**state))))


def test_the_engines_set_by_create_app_are_returned() -> None:
    assert preview_engines(_request(preview_engines=frozenset({Engine.ZAP}))) == {Engine.ZAP}


def test_an_app_without_the_setting_has_no_preview() -> None:
    assert preview_engines(_request()) == frozenset()


@pytest.mark.parametrize("value", [("zap",), frozenset({"zap"}), {Engine.ZAP}])
def test_a_malformed_setting_is_an_error(value: object) -> None:
    with pytest.raises(RuntimeError):
        preview_engines(_request(preview_engines=value))
