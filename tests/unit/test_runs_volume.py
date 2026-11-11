"""從 compose 解析之後的設定取出 runs volume（docs/DECISIONS.md §30.13；make runs-layout-migrate）。

解析失敗、缺少欄位或名稱不合法時拒絕，不退回任何預設名稱。
"""

import io
import json
from typing import Any

import pytest

from secscan.cli.runs_volume import MAX_CONFIG_BYTES, RunsVolumeError, main, parse


def _config(**changes: Any) -> str:
    config: dict[str, Any] = {"name": "secscan", "volumes": {"runs": {"name": "custom_runs"}}}
    return json.dumps(config | changes)


def test_the_project_and_the_resolved_volume_are_read() -> None:
    assert parse(_config()) == ("secscan", "custom_runs")


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        _config(name=None),
        _config(name="Upper"),
        _config(volumes={}),
        _config(volumes={"runs": {}}),
        _config(volumes={"runs": {"name": ""}}),
        _config(volumes={"runs": {"name": "bad name"}}),
        _config(volumes={"runs": {"name": "-flag"}}),
        _config(volumes=[]),
    ],
)
def test_anything_unexpected_is_refused(text: str) -> None:
    with pytest.raises(RunsVolumeError):
        parse(text)


def test_main_prints_one_line_or_refuses() -> None:
    out, err = io.StringIO(), io.StringIO()
    assert main(io.StringIO(_config()), out, err) == 0
    assert out.getvalue() == "secscan custom_runs\n"

    out, err = io.StringIO(), io.StringIO()
    assert main(io.StringIO("{}"), out, err) == 1
    assert (out.getvalue(), "不使用預設名稱" in err.getvalue()) == ("", True)

    out, err = io.StringIO(), io.StringIO()
    assert main(io.StringIO(" " * (MAX_CONFIG_BYTES + 1)), out, err) == 1
    assert "太大" in err.getvalue()
