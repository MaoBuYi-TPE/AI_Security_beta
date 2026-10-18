"""程序入口必須載入完整的 ORM model 登記（否則跨功能的 FK 解析不到資料表）。

在新的 Python 程序裡檢查：同一個測試程序裡其他測試早已 import 過所有 model，看不出問題。
"""

import subprocess
import sys

import pytest

from secscan.migrations.metadata import MODELS

_PROBE = (
    "import {module}\n"
    "from secscan.core.db import Base\n"
    "[fk.column for table in Base.metadata.sorted_tables for fk in table.foreign_keys]\n"
    "print(','.join(sorted(Base.metadata.tables)))\n"
)


@pytest.mark.parametrize("module", ["secscan.main", "secscan.cli"])
def test_entrypoint_registers_every_orm_model(module: str) -> None:
    # 執行的是本測試寫死的程式碼與目前的直譯器，沒有外部輸入。
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", _PROBE.format(module=module)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().split(",") == sorted(model.__tablename__ for model in MODELS)
