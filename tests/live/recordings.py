"""隔離 lab 的量測輸出只可新增；路徑與檔名由測試程式指定。"""

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def reserve_recording_directory() -> None:
    root = os.environ.get("SECSCAN_RECORD_DIR")
    if root:
        Path(root).mkdir(parents=True, exist_ok=False)


def write_measurement(
    label: str, document: Mapping[str, Any], *, filename: str = "comparison.json"
) -> None:
    root = os.environ.get("SECSCAN_RECORD_DIR")
    if not root:
        return
    encoded = json.dumps(document, ensure_ascii=False, indent=1, allow_nan=False) + "\n"
    directory = Path(root) / label
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / filename).open("x", encoding="utf-8") as stream:
        stream.write(encoded)
