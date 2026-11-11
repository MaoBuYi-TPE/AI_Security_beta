"""從 compose 解析之後的設定取出 project name 與 runs volume 的名稱（docs/DECISIONS.md §30.13）。

make runs-layout-migrate 在主機上執行：

    docker compose -f compose.yaml --profile app config runs-init --format json \\
        | uv run python -m secscan.cli.runs_volume

- 和 make up 使用同一組 compose 設定（APP_COMPOSE），所以取出的就是正式部署實際使用的 volume；
  不退回任何預設名稱。
- 純函式：只讀 stdin，不 import Docker、不連網、不讀環境變數。輸出一行「<project> <volume>」。
- JSON 無法解析、缺少欄位或名稱不合法時 exit 1（說明寫到 stderr），呼叫端拒絕搬移。
"""

import json
import re
import sys
from typing import TextIO

# compose 的 project name 與 Docker 的 volume 名稱。
_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_VOLUME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}")
MAX_CONFIG_BYTES = 1024 * 1024


class RunsVolumeError(ValueError):
    """compose 的設定不是預期的格式。"""


def parse(text: str) -> tuple[str, str]:
    """compose config 的 JSON → (project name, runs volume 的名稱)。"""
    try:
        config = json.loads(text)
    except json.JSONDecodeError:
        raise RunsVolumeError("compose 的設定不是 JSON") from None
    if not isinstance(config, dict):
        raise RunsVolumeError("compose 的設定不是物件")
    project = config.get("name")
    volumes = config.get("volumes")
    runs = volumes.get("runs") if isinstance(volumes, dict) else None
    volume = runs.get("name") if isinstance(runs, dict) else None
    if not isinstance(project, str) or not _PROJECT.fullmatch(project):
        raise RunsVolumeError("compose 的設定沒有合法的 project name")
    if not isinstance(volume, str) or not _VOLUME.fullmatch(volume):
        raise RunsVolumeError("compose 的設定沒有合法的 volumes.runs.name")
    return project, volume


def main(
    stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr
) -> int:
    text = stdin.read(MAX_CONFIG_BYTES + 1)
    if len(text) > MAX_CONFIG_BYTES:
        stderr.write("compose 的設定太大：拒絕搬移。\n")
        return 1
    try:
        project, volume = parse(text)
    except RunsVolumeError as exc:
        stderr.write(f"{exc}：拒絕搬移（不使用預設名稱）。\n")
        return 1
    stdout.write(f"{project} {volume}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
