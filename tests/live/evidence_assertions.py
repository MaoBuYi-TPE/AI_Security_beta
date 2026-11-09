"""live 測試的原始證據（T23a；docs/DECISIONS.md §30.3）：runs volume 只剩加密檔，原始輸出以
export-evidence 讀取。

- run 結束、容器確認刪除之後，runner 的 keeper 約 10 到 20 秒加密這個 run 的目錄；讀原始輸出之前
  先等它只剩 `sealed/`（不等的話會和 keeper 競速，有時讀到明文、有時讀不到）。
- export-evidence 在 runner 容器內執行（只有它持有原始證據的金鑰）：先完整驗證、寫入 audit，才把
  明文寫到 stdout；不寫任何檔案。
- 直接讀 volume（唯讀掛載的輔助容器）只用來確認密文：只剩 `sealed/`，位元組中沒有明文的 canary
  與已知的值。
"""

import hashlib
import json
import subprocess
import uuid
from collections.abc import Iterable
from typing import Any

from tests.live.support import BUSYBOX, Api, container, wait_for

RUNS_VOLUME = "secscan_live_runs"
SEAL_TIMEOUT = 180.0
SEALED_DIR = "sealed"


def _busybox(script: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - 固定的 docker 指令與測試自己組的參數
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            # run 的目錄是 0700、屬於 10001：沒有 capability 的 root 讀不了。
            "--user",
            "10001:10001",
            "-v",
            f"{RUNS_VOLUME}:/runs:ro",
            "--entrypoint",
            "sh",
            BUSYBOX,
            "-c",
            script,
        ],
        capture_output=True,
        check=False,
        timeout=120,
    )


def entries(run_id: str) -> list[str] | None:
    """run 目錄最上層的條目；目錄不存在時是 None。"""
    run = uuid.UUID(run_id)
    result = _busybox(f'[ -d "/runs/{run}" ] && ls -A "/runs/{run}"')
    if result.returncode != 0:
        return None
    return sorted(result.stdout.decode().split())


def wait_sealed(run_id: str, *, timeout: float = SEAL_TIMEOUT) -> bool:
    """等到 run 目錄只剩 sealed/；目錄不存在（從來沒有輸出）時回 False。"""

    def check() -> str | None:
        found = entries(run_id)
        if found is None:
            return "missing"
        return "sealed" if found == [SEALED_DIR] else None

    return wait_for(check, timeout=timeout, interval=2) == "sealed"


def export(run_id: str, path: str) -> bytes | None:
    """runner 容器內的 export-evidence；這個 run 沒有這個檔案時回 None。"""
    result = subprocess.run(  # noqa: S603 - 固定的 docker 指令與測試自己組的參數
        [  # noqa: S607
            "docker",
            "exec",
            container("runner"),
            "secscan-admin",
            "export-evidence",
            "--run",
            str(uuid.UUID(run_id)),
            "--path",
            path,
        ],
        capture_output=True,
        check=False,
        timeout=120,
    )
    if result.returncode != 0:
        message = result.stderr.decode(errors="replace")
        if "找不到" in message or "不存在" in message:
            return None
        raise AssertionError(f"export-evidence 失敗：{message.strip()}")
    return result.stdout


def listing(run_id: str) -> list[dict[str, Any]]:
    """加密檔的原本路徑、大小與 sha256（export-evidence 沒有 --path）。"""
    output = subprocess.run(  # noqa: S603 - 固定的 docker 指令與測試自己組的參數
        [  # noqa: S607
            "docker",
            "exec",
            container("runner"),
            "secscan-admin",
            "export-evidence",
            "--run",
            str(uuid.UUID(run_id)),
        ],
        capture_output=True,
        check=True,
        timeout=120,
    ).stdout.decode()
    return [json.loads(line) for line in output.splitlines() if line]


def run_file(run_id: str, path: str) -> bytes | None:
    """等加密完成，再以 export-evidence 讀出 run 目錄中的一個原本的檔案（例如 out/zap.log）。"""
    if not wait_sealed(run_id):
        return None
    return export(run_id, path)


def sealed_bytes(run_id: str) -> bytes:
    """run 目錄中所有檔案的位元組與名稱（直接讀 volume：只應該看到密文）。"""
    run = uuid.UUID(run_id)
    script = f'cd "/runs/{run}" && find . -print && find . -type f -exec cat {{}} +'
    result = _busybox(script)
    assert result.returncode == 0, "讀不到 run 目錄"
    return result.stdout


def assert_sealed(run_id: str, forbidden: Iterable[bytes]) -> None:
    """run 目錄只剩 sealed/，而且檔名與內容都沒有任何一個 forbidden 的值。"""
    assert wait_sealed(run_id), f"run {run_id} 沒有原始證據的目錄"
    content = sealed_bytes(run_id)
    for value in forbidden:
        assert value not in content, "加密之後的 run 目錄仍有明文的值"


def assert_exports_match(run_id: str, artifacts: Iterable[dict[str, Any]]) -> None:
    """artifact 的 sha256（收集時的值）等於解密匯出的明文的 sha256。"""
    for artifact in artifacts:
        prefix = "out/" if artifact["kind"] == "output" else "in/"
        content = export(run_id, f"{prefix}{artifact['path']}")
        assert content is not None, artifact["path"]
        assert hashlib.sha256(content).hexdigest() == artifact["sha256"], artifact["path"]


def assert_api_sealed(api: Api, scan_id: str, *, timeout: float = SEAL_TIMEOUT) -> None:
    """API 的 engines[].evidence：有容器的 run 都是 sealed（沒有目錄的是 none）。"""

    def check() -> bool | None:
        engines = api.data("GET", f"/scans/{scan_id}")["engines"]
        statuses = {engine["evidence"]["status"] for engine in engines}
        return statuses <= {"sealed", "none"} or None

    wait_for(check, timeout=timeout, interval=3)


def run_ids(api: Api, scan_id: str) -> set[str]:
    """scan 的事件中出現過的 run（有容器的 run 才會有目錄）。"""
    events = api.data("GET", f"/scans/{scan_id}/events")
    return {str(event["scanner_run_id"]) for event in events if event["scanner_run_id"]}


def assert_scan_sealed(api: Api, scan_id: str, forbidden: Iterable[bytes]) -> None:
    """API 顯示 sealed（或 none），每個有目錄的 run 只剩密文、沒有 forbidden 的值。"""
    assert_api_sealed(api, scan_id)
    values = list(forbidden)
    for run_id in run_ids(api, scan_id):
        if entries(run_id) is not None:
            assert_sealed(run_id, values)
