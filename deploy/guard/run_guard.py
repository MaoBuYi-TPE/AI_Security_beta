"""egress guard 的進入點（docs/DECISIONS.md §15.1）：在官方 mitmproxy 映像中以 `python3 -I` 執行。

這裡只接上 mitmproxy（建立 DumpMaster、回應的 factory）；啟動的檢查與 addon 都在 secscan.guard，
在 3.12 的測試環境中測試。`-I` 不把這個目錄加進 sys.path，所以自己加（只加這一個目錄）。
mitmproxy 只在真的啟動 guard 時才載入：healthcheck（`--check`）每 5 秒執行一次，不必載入它。
  run_guard.py           啟動 guard
  run_guard.py --check   healthcheck：status 是新的、正在檢查時回 0
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secscan.guard.bootstrap import check_status, serve
from secscan.guard.config import GuardConfigError, config_from_env
from secscan.guard.events import GuardLog, guard_logger

ROUTE_TABLE = Path("/proc/net/route")
EXIT_CONFIG = 2


def main(argv: list[str]) -> int:
    try:
        config = config_from_env(os.environ)
    except GuardConfigError as exc:
        sys.stderr.write(f"guard 設定錯誤：{exc}\n")
        return EXIT_CONFIG
    if argv[1:] == ["--check"]:
        return check_status(config)
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster

    def master(core: dict[str, object]) -> DumpMaster:
        # 必須在 event loop 內建立；with_dumper=False：不把請求內容印到 stdout。
        return DumpMaster(options.Options(**core), with_termlog=True, with_dumper=False)

    return asyncio.run(
        serve(
            config,
            create_master=master,
            make_response=http.Response.make,
            routes=lambda: ROUTE_TABLE.read_text(encoding="ascii"),
            log=GuardLog(guard_logger()),
        )
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
