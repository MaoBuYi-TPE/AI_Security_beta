"""runner：認領 scanner_run 並執行（docs/DECISIONS.md §13.7）。

T09 只有 fake 引擎的 FakeRunner；M2 的真 runner（經 docker-socket-proxy 啟動單次容器）也放在這裡，
它是唯一可以 import Docker SDK 的模組（CLAUDE.md §5）。
"""
