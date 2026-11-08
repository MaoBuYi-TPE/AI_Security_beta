"""T31 的 benchmark harness（docs/DECISIONS.md §29）。

黑箱：只讀平台 API 回的 JSON 與本機的實驗檔案，不 import secscan（以 AST 測試強制）。
純函式的部分（規格、排程、正規化、評估、統計）不讀寫網路；Live 的流程在 tests/live/。
不進 wheel 與映像（uv_build 只打包 src/secscan，.dockerignore 是 allowlist）。
"""
