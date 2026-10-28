"""egress guard（docs/DECISIONS.md §15）：在 mitmproxy 中逐請求檢查掃描流量的 addon，
以及與 runner 共用的 policy、status 格式。

guard 在官方 mitmproxy 映像（Python 3.14）中執行：這個套件只能用標準函式庫與純 domain 模組，
不 import mitmproxy（flow 以 Protocol 描述），所以在 3.12 的測試環境中可以完整測試。
"""
