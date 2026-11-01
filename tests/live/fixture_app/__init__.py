"""T30 自製 fixture app：可切換弱點版（insecure）與修補版（secure）的靶機。

只在隔離的 lab_net 上執行，只為量測掃描器的 ground truth 服務，不是開發產品前端
（docs/SECURITY_AND_TESTING.md §5.1）。處理邏輯寫成純函式（`app.handle(mode, request,
state) -> Response`），由薄薄的 `http.server` 外殼呼叫，因此單元測試不必開 socket
（pytest-socket）。只用標準函式庫，才能掛在既有的 guard 映像的 python 內執行。

案例的事實來源是 `cases.py`（case_id、surface、類別、兩個模式的行為、OWASP、holdout 等），
與案例表（`SECURITY_AND_TESTING.md` §4.4/§5.1）和 OpenAPI 規格三者對齊。
"""
