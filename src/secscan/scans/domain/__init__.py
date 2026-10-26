"""scan 的 domain 規則：catalog（引擎與 scan profile）、request（Idempotency-Key、fingerprint、
預算）、lifecycle（run 的轉換與 scan 狀態的彙總）、model（domain model 與事件的 payload）。

不依賴 Web 框架、DB 與 Docker（import-linter 強制）。
"""
