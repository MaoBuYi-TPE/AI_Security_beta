"""規格的 domain 規則：documents（JSON 與 YAML 的解析）、references（參照）、openapi（正規化與
inventory）、model（domain model）。

不做任何 I/O；import-linter 禁止這個套件依賴 Web 框架、DB 與 Docker。YAML 只用 PyYAML 純 Python
的事件 API。
"""
