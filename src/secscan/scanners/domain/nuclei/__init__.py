"""Nuclei 引擎的純 domain（T17：凍結 HTTP 模板清單與執行設定）。

這個套件只有純函式與凍結常數：模板清單的選取政策、lock 檔讀寫與定義雜湊。
實際產生 lock 檔（下載／解壓／跑 nuclei -tl）的工具在 src/ 之外的
tools/freeze_nuclei_templates.py；Adapter 與 JSONL parser 在 T18。
依 import-linter 的 forbidden 契約，這裡不得 import 框架、DB 或 Docker。
"""
