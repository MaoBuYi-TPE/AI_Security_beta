"""runs volume 中兩個區域的名稱（docs/DECISIONS.md §30.13）。

純常數，admission 與 runner/layout.py 共用：

- active：一般的 run 目錄；worker 只以 subpath 唯讀掛載這裡，掃描容器只掛載 active/<run>/in、out。
- held：隔離的目錄；只有 runner 掛載整個 volume 的根目錄，worker 與掃描容器都看不到。
"""

ACTIVE_AREA = "active"
HELD_AREA = "held"
