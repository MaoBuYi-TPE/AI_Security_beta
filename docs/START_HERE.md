# 開始開發

## 1. 先做哪一段

第一個產品化目標不是三工具同時掃描，而是：

```text
建立核准靶場 target
  -> POST /api/v1/scans
  -> DB + outbox
  -> FakeRunner
  -> GET /api/v1/scans/{id}
  -> 查詢明確標為 fixture 的 observations
```

此流程穩定後，先把 FakeRunner 的執行端替換為受控 ZAP Adapter，再接 Nuclei。第一輪即可發現 API、狀態機、權限與資料模型問題，不必一次排查三種工具的依賴。

## 2. 給 Claude Code 的第一段提示

以下是開發任務提示，不是已完成實作：

> 請先讀取根目錄 CLAUDE.md，以及 docs/PROJECT_PLAN.md、docs/ARCHITECTURE.md、docs/API_CONTRACT.md、docs/SECURITY_AND_TESTING.md、docs/TASKS.md。
>
> 這是一個只做後端的 Web/API 多引擎動態安全檢測畢業專題。先檢查實際儲存庫狀態，不得假設 app、Makefile 或測試已存在。
>
> 本次先完成 T01–T02 的可落地部分：整理範圍/待驗證項目，建立 Python 3.12、FastAPI、Pydantic 2 的最小專案，建立健康端點、設定載入、測試、lint/typecheck 命令與開發文件。依賴需生成實際 lockfile，不要寫假的已解析版本。保留日後 SQLAlchemy、Alembic、Celery/Redis 的模組界線，但不要一次生成全部功能。
>
> 本次不要開發前端、不接 AI、不啟動真實 active scan、不連公共靶場、不上傳任何私有檔案至雲端。工具 smoke test 需要已核准的自有隔離靶場；沒有環境就將 T03 記為待驗證，不可用 Mock 代替真實成功。
>
> 完成後列出修改檔案、真正執行的命令/測試結果、尚未執行項目及原因。只將符合驗收條件的任務標為 done。

## 3. 下一輪提示：資料與 FakeRunner

> 在 M0 骨架與品質命令完成後，依 TASKS 的 T04–T09 順序實作 M1。先做 migrations、API key/project object 授權、target/scope、spec/auth profile，再做 scan/outbox/idempotency 與 FakeRunner。先選一個最小閉環，補齊驗證、故障與權限測試再擴充。禁止啟動真實 scanner；測試不得出網。FakeRunner 的輸出清楚標成 fixture。

## 4. 第一版可視為完成的展示

以 API client 建立已核准目標、提交 ZAP+Nuclei 任務、看到逐引擎狀態、查到來源/證據、展示同問題兩筆 observation 如何關聯成 finding，再對切換為已修補版本的靶場做新 scan。最後展示未核准 target 被拒與取消後停止新流量。

能完成這個閉環、通過安全/故障測試、保存可追溯實驗資料，比「三個 scanner 都可以啟動但其他都沒做」更適合交付。

## 5. CLI 約定的建立時點

本包尚無 Makefile，以下只約定未來命令名稱：

| 命令 | 建立階段 | 預期行為 |
|---|---|---|
| make bootstrap | M0 | 安裝已鎖定開發依賴；第一次先真正生成 lock |
| make dev | M0 | 啟動 API 開發程序，綁本機/管理環境，不暴露公網 |
| make test | M0 | 執行離線 unit/integration（依環境配置），不能 live scan |
| make lint | M0 | 執行 lint/format check |
| make typecheck | M0 | 型別檢查 |
| make migrate | M1 | 執行 Alembic upgrade；不含破壞性重置 |
| make test-contract | M1–M2 | 對固定 fixture 測 API/Parser 契約 |
| make test-live-lab | M3–M5 | 需明確環境開關、LAB_ONLY/grant/隔離檢查後才執行 |

不得建立一個表面回 exit 0、實際沒有驗證的 target 來讓命令「看起來都有」。測試不可用時明確失敗或列出有理由的 skip。
