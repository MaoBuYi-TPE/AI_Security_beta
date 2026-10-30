# 開始開發

## 1. 先做哪一段

第一個產品化目標不是三個工具同時掃描，而是：

```text
建立核准靶場 target 與 ScopeGrant
  -> POST /api/v1/scans
  -> 同一 transaction 寫入 scan 與 scanner_runs
  -> FakeRunner 以 SKIP LOCKED 認領並完成
  -> GET /api/v1/scans/{id}
  -> 查詢明確標為 fixture 的 observations
```

這個流程穩定之後，依序：

1. **M2**：換成真的 runner（單次容器）與 egress guard。先用 fake 掃描容器驗證隔離、預算與取消。
2. **M3**：接上 ZAP Adapter。
3. **M4**：接上 Nuclei，並做結果整合。
4. **M6**：P0 Gate 通過後，才接 Schemathesis。

這樣第一輪就能發現 API、狀態機、權限與資料模型的問題，不必一次排查三種工具的依賴。

## 2. M0 環境準備（第一次動手前）

- 安裝 uv（`brew install uv` 或官方安裝腳本）。
- 啟動 OrbStack，確認 `docker compose version`。如果不能用，改用已安裝的 `docker-compose`。
- 確認 ZAP、Nuclei、Schemathesis 映像的 digest 與 arm64 支援，記錄到版本表。
- lab 靶機只接 internal network，不要把靶機的 port 發布到對外介面。

## 3. 給 Claude Code 的第一段提示

以下是開發任務提示，不是已完成的實作：

> 請先讀取根目錄 CLAUDE.md 與 docs/TASKS.md，需要時再讀其他 docs。
>
> 這是 1 人、只做後端的 Web/API 多引擎動態安全檢測畢業專題。先檢查實際儲存庫狀態，不得假設 src、Makefile 或測試已存在。
>
> 本次完成 T02：
> - 建立 Python 3.12、FastAPI、Pydantic 2 的最小專案（`src/secscan/`，依功能分模組），包含健康端點與設定載入。
> - 建立品質工具：pytest（含 coverage 門檻）、ruff、mypy、import-linter、pre-commit。
> - 建立 Makefile 的 bootstrap、dev、test、lint、typecheck。
>
> 依賴要真正產生 uv.lock，不要寫假的已解析版本。先寫測試再實作。
>
> 本次不要開發前端、不接 AI、不啟動真實掃描、不連公共靶場、不上傳任何私有檔案到雲端。
>
> 完成後列出修改的檔案、真正執行的命令與結果、尚未執行的項目與原因。只將符合 DoD 的任務標為 done。

## 4. 下一輪提示：工具 spike（T03）

> 依 TASKS T03：
> 1. 在 compose.lab.yaml 建立隔離的 lab（Juice Shop、VAmPI vulnerable/secure），只接 internal network。
> 2. 用一個暫時的 mitmproxy，讓 ZAP、Nuclei、Schemathesis 都經 proxy 掃描 lab。
> 3. 把真實輸出錄到 tests/fixtures/<tool>/，並記錄請求量、耗時、版本與 digest。
> 4. 確認不經 proxy 的直連會失敗。
>
> 不得掃描 lab 以外的任何目標；環境不可用時標為 blocked。

## 5. 再下一輪：資料與 FakeRunner（M1）

> M0 完成後，依 TASKS 的 T04–T09 順序實作 M1：
> 1. 先做 migrations、API key/project 的 object-level 授權、target/ScopeGrant、spec/auth profile。
> 2. 再做 scan、scanner_run 工作佇列（SKIP LOCKED）、idempotency 與 FakeRunner。
>
> 先選一個最小閉環，補齊驗證、故障與權限測試，再往外擴充。
>
> 禁止啟動真實掃描器；測試不得出網。FakeRunner 的輸出要清楚標成 fixture。

## 6. 第一版可視為完成的展示

以 API client 依序展示：

1. 建立已核准的目標。
2. 提交 ZAP+Nuclei 任務，看到各引擎的狀態與 guard 計數的請求量。
3. 查到來源與證據，並展示同一問題的兩筆 observation 如何關聯成一個 finding。
4. 把靶場切換為已修補版本（VAmPI secure 或 fixture 修補版），做新的 scan 並比較。
5. 展示未核准的 target 被拒、越界請求被 guard 擋下（canary 收包數 0），以及取消後停止新流量。

能完成這個閉環、通過安全與故障測試、保存可追溯的實驗資料，比「三個 scanner 都能啟動，但其他都沒做」更適合交付。

## 7. CLI 約定的建立時點

M0 的 `bootstrap`、`dev`、`test`、`lint`、`typecheck` 已在 T02 建立；`lab-up`／`lab-down` 已在 T03 與 `compose.lab.yaml` 一起建立；`env`、`db-up`、`test-db-up`、`db-down`、`migrate` 已在 T04 與 `compose.yaml` 一起建立；本機管理指令 `uv run secscan-admin` 已在 T05 建立（T08 加入 `rotate-secret-keys`、T09 加入 `fake-runner`、T10 加入 `runner` 與 `worker`）；`build`、`images`、`scan-net`、`up`、`down`、`test-live-runner` 已在 T10 建立；`lab-net` 已在 T11 建立。其餘命令仍只是約定的名稱：

| 命令 | 建立階段 | 預期行為 |
|---|---|---|
| make bootstrap | M0 | 安裝已鎖定的開發依賴；第一次要真正產生 lock |
| make dev | M0 | 啟動 API 開發程序，只綁 127.0.0.1 |
| make test | M0（T04 起會先啟動 db-test） | 執行 unit/contract/integration 測試與 coverage 門檻，不做 live scan。測試程序不連網、不碰 Docker；需要 OrbStack 執行 db-test |
| make lint | M0 | ruff lint/format check、import-linter |
| make typecheck | M0 | mypy |
| make lab-net | M2（T11 已建立） | 建立或檢查 lab_net（internal＋isolated＋10.89.7.0/24＋只配發下半段的 ip-range）；egress guard 固定在 .254。舊的 lab_net 沒有 ip-range 時會失敗，刪除後重建（README） |
| make lab-up | M0（T03 已建立） | 以 compose profile 啟動 lab 靶機（只接 internal network，不發布 port）；T11 起先執行 make lab-net |
| make lab-down | M0（T03 已建立） | 停止並移除 lab（先停 spike 再執行） |
| make env | M1（T04 已建立） | 建立或補齊 `.env`（權限 600）中缺少的本機 DB 密碼（隨機值），不覆寫既有的值 |
| make db-up／make db-down | M1（T04 已建立） | 啟動開發用 PostgreSQL（只綁 127.0.0.1:55432）／停止 db 與 db-test（保留開發資料） |
| make test-db-up | M1（T04 已建立） | 啟動整合測試用 PostgreSQL（tmpfs，只綁 127.0.0.1:55433） |
| make migrate | M1（T04 已建立） | 執行 Alembic upgrade head，並印出目前版本；不含破壞性重置 |
| uv run secscan-admin create-admin-key --name … [--output PATH] | M1（T05 已建立） | 建立 platform_admin key（預設 90 天、最多 365 天）；完整的 key 只寫出一次（stdout，或新建、權限 600 的檔案），DB 只存 hash（`API_CONTRACT.md` §13.4） |
| uv run secscan-admin rotate-secret-keys | M1（T08 已建立） | 以 `SECRET_ENCRYPTION_KEYS` 的第一個金鑰重新加密所有的 secret；有任何一份解不開就全部回滾（`API_CONTRACT.md` §16.6） |
| uv run secscan-admin fake-runner [--outcome succeed\|fail] [--hold-seconds N] [--once] | M1（T09 已建立） | 對帳 lease 過期的 fake run，再處理排隊中的 fake run；不連任何位址，結果標為 fixture（`API_CONTRACT.md` §17.5） |
| uv run secscan-admin runner [--once] [--outcome succeed\|fail] [--hold-seconds N] | M2（T10 已建立） | 容器版的 runner：經 socket-proxy 啟動強化的單次容器（T10 只有 fake），收集輸出；SIGTERM 時停止並刪除容器（`API_CONTRACT.md` §18.1） |
| uv run secscan-admin worker [--once] | M2（T10 已建立） | 對帳過期的解析，再處理 collected 的 run（T10 只有 fake，不讀檔；`API_CONTRACT.md` §18.2） |
| make build／make images | M2（T10 已建立） | 建立 secscan 與 egress guard（T11）的映像／以 digest pull 核准的掃描器映像與 socket-proxy（runner 不 pull） |
| make up／make down | M2（T10 已建立） | 啟動／停止 app stack（db、api、runner、worker、socket-proxy；T11 加上 guard），並建立 internal＋isolated 的 scan_net 與 lab_net；API 只綁 127.0.0.1:`API_PORT`（預設 8000） |
| make test-live-runner | M2（T10 已建立） | 需要 `ENABLE_LIVE_LAB_TESTS=1`：在獨立的 compose 專案中以真的 Docker 跑 `tests/live/`，一律拆除；T11 起在 live 自己的 lab 網路上啟動接收端與探針（SEC-02～SEC-10、取消與故障），T12 加上預算與 preflight，T13 加上 runner 中斷後的對帳與撤銷 grant；不啟動 Juice Shop、VAmPI |
| make test-contract | M1–M2 | 對固定 fixture 測 API/Parser 契約 |
| make test-live-lab | M3 起 | 需要 `ENABLE_LIVE_LAB_TESTS=1`、LAB_ONLY、有效 grant，並通過隔離檢查才執行 |
| make record-fixtures | M3 起 | 只在 lab 重新錄製工具輸出 fixture，並產生差異供人工審查 |
| make bench | M5 起 | 透過自己的 API 執行實驗，結果輸出到 benchmarks/results/ |

不得建立一個表面上回 exit 0、實際上沒有驗證的 target，只為了讓命令「看起來都有」。測試不能用時，要明確失敗，或列出有理由的 skip。
