# 開發任務清單

所有項目初始都是未完成。標記完成時，必須附上實作檔案、實際測試結果與尚未涵蓋的限制；不能因為文件描述過就勾選。

- 時程：1 人開發，2026/10/16 – 2027/06/30（約 37 週）。
- 日期是規劃值，可以依學校行事曆調整；調整後要同步更新 `PROJECT_PLAN.md` §10。
- 任務編號沿用原稿（T01–T29），整合版新增的任務從 T30 開始編號。

## M0｜10/16 – 11/08：範圍、骨架與可行性

- [ ] T01 凍結題目、P0/P1、研究問題與排除項目。
  - 產出：需求摘要與待驗證假設；訪談 2–3 位開發者為選做。
  - DoD：能清楚說明相對於手動使用工具，本系統增加了什麼；沒有任何自訂前端任務。
- [ ] T02 建立 Python 專案與品質命令。
  - 產出：
    - pyproject.toml、uv.lock、.env.example
    - Makefile：bootstrap、dev、test、lint、typecheck、lab-up
    - 最小的 `src/secscan/main.py` 與健康端點
    - 品質工具：pytest（含 coverage 門檻）、ruff、mypy、import-linter、pre-commit
  - DoD：在乾淨環境能啟動健康端點，並實際跑過 test、lint、typecheck；README 中的指令都有效。
- [ ] T03 確認掃描器映像、模板與實驗網路。
  - 前置：安裝 uv、啟動 OrbStack，確認 `docker compose` 可用（不行就改用 `docker-compose`）。
  - 產出：
    - 工具相容性表：名稱、版本、digest、arm64 支援、授權條款、必要的可寫路徑、唯讀 rootfs 相容性、proxy/auth/output 相容性。
    - lab compose：Juice Shop、VAmPI vulnerable/secure，只接 internal network。
  - 做法：用一個暫時的 mitmproxy 讓三個工具都經 proxy 掃描 lab。把真實輸出錄到 `tests/fixtures/<tool>/`，並量測各工具的請求量與耗時，作為之後調整預算的依據。
  - 需要逐項確認：
    - ZAP 的 upstream proxy 設定鍵與 report 格式
    - Nuclei `-sf` 檔案格式，以及經 proxy 時的 DNS 行為
    - Schemathesis `--proxy` 的行為與 NDJSON 結構
    - Docker volume subpath
    - 各工具的秘密注入方式
  - DoD：取得 ZAP、Nuclei、Schemathesis 的真實輸出樣本並保存 hash；不經 proxy 的直連必須失敗。
  - 限制：只掃自建的 lab，不能提前開放任意 URL 的平台功能。環境不可用時標為 blocked，不能改掃公共網站，也不能把 Mock 當成 live 成果。

## M1｜11/09 – 12/13：API 與資料基礎

前置：T01–T02。

- [ ] T04 建立 DB Model、Alembic、Repository 與設定。
  - DoD：全新 DB 可完成 migration；FK、unique、index 都有測試；測試資料與正式配置分離。
- [ ] T05 建立 API key、project 與 object-level 權限。
  - DoD：
    - key 高熵且只存 hash，支援過期與撤銷。
    - viewer 不可寫入；A 專案不能讀 B 專案的資料。
    - 初始管理 key 由本機 CLI 建立，且只顯示一次。
- [ ] T06 建立 target、ScopeGrant 與審批流程。
  - DoD：
    - pending/approved/revoked/expired 的轉換正確。
    - 沒有核准就不能開始掃描。
    - `LAB_ONLY` 時，grant 的 IP 必須在 `LAB_CIDR` 內。
    - 留下 audit 紀錄。
- [ ] T07 建立 OpenAPI 上傳與受限的 operation inventory。
  - DoD：驗證大小、格式、$ref、servers，包含惡意與跨 origin 的測試；不從外部抓取任何東西。
- [ ] T08 建立 auth profile 與 secret 生命週期。
  - DoD：secret 以 MultiFernet 加密、只寫不讀、支援換版、不寫入 log；preflight 定義有驗證。
- [ ] T09 建立 scan、scanner_run 工作佇列、idempotency、狀態機與 FakeRunner。
  - DoD：
    - API 回 202；scan 與 scanner_runs 在同一個 transaction 建立。
    - SKIP LOCKED 認領與 lease 有測試，包含兩個 consumer 同時認領的情境。
    - 相同 Idempotency-Key 與相同內容不會重複建立；相同 key 不同內容回 409。
    - FakeRunner 能跑完、失敗、被取消。
    - scan_events 可以輪詢。

里程碑證據：不用真工具，也能從 API 建立受控任務、查詢狀態，並得到假 runner 明確標記的測試結果；所有權限測試都通過。

## M2｜12/14 – 01/24：Runner 與強制安全邊界（期末考期間，排輕一點）

前置：T03、T06、T09。

- [ ] T10 建立 runner、docker-socket-proxy、ExecutionPlan 驗證與容器限制。
  - DoD：
    - api、worker、掃描容器都沒有 Docker socket，也不是 privileged。
    - socket-proxy 只開放容器需要的區段。
    - 未核准的映像、path、args、網路都會被拒絕（SEC-12、SEC-21）。
- [ ] T11 完成 internal networks、egress guard，以及 DNS/IP/path/method/redirect 檢查。
  - DoD：
    - SEC-02 到 SEC-10 中適用的項目都通過。
    - 以 canary 的收包紀錄證明沒有越界。
    - guard 不可用時 fail closed；無法約束的 profile 一律關閉。
- [ ] T12 完成共享預算、telemetry 與認證 preflight 路徑。
  - DoD：
    - 所有掃描流量共用同一個上限，preflight 也計入。
    - Token 只送往核准的 origin。
    - 從 telemetry 可以算出實際請求數。
- [ ] T13 實作心跳/lease、取消、timeout、孤兒容器清理與 reconciler。
  - DoD：
    - 重複認領時不會重複啟動容器。
    - 中斷後不會永遠停在 running。
    - 取消時先封鎖 guard，再回收容器。

放行規則：T10–T13 全部通過前，不對操作者開放真實的 active scan API。只支援完全封閉的 HTTP 靶場；不跳過 HTTPS guard 測試來擴大範圍。

上學期成果展示的內容：授權流程、FakeRunner 任務、guard 擋下越界請求、取消，以及 M0 的工具 spike 結果。

## M3｜01/25 – 02/28：ZAP Adapter（寒假與農曆年）

前置：M2。

- [ ] T14 實作 ZAP capability probe 與 Web/API ExecutionPlan。
  - DoD：
    - 使用 `-silent` 與伺服器產生的 AF plan。
    - auth 以 `ZAP_AUTH_HEADER*` 環境變數注入；沒有 auth 的 profile 明確標為 anonymous。
    - API spec 的 origin 綁定到核准目標；profile 與 method 不相容時拒絕。
- [ ] T15 實作版本化的 ZAP JSON Parser 與觀察輸入契約。
  - DoD：clean、findings、malformed、timeout、exit 各種 fixture 都有測試；非零退出不一律當成 crash。
- [ ] T16 執行 ZAP 真實 e2e 與失敗情境。
  - DoD：
    - Juice Shop 與 VAmPI 的已知正例/負例、Token 失效、工具超時、取消，都有真實證據。
    - 保留版本與 guard 的流量資訊。
    - 依量測結果調整 lab profile 的預算，並留下紀錄。
- [ ] T30 建立自製 fixture app 與 ground truth 初稿。
  - DoD：
    - fixture app 可以切換弱點版與修補版，只放在 lab_net。
    - 約 12 個資安案例與 6 個 contract/robustness 案例，都寫好預期行為與確認方式。

里程碑證據：第一次走通 API → 真實工具 → 解析 → DB → 查詢的完整閉環，而不只是啟動容器。

## M4｜03/01 – 04/04：Nuclei 與結果整合

前置：M3。去重的單元測試可以提早進行。

- [ ] T17 凍結 Nuclei 的 HTTP 模板清單與執行設定。
  - DoD：
    - 依 tag/類型產生 ID 清單，記錄 release、hash 與 ID。
    - 以類別為單位審查，並抽查高風險模板。
    - 使用 `-ni -duc -pt http`；禁用 code/headless/dos 模板、OAST 與雲端上傳。
- [ ] T18 實作 Nuclei Adapter、JSONL Parser 與真實 e2e。
  - DoD：空檔、壞行、重複、非零退出、取消、timeout 都有明確定義；零告警與失敗可以區分。
- [ ] T19 實作 Observation/Finding、rule_groups、mapping 版本與保守的 fingerprint。
  - DoD：
    - 正確保留來源、kind、severity、confidence。
    - OWASP Top 10:2025 與 API 2023 的對應都記錄 mapping_source。
    - 不可信的映射不跨工具合併。
- [ ] T20 建立去重的反例測試與來源追溯查詢。
  - DoD：
    - 這些情況都不會誤合併：同 CWE 但參數不同、同 route 但身分或物件不同、不同的弱點。
    - 所有證據都能追溯到來源。

里程碑證據：兩個引擎能在同一個 API 流程中取得真實結果，並展示共享預算、部分失敗，以及同一問題有多個來源。

## M5｜04/05 – 04/25：報告、複掃與 P0 驗收

前置：M4。

- [ ] T21 完成人工 triage、audit 與 JSON/Markdown 報告。
  - DoD：未確認的告警有清楚標記；artifact 的權限、遮罩、下載都安全；不執行 HTML，也不載入遠端資源。
- [ ] T22 實作比較快照、coverage 判斷與差異分類。
  - DoD：scope、auth、工具或 spec 不一致時顯示理由；漏掃不會顯示成已修補；舊的 scan 保留。
- [ ] T23 完成所有 P0 的安全、故障、整合測試，並在乾淨環境重建。
  - DoD：
    - 安全負向測試全部通過。
    - 整體 coverage ≥ 80%，核心模組 branch coverage ≥ 90%。
    - 原始證據以加密方式保存。
    - 文件與實際的 API 一致。
- [ ] T31 建立 benchmark harness。
  - DoD：透過自己的 API 執行各實驗組別，保存 manifest 與 guard 計數；`evaluate.py` 是純函式，並且有測試。

放行規則：M5 通過（Gate A–D）後，才能啟動 M6 的第三引擎；沒通過時，M6 改為補強期。

## M6｜04/26 – 05/23：Schemathesis 與 SARIF（或補強）

前置：M5。

- [ ] T24 查核 Schemathesis 鎖定版本的 JSON/NDJSON 輸出，以及 phase、method、proxy、auth、seed 的行為。
  - DoD：使用受控的 spec 與 seed；確實停止發送未授權的 method；能取得可以對應到 operation 的觀察。
- [ ] T25 實作第三個 Adapter，並把 contract/robustness 分開統計。
  - DoD：HTTP 500 與 schema failure 不會直接變成 confirmed security；真實輸出的解析與故障測試都有。
- [ ] T26 視進度細化 API 覆蓋率，並提供一份 CI 呼叫範例。
  - DoD：以 guard telemetry 證明真正送出過哪些核准的 operation，缺資料時回 N/A；不用告警數量推估覆蓋率。
- [ ] T32 SARIF 匯出與 dogfooding。
  - DoD：SARIF 通過 schema 驗證；在 lab 中用 Schemathesis 掃描平台自己的 API，並記錄結果。

降階：刪除 T24、T25、T32，保留兩個引擎，不影響核心研究問題；把時間用在 T23 與 T27–T29。

## M7｜05/24 – 06/30：實驗、分析與展示

- [ ] T27 凍結 ground truth、holdout、工具版本、預算與資料快照。
  - DoD：指導教授或同學抽樣複核至少 20% 的案例；自訂模板的實驗另外列出；相同總預算的規則清楚。
- [ ] T28 執行重複實驗，保存真實結果並計算指標。
  - DoD：
    - 每組重複 5 次（至少 3 次）。
    - security 與 contract 分開統計。
    - 報告 TP/FP/FN、去重 precision/recall、時間與請求數，以及失敗情形。
- [ ] T29 完成報告、操作/部署文件與口試 demo。
  - DoD：在乾淨環境重建一輪；能說明哪些範圍沒有覆蓋、哪些地方失敗；沒有把示意數字當成成績。

## 各功能共同 Definition of Done

- 功能要同時包含：實作、輸入驗證、權限、錯誤語意、測試、文件，以及必要的 migration。
- 採用 TDD：先有會失敗的測試，再實作。
- 掃描相關的功能，另外需要真實的 live 證據、版本紀錄與清理測試。
- 「完成」指的是可以驗證的行為，不是 class、route 或檔案存在。

## 每次交付紀錄格式

```text
任務：Txx
狀態：not_started / in_progress / blocked / done
修改檔案：
實際執行測試與結果：
未執行測試與原因：
安全/相容性限制：
下一個依賴已滿足的任務：
```

不要先填「全部通過」。如果工具、網路或環境不可用，就標為 blocked，並保存之後需要補驗證的具體內容。
