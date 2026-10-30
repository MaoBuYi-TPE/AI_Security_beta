# 設計決策紀錄：兩份規劃的比較與取捨

- 日期：2026-10-16
- 狀態：已採納（規劃階段，尚未實作或量測）
- 比較對象：
  - **ChatGPT 版**：本儲存庫第一個 commit 的原稿（`git show 86d7b2b`）。
  - **Claude 版**：在 Claude Code 規劃模式中產出的計畫（1 人、一學年、三工具）。
- 用途：說明目前文件中的重要設計從哪裡來、為什麼這樣選。可直接作為專題報告「設計取捨」章節的素材。
- 規則：要推翻本文件的任何決定，先在這裡新增一節寫下理由，再修改其他文件。

## 1. 整體評價

### 1.1 ChatGPT 版

強項：

- **安全邊界在網路層**：掃描器只能經 egress guard 出站，並以「禁止目標實際收包數為 0」作為證據。
- **可靠性周全**：DB lease、container label 對帳、開始發流量後中斷不自動重跑、取消時先斷出站再停容器。
- **結果處理保守且誠實**：Observation 與 Finding 分離、不輕易跨工具合併、「沒再看到」不等於「已修好」、contract/robustness 不算進資安數量。
- **實驗方法嚴謹**：相同總預算、修補後的負例、holdout、去重 precision/recall。
- **開發規則重視誠實**：不得杜撰結果、Mock 不等於完成、交付時列出實際執行的測試。

弱點：

- 假設 3 人、16 週，與實際條件（1 人、約 37 週）不符。
- 部署假設兩台 VM，1 人用一台 Mac 開發不實際。
- 起始流量預算（2 req/s、5,000 次、25 分鐘）可能讓 ZAP 主動掃描被截斷，使檢出率失真。
- 「人工審查每個 Nuclei 模板」與「兩人交叉審查」，1 人無法執行。
- 依類型分層（api/domain/services/db），與本專案「依功能組織」的規範衝突；API 沒有統一 envelope。
- 沒有具體的工具版本與旗標，也沒有使用 OWASP Top 10:2025。

### 1.2 Claude 版

強項：

- 依實際條件規劃（1 人、一學年），並預留期末考、寒假與農曆年的緩衝。
- 工具版本、映像、旗標經過查核，也找出本機環境問題（OrbStack 未啟動、`docker compose` 不可用）。
- 結果對應 OWASP Top 10:2025 與 API Security Top 10:2023，並標記對應來源。
- 符合本專案的開發規範：依功能分模組、統一 envelope、TDD、整體 coverage ≥ 80%。
- 有刑法第 36 章的法律提醒。

弱點：

- 安全檢查只在應用層，擋不住掃描器自行解析 DNS 或跟隨 redirect 的情況。
- 去重過於積極：依類別就合併，而且多個工具一致就提高信心度。
- 把 HTTP 500 直接當成資安問題。
- 複掃時把「沒看到」當成「已修好」。
- 建立掃描後才派送，沒有交易一致性保證；lease 遺失會自動重排，可能重複打靶機。
- 平台用帳密 + JWT + refresh，對純後端來說做得太多。

## 2. 逐項比較與選擇

| # | 面向 | ChatGPT 版 | Claude 版 | 採用 | 理由 |
|---|---|---|---|---|---|
| 1 | 團隊與時程 | 3 人、16 週（尚未確認） | 1 人、2026/10 – 2027/06（已確認） | Claude | 依實際條件規劃 |
| 2 | 工具範圍 | P0 只做 ZAP + Nuclei；Schemathesis 為條件式 P1 | 三個工具都在 MVP | 融合 | 三個都做，但沿用 Gate：兩引擎端到端驗收通過後，才開始接 Schemathesis |
| 3 | 掃描執行方式 | Runner 每次啟動一個獨立容器 | 常駐 ZAP daemon，其他工具用 subprocess | ChatGPT＋調整 | 三個工具的 adapter 形狀一致、每次都是乾淨環境、取消就是停容器；掃描器在網路上碰不到 DB。Docker 權限用 socket-proxy 限縮 |
| 4 | 出站控制 | 強制 egress guard（mitmproxy addon）加網路拓撲 | 應用層 SSRF 檢查；Smokescreen 列延伸 | ChatGPT | 掃描器自己解析 DNS、自己跟 redirect，只在應用層檢查擋不住。guard 另外提供共享預算、操作覆蓋率與實際請求數 |
| 5 | 目標授權 | ScopeGrant（origin、IP、path、method、預算、期限）加管理員核准 | DNS TXT 或 well-known 檔案驗證 | ChatGPT＋上限 | lab 靶機沒有公開網域，用不到 DNS 驗證。保留全域上限：`LAB_ONLY` 時 grant 的 IP 必須落在 `LAB_CIDR` 內 |
| 6 | 平台認證 | 平台 API key（只存雜湊）加 project 角色 | 帳密 + JWT + refresh | ChatGPT | 純後端、給 API client 與 CI 使用，API key 就夠，攻擊面也小（YAGNI）。做前端時再加使用者登入 |
| 7 | 任務派送 | Celery + Redis + outbox + DB lease | Celery + Redis，commit 後才派送 | **兩者都不採：PostgreSQL 工作佇列** | 見本文件 §3 |
| 8 | 失敗重試 | 開始發流量後中斷就標 interrupted，不自動重跑 | lease 遺失就自動重排 | ChatGPT | 避免重複打靶機；只有 parser 可安全重試 |
| 9 | 引擎順序 | 同一 target 依序執行、共享預算 | 三個工具並行 | ChatGPT | 比較公平、靶機負載可控；16 GB RAM 一次只跑一個 ZAP |
| 10 | 結果模型 | 不可變的 Observation，加上跨掃描、有生命週期的 Finding | 每次掃描各自的 findings 加 occurrences | ChatGPT | 複掃比較與 triage 延續比較自然 |
| 11 | 跨工具去重 | 保守：語意規則群組 + method + route + 參數 + auth role 都相同才合併；多工具命中也不升級 | 依類別合併；2 個以上工具同意就把 confidence 升一級 | ChatGPT | 誤合併會把漏洞藏起來。「多工具一致是否較準」改成實驗要回答的問題，不當預設規則 |
| 12 | Schemathesis 結果分類 | security、contract、robustness、informational 分開計算 | HTTP 500 算 medium 等級的 security | ChatGPT | 500 本身是健壯性問題，有安全影響的證據才算資安 |
| 13 | 複掃比較 | 先判斷可比性，再分成 new / persistent / not_observed / inconclusive / not_comparable | new / fixed / unchanged | ChatGPT | 「沒再看到」不等於「已修好」 |
| 14 | 標準對應 | 只引用 API Top 10:2023 | Top 10:2025 + API 2023，並標記 official 或 curated | Claude＋ChatGPT 原則 | 報告需要 2025 版；同時遵守「不捏造 CWE 或 CVSS」 |
| 15 | 報告格式 | JSON + Markdown | JSON + SARIF + HTML | 融合 | P0 做 JSON + Markdown；P1 加 SARIF（展示 CI 整合）；HTML/PDF 列延伸 |
| 16 | API 回應格式 | 直接回資源本體，cursor 分頁 | `{success, data, error, meta}`，頁碼分頁 | Claude＋ChatGPT 的 error 欄位 | 專案規範要求統一 envelope；error 內用 code、message、request_id；事件輪詢用 sequence cursor |
| 17 | 程式結構 | 依類型分層 | 依功能分模組 | Claude＋ChatGPT 的依賴規則 | 依功能組織；保留「domain 不依賴 FastAPI 或 Docker」，用 import-linter 強制 |
| 18 | 測試門檻 | 核心模組 branch coverage ≥ 80%；SEC-01 到 SEC-20 要有收包證明 | TDD；整體 coverage ≥ 80% | 融合 | 整體 ≥ 80%、核心安全模組 branch ≥ 90%，加上 SEC 測試矩陣與故障注入 |
| 19 | 流量預算 | 每 target 2 req/s、5,000 次、25 分鐘 | 由各工具自設上限 | 融合 | 保留「跨引擎共享預算」機制；數值先當保守起始值，M3 量測後再調整 lab profile |
| 20 | Nuclei 模板 | 人工審查的 HTTP 模板白名單 | 用 severity 與 tag 過濾 | 融合 | 依 tag/類型產生固定 template ID 清單（鎖 release + hash），以類別為單位審查；另加上 `-ni`（關閉 OAST）與 `-duc` |
| 21 | 實驗設計 | 自製可切換弱點靶場、holdout、相同總預算、重複 5 次 | Juice Shop、VAmPI、DVWA，重複 3 次 | 融合 | 採用 ChatGPT 的方法論，加上 VAmPI 現成的 vulnerable/secure 開關；DVWA 改列延伸 |
| 22 | 部署環境 | 兩台 VM | 單台 Mac（OrbStack） | 融合 | 開發期單機（socket-proxy + 網路隔離）；掃描 lab 以外的目標前，再改用獨立 VM |
| 23 | 誠實與完成定義 | 很完整 | 較少 | ChatGPT | 和 AI 協作開發時特別重要 |
| 24 | 工具事實與本機環境 | 沒有具體版本 | 版本、旗標、映像都已查核，也找出本機環境問題 | Claude | M0 可以直接開工 |
| 25 | 法律 | 強調授權，但沒引用法條 | 刑法第 36 章提醒 | Claude | 口試與指導教授會問 |

## 3. 兩份都沒採用的決定：以 PostgreSQL 作為工作佇列

兩份規劃都使用 Celery + Redis。本專題改為直接以 PostgreSQL 資料列當工作佇列，理由如下：

1. **規模很小**：初版只有一個 runner，同一 target 的引擎依序執行，工作量極小。
2. **DB 本來就是唯一事實來源**：ChatGPT 版的設計本來就需要 DB claim/lease 來防止重複啟動容器，broker 在那個設計中只剩「通知」的作用。
3. **交易一致**：scan 與各引擎的 scanner_run 在同一個 transaction 建立。不會出現「DB 已寫入但工作沒派出去」的情況，所以不需要 outbox 與 dispatcher。
4. **少一種重送語意**：Redis broker 對未確認的工作，會在 visibility timeout（預設 1 小時）後重送給其他 worker 執行 [S31]；Celery 文件也要求工作設計成可以安全重複執行 [S11]。長時間的掃描如果沒處理好，就會變成重複掃描。改用 `SELECT … FOR UPDATE SKIP LOCKED` 認領資料列，就沒有這個問題；PostgreSQL 文件也說明這適合多個消費者存取的佇列型資料表 [S28]。
5. **少一個服務**：16 GB 的開發機少跑一個 Redis，測試也少一類故障（broker 不可用、重複 message）。

做法：

- runner 認領 `scanner_runs`（queued → preparing）。
- worker 認領 `scanner_runs`（collected → normalizing）與 `reports`（pending → running）。
- 每次認領都寫入 lease 與 heartbeat。先用 1–2 秒輪詢，需要時再加 LISTEN/NOTIFY。
- 系統仍不宣稱 exactly-once：開始發流量後中斷就標 interrupted，不自動重跑。

何時重新檢討：需要多台 runner 並行，或工作量大到輪詢造成 DB 負擔時。佇列邏輯集中在 `scans/` 模組，替換範圍小。

## 4. 對 ChatGPT 版的修正

| 原設計 | 修正 | 理由 |
|---|---|---|
| 控制平面與 Runner 各一台 VM | 開發期單台 Mac（OrbStack）：internal networks、docker-socket-proxy、非 root 容器。掃描 lab 以外的授權目標前，runner 與掃描容器移到獨立 VM | 1 人開發的實際條件；殘餘風險寫入威脅模型 |
| 預算 2 req/s、5,000 次、25 分鐘 | 保留為 M0–M2 的保守起始值；M3 量測各工具實際請求量後調整 lab profile，並在報告揭露 | 避免 ZAP 主動掃描被截斷，造成檢出率失真 |
| 人工審查每個 Nuclei 模板 | 依 tag/類型產生固定 ID 清單，鎖 release + hash，以類別為單位審查，並抽查高風險模板 | 數千個模板無法逐一審查 |
| 兩人交叉審查與標記 | 本人標記，再請指導教授或同學抽樣複核；每個里程碑結束時跑 code-reviewer 與 security-reviewer agent | 1 人專題；單人標記列為效度威脅 |
| 依類型分層 | 依功能分模組，保留依賴方向規則並以 import-linter 強制 | 符合專案規範 |
| 回資源本體、cursor 分頁 | 統一 envelope；清單 page/limit；事件 sequence cursor | 符合專案規範 |
| 只用 API Top 10:2023 | 加上 Top 10:2025 | 報告需要最新版 |
| 只有 JSON/Markdown | P1 加 SARIF | 展示 CI 整合 |
| 核心模組 branch ≥ 80% | 整體 ≥ 80%（專案規範）＋核心安全模組 branch ≥ 90% | 兩者都要 |

## 5. 對 Claude 版的修正

| 原設計 | 改為 | 理由 |
|---|---|---|
| 常駐 ZAP daemon + subprocess | Runner 啟動單次容器 | 三個工具同形、每次乾淨環境、取消可靠；掃描器在網路上碰不到 DB |
| 應用層 SSRF 檢查 | egress guard + 網路拓撲；URL 正規化的表格測試保留 | 掃描器會自行解析 DNS、跟隨 redirect |
| DNS TXT / well-known 驗證 | ScopeGrant + 管理員核准 + `LAB_ONLY` + `LAB_CIDR` 上限 | lab 靶機沒有公開網域 |
| 帳密 + JWT + refresh | 平台 API key + project | 純後端、攻擊面小 |
| 三工具並行 | 依序執行、共享預算 | 公平比較、靶機負載、記憶體 |
| 每次掃描的 findings | Observation + 跨掃描 Finding | 複掃與 triage 延續 |
| 類別式關聯、多工具升信心 | 保守 fingerprint、多工具不升級；一致性改為實驗分析 | 誤合併會隱藏漏洞 |
| HTTP 500 算 security | 預設 robustness，有安全證據才算 security | 不灌水資安數量 |
| new / fixed / unchanged | 五分類 + 可比性判斷 | 「沒再看到」不等於「已修好」 |
| lease 遺失自動重排 | 標 interrupted、不自動重跑 | 不重複打靶機 |
| 從遠端 URL 抓 OpenAPI | 只收上傳 | 平台本身沒有 SSRF 攻擊面 |
| P0 就做 HTML 報告 | P0：JSON + Markdown；P1：SARIF；HTML/PDF 列延伸 | 降低 XSS 風險與工作量 |

## 6. 需要重新檢討的時機

- **要掃描 lab 以外的授權目標**：先完成 HTTPS guard 與 CA 測試，並把 runner 與掃描容器移到獨立 VM。
- **要做前端**：加入使用者登入（session 或 OIDC）與 CSRF 防護；API key 保留給 CI。
- **要多 runner 並行或排程大量掃描**：重新評估工作佇列（§3）。
- **M5 Gate 未通過**：M6 改為補強，不接 Schemathesis。

## 7. T04 補充決定：整合測試資料庫與 DB 角色（2026-10-18）

原規劃（`PROJECT_PLAN.md` §7、`SECURITY_AND_TESTING.md` §4.3）用 testcontainers 在 pytest 內啟動 PostgreSQL。T04 實作時改為下表做法：

| 項目 | 原規劃 | 採用 | 理由 |
|---|---|---|---|
| 測試 DB 怎麼啟動 | pytest 以 testcontainers 啟動容器 | `compose.yaml` 的 `db-test`（tmpfs），由 `make test` 先啟動；pytest 只連 127.0.0.1 | testcontainers 需要測試程序本身能操作 Docker daemon（Ryuk reaper 還要掛 docker.sock）。T10 預定在測試中封鎖 Docker daemon，若測試需要 Docker 權限，這道防線就得開例外。改由 Makefile 啟動後，測試程序完全不碰 Docker |
| 每次都是全新 DB | 每次啟動新容器 | 每個測試 session 在 db-test 建立專屬角色與全新資料庫，結束時刪除 | 仍然每次驗證「全新 DB 可完成 migration」，又不必每次重啟容器 |
| 防止誤用其他資料庫 | — | 只接受 `cluster_name=secscan-test` 的伺服器；連線設定只讀 `TEST_DB_*`，與應用程式的 `DB_*` 分開 | 設定指錯（例如指到開發用 db）時直接拒絕，不會在開發資料上建立或刪除東西 |
| 連線用的 DB 角色 | 未規定 | 應用程式、migration 與整合測試都用非 superuser 的「資料庫擁有者」角色；superuser 只用於初始化 | 一旦遭 SQL 注入，攻擊者拿不到 `COPY ... PROGRAM`、讀伺服器檔案或建立角色的能力；測試的權限與正式環境一致，需要 superuser 的 migration 會在測試就失敗 |
| 對外 port | — | 只綁 127.0.0.1（開發 55432、測試 55433） | `make dev` 在宿主執行，需要連得到 DB；M2 把 api/worker/runner 容器化之後，DB 改成只接 control_net |

限制與後續：

- 資料庫擁有者仍能停用或刪除 audit_events 的 trigger。trigger 擋得住程式錯誤造成的誤改，擋不住已取得 DDL 能力的攻擊者，所以目前只稱「防誤改」，不稱「防竄改」。把 DDL 與 DML 角色分開（migration 角色擁有 schema；應用程式角色只有 DML，對 audit_events 只有 INSERT/SELECT），列為 M2/T23 的強化項目。
- 開發用 db 的應用程式角色密碼，只在第一次初始化 volume 時寫入；之後修改 `.env` 不會同步（見 README）。
- superuser 密碼（`DB_ADMIN_PASSWORD`、`TEST_DB_PASSWORD`）與應用程式密碼放在同一個 `.env`，而應用程式每次啟動都會讀這個檔。M2 容器化時改用 compose `secrets:` 與 `POSTGRES_PASSWORD_FILE`，把基礎設施與應用程式的秘密分開。
- DB 連線尚未設定 `sslmode`。只在單機 loopback 使用時影響不大；M2（離開單機）前補上。`statement_timeout`、`lock_timeout` 與 `idle_in_transaction_session_timeout` 已在 T09 設定（§13.8）。

何時重新檢討：要在 CI（例如 GitHub Actions）執行時，可改用 CI 的 service container。測試程式只依賴 `TEST_DB_*` 與 `cluster_name`，不需要修改。

## 8. T04 補充決定：功能模組的依賴順序（2026-10-18）

功能模組都放在 `src/secscan/<feature>/`，但彼此仍會互相呼叫。例如：
- 每個 router 都要用 api_keys 的身分驗證。
- 撤銷 key、核准 grant 都要寫 audit。

如果把它們設成互不依賴，T05 一開始就會違反 import-linter。T04 依實際呼叫關係定出順序，上層可以 import 下層，反之不行：

```text
main → migrations → health | projects → api_keys → audit → core
```

| 模組 | 為什麼在這一層 |
|---|---|
| projects | 專案的 API 需要身分驗證（api_keys）與稽核（audit）。`GET /projects/{id}/audit-events` 也放在 projects 的 router |
| api_keys | 撤銷、建立 key 要寫 audit。建立 project 範圍的 key 時，project 存不存在交給 FK 判斷（`fk_api_keys_project_id_projects` 對應 404），不 import projects |
| audit | 只依賴 core；被所有需要稽核的模組使用 |

其他規則：
- **跨功能的 FK 以資料表名稱引用**（例如 `ForeignKey("projects.id")`），不 import 對方的 model。被引用的 model 由 `secscan.migrations.metadata` 統一登記；每個使用 ORM 的程序入口（API、T05 的 CLI、M2 的 worker 與 runner）都必須 import 它，否則 FK 解析不到資料表。`tests/unit/test_entrypoint_registry.py` 在新的 Python 程序裡檢查 API 入口。
- **T06 起的 targets、grants、specs、auth_profiles、scans** 依同樣的原則插在 projects 之上。插入時在本節補上理由。
- **domain 規則**（狀態機、scope 比對、fingerprint）一律放在 `<feature>/domain.py`，或拆成 `<feature>/domain/` 套件，才會受到「不得依賴框架、DB、Docker」的檢查。

何時重新檢討：如果出現雙向需求（例如 audit 需要 api_keys 的型別），先考慮把共用的純型別移到 core，而不是打破順序。

T05 加入 `cli` 與 `security` 兩個模組，更新後的順序見 §9。

## 9. T05 補充決定：平台 API key、權限與 request-scoped transaction（2026-10-19）

T05 實作 §2 第 6 項「平台 API key（只存雜湊）加 project 角色」。以下是規劃文件沒有寫到、實作前才定下的細節。

### 9.1 key 的格式、雜湊與驗證

| 項目 | 採用 | 理由 |
|---|---|---|
| 格式 | `secscan_<prefix>_<secret>`<br>prefix：16 個小寫 hex（64-bit，公開的識別碼，存在 DB）<br>secret：`secrets.token_hex(32)`（256-bit） | 固定標記讓秘密掃描容易辨識；長度與字元集固定，格式不符直接回 401，不查 DB |
| 雜湊 | 對完整 key 做 SHA-256（32 bytes），不加 pepper | key 是 256-bit 亂數，離線猜測不可行，不需要 bcrypt、argon2 這類為低熵密碼設計的慢雜湊。pepper 要多管理一個秘密（API 與 CLI 都要讀，更換時所有 key 一起失效）。<br>代價：能寫入 api_keys 的人（例如 SQL injection 或被竄改的還原檔）可以插入自己知道的 key 的 hash，取得管理權限；把 pepper 放在 DB 之外的 HMAC 擋得住這種情況。M1 是單一信任區（同一台機器、同一組 DB 帳密），接受這個代價，重新檢討的時機見 §9.5 |
| 比對 | 以 prefix 查詢，再用 `hmac.compare_digest` 比對 hash；prefix 不存在時，仍與假 hash 比對一次 | 「不存在」與「secret 錯誤」的運算量相近 |
| 401 回應 | 缺少、格式錯、不存在、secret 錯、已撤銷：同一個 `UNAUTHENTICATED`，訊息與 `WWW-Authenticate: Bearer` 都相同<br>secret 驗證成功但已過期：`API_KEY_EXPIRED`。先比對 secret，再判斷撤銷與到期（有測試固定這個順序） | 不洩漏 key 是否存在或已撤銷；「已過期」只會告訴真正持有 key 的人，只知道公開 prefix 的人探測不到 |
| 有效期 | 所有 key 都會過期：預設 90 天、最多 365 天，而且必須晚於現在。API 與 CLI 規則相同<br>domain 的 `NewApiKey` 要求一定要有到期時間；DB 欄位仍可為 NULL（T04 的 schema），驗證時把沒有到期時間的 key 一律視為過期 | 平台 key（尤其 platform_admin）權限大，不留永久憑證；過期後用 CLI 或 API 重新建立即可。不為此新增 migration：驗證時 fail closed 已足夠 |
| 誰能建立 admin key | 只有本機 CLI `secscan-admin create-admin-key`；API 只能建立 operator、viewer key。`issue_admin_key` 本身不做授權檢查，另以測試確保 src 中只有 CLI 呼叫它 | 能執行 CLI 的人本來就有 DB 帳密。外洩的 admin key 無法經 API 再建立 admin key，撤銷後就失去管理權限；但它在撤銷前建立的 project 與 operator、viewer key 仍然有效，要另外從 audit 找出來撤銷（§9.5） |
| 完整 key 的去向 | 只在建立時出現一次：API 的回應（加 `Cache-Control: no-store`），或 CLI 在 commit 成功後寫到 stdout 或 `--output` 指定的新檔案（`O_EXCL`、權限 600，已存在就拒絕）。DB 只存 prefix 與 hash；audit 與 log 不記完整 key、secret 或 hash | DoD「只存 hash、只顯示一次」。沒有建立 key 時不寫出任何東西，也不留下空檔 |

### 9.2 權限規則

| 角色 | 全域管理<br>（建立 project、撤銷 key） | 自己 project：讀 | 自己 project：寫<br>（T06 起） | 自己 project：管理<br>（建立 key、看稽核） | 其他 project |
|---|---|---|---|---|---|
| platform_admin | 允許 | 允許 | 允許 | 允許 | 允許（不存在才 404） |
| operator | 403 | 允許 | 允許 | 403 | 404 |
| viewer | 403 | 允許 | 403 | 403 | 404 |

- **規則集中成一個純函式**：`decide(principal, permission, project_id)`，放在 `api_keys/domain.py`，回傳 ALLOWED、NOT_FOUND 或 FORBIDDEN。service 呼叫它，route 不自行判斷。
- **先判斷 project，再判斷角色**：不是自己的 project 一律 404（與不存在相同），是自己的 project 但角色不足才 403（`API_CONTRACT.md` §1）。
- **`/api/v1` 在 router 層強制驗證 key**：之後新增的路由即使忘了宣告依賴，也不會變成公開端點。
- **新增 `GET /api/v1/projects/{project_id}`**：T05 其他以 project 為範圍的端點都只限 admin，viewer 需要一個能讀的單一物件，才能驗證 object-level 的 404。
- **清單查詢的範圍用明確的型別**：`ProjectScope` 是 `AllProjects`（只有 platform_admin）或 `OneProject(project_id)`，由 `Principal.project_scope` 決定，repository 必須收到其中一種。不用 `None` 代表「全部」：漏傳或傳錯時直接失敗，不會變成列出所有 project。
- **被拒絕的存取寫進日誌**：`authorize()` 記下 decision、key_id、角色、權限、project_id 與 request_id（不記 body），方便發現有人逐一嘗試其他 project 的 UUID。
- **T06 起的資源**（target、grant、scan…）：同樣呼叫 `authorize()`，清單查詢同樣收 `ProjectScope`。

### 9.3 request-scoped transaction

- **每個請求一個 session 與 transaction**：成功就 commit，有例外就 rollback；業務變更與 audit 在同一個 transaction。
- **依賴使用 `Depends(..., scope="function")`**：FastAPI 0.143.3 的 yield 依賴預設在回應送出**之後**才結束，那樣 commit 失敗時 client 已經收到 201。function scope 在回應送出之前結束，commit 失敗會回 500。
- **重試放在 savepoint 裡**：可能撞到唯一約束的重試（prefix 碰撞）在 `begin_nested()` 內進行，失敗時不會讓整個 transaction 無法繼續使用。

### 9.4 模組與分層（更新 §8）

```text
main | cli → migrations → health | projects → api_keys → audit → security → core
```

| 模組 | 為什麼在這一層 |
|---|---|
| cli | 本機管理指令（建立 admin key）。和 main 一樣是程序入口，必須 import model 登記（`tests/unit/test_entrypoint_registry.py` 兩個入口都檢查） |
| security | CLAUDE.md §5 規劃的共用模組：API key 的產生與雜湊、遮罩（T08 再加 MultiFernet）。audit 要用遮罩，api_keys 要用 key 雜湊，所以放在兩者之下。和 domain 一樣不得依賴框架、DB 與 Docker（import-linter 的 forbidden contract） |

T06 加入 targets 與 grants 兩個模組，更新後的順序見 §10.7。

### 9.5 不在 T05 範圍

- **速率限制（429 `API_RATE_LIMITED`）**：key 有 256-bit，暴力猜測不可行，而且 API 目前只綁 127.0.0.1。多個 worker 之間要共享計數，需要一併設計，列入 M2/T23 的部署強化。
- **`last_used_at`**：需要改 schema，而且每個請求都要寫 DB；需要時再加 migration。
- **全域 audit 查詢**：CLI 建立 admin key、撤銷 admin key 的事件沒有所屬 project，T05 只能直接查 DB；查詢 API 留給 T21。
- **全域安全 header**（`X-Content-Type-Options`、所有回應的 `Cache-Control: no-store`）：列入 M2/T23。T05 只對含完整 key 的回應設 `no-store`。
- **請求大小上限與「驗證前不讀 body」**：FastAPI 在執行依賴（包括驗證 key）之前，就先讀完並解析 JSON body。所以沒有 key 的請求送壞掉的 JSON 會得到 422（不是 401），送很大的 body 也會被整個讀進記憶體。T05 只把文件與測試改成實際行為。在 `/api/v1` 前加 pure-ASGI middleware（`Authorization` 格式不符就先回 401、累計超過上限就回 413）列入 T07（規格上傳的大小限制）與 T23。
- **key 的事故應變工具**：列出 key、依 prefix 撤銷、撤銷某把 key 建立過的所有 key，以及 `last_used_at`。目前遺失 key id 時，只能從建立時的 stderr、project 的 audit 或直接查 DB 找回。列入 M2。
- **dev 的 `/docs`**：FastAPI 預設從 CDN 載入 Swagger UI（沒有 SRI）。README 提醒不要在 `/docs` 貼 admin key；改為自行託管列入 M2/T23。
- **遮罩的已知缺口**：HAR 那種 name/value 成對的格式、URL 中的帳密與 query 參數、`password=…` 之類的文字還不處理（`security/redaction.py` 的說明）。T08（認證設定）與 M3（證據遮罩）需要時再擴充，並補對應的測試。T08 不把 secret 放進任何會被遮罩的結構（§12.2），所以沒有擴充，留給 M3。

T23 的硬性條件：速率限制、請求大小上限與安全 header 都完成之前，不發布 API 的 port，也不綁 loopback 以外的位址（目前只靠 `make dev` 綁 127.0.0.1）。

何時重新檢討：
- key 要給 CI 等系統長期使用，而 365 天的上限太短：改成可設定的上限，並記錄理由。
- API 要改成多 worker 或對外開放：先完成速率限制。
- DB 與應用程式分屬不同的信任區（例如 DB 由他人管理），或 DB 的寫入權限可能外流：重新評估 HMAC＋pepper。

## 10. T06 補充決定：target、scope grant 與審批（2026-10-19）

T06 實作 §2 第 5 項：ScopeGrant（origin、IP、path、method、預算、期限）加上管理員核准，以及它的上限——`LAB_ONLY` 時 grant 的 IP 必須落在 `LAB_CIDR` 內。以下是規劃文件沒有寫到、實作前才定下的細節。

### 10.1 LAB_ONLY 與 LAB_CIDR

| 項目 | 採用 | 理由 |
|---|---|---|
| `LAB_ONLY` | 設定 `LAB_ONLY`，預設 true；P0 設成 false 時程式啟動就失敗 | P0 只掃 lab（`PROJECT_PLAN.md` §5.3）。要掃描 lab 以外的目標，必須先滿足 §6 的條件：HTTPS guard 與 CA 測試、runner 與掃描容器移到獨立 VM。不留「關掉就能掃任何 IP」的開關 |
| `LAB_CIDR` | 設定 `LAB_CIDR`，預設 `10.89.7.0/24`，也就是 `compose.lab.yaml` 的 lab_net（有測試比對兩者一致）。必須是 RFC 1918 私有網段 [S52] 內、前綴 /16–/30 的 IPv4 網段 | CLAUDE.md §6：不一律開放 RFC 1918。太寬的設定（例如 `10.0.0.0/8`）可能涵蓋校園網路；/31、/32 沒有一般意義的網段與廣播位址，規則會變得難懂 |
| grant 的 IP | 只收個別的 IPv4 主機位址，不收網段與 IPv6。每個都要在 `LAB_CIDR` 內，而且不是網段位址或廣播位址 | 「靶場私有位址逐項白名單」。lab 網路已關閉 IPv6（`compose.lab.yaml`） |
| 檢查時點 | 建立 target（host 是 IP 時）、申請 grant、核准、掃描 gate（§10.6），每次都以當下的設定檢查 | 設定可能在申請與核准之間、核准與掃描之間改變。縮小 `LAB_CIDR` 之後，範圍外的 grant 就不能再核准或使用 |

`LAB_CIDR` 只存在設定中，DB 無法檢查；DB 只保證 IP 的筆數（§10.4）。

### 10.2 URL 與 origin

- **只接受 `http://host[:port]`**，結尾可以有一個 `/`。scheme 與 host 轉成小寫、省略 `:80`，結果就是 canonical origin。
- **一律拒絕**：
  - https（P0 只支援 HTTP 靶場，CLAUDE.md §6）與其他 scheme
  - userinfo（`user:pass@`）、反斜線、percent-encoding
  - path、query、fragment（seed path 見下方）
  - 非 ASCII 字元、空白與控制字元
  - IPv6、尾端的點、`localhost` 與 `*.localhost`（解析到 loopback [S53]）
  - 數字形式模糊的 host：前導 0、十六進位、整數、不足 4 段，以及最後一段以數字開頭、卻不是合法 IPv4 的名稱 [S49]
  - 第 3、4 個字元是 `--` 的標籤（保留給 `xn--` 等國際化網域名稱 [S55]）
  - 不合法的 port：0、超過 65535、前導 0
- **理由**：同一個字串，不同的 URL parser 可能解出不同的 host（SEC-05）。以 Python 3.12 實測與 WHATWG URL 規格（瀏覽器與部分工具採用）對照 [S47][S48]：
  - `http://lab\@evil`：`urlsplit` 解出 host `evil`；WHATWG 把反斜線當成斜線，解出 `lab`。
  - `http://0x0a.89.7.20`、`http://167772160`：WHATWG 當成 IPv4（`10.89.7.20`、`10.0.0.0`），`urlsplit` 當成主機名稱。
  - 全形的 `ｌａｂ`：WHATWG 轉成 `lab`，`urlsplit` 原樣保留。
  - `urlsplit` 會默默去掉開頭的空白。

  只接受各家解讀一致的最嚴格子集，平台記錄的 origin 才會和工具實際連線的 host 相同。測試以 Hypothesis 檢查結果 idempotent，並和 `urlsplit` 比對解析結果；M2 的 guard 再和 mitmproxy 比對（T11）。
- **錯誤訊息不回顯輸入**：只說明原因（例如「不可包含帳密」），userinfo 裡的密碼不會出現在回應或日誌。
- **不解析 DNS、不連線**：API 不對使用者給的 URL 發出任何流量。origin 與 IP 的對應，由管理員核准時人工核對；執行時由 guard 強制（DNS 結果必須在 grant 的 IP 內，`ARCHITECTURE.md` §3.2）。
- **seed path 延後**：`API_CONTRACT.md` §3 的「受限 seed path」目前沒有使用者，T06 不收，`base_url` 只能是 origin。M3 的 ZAP web profile 需要時再加，屆時與 grant 的 path 範圍一起驗證。
- **同一個 project 內 origin 不重複**：重複時回 409 `TARGET_ORIGIN_CONFLICT`。target 代表一個 origin，重複會讓「這次掃描該用哪個 target 的 grant 與預算」變得不明確。

### 10.3 grant 的範圍、預算與期限

| 欄位 | 規則 | 理由 |
|---|---|---|
| `allowed_origins` | 1–4 個，依 §10.2 正規化，必須包含 target 自己的 origin；host 是 IP 的 origin，那個 IP 必須列在 `allowed_ips` | 一個 grant 至少涵蓋自己的 target；IP 綁定以 `allowed_ips` 為準 |
| `allowed_ips` | 1–16 個，規則見 §10.1 | guard 以這份清單檢查 DNS 結果與實際連線的位址 |
| `allowed_paths` | 1–256 個，每個是完整的 literal path，或含整段 `{name}` 佔位的 route（例如 `/api/items/{id}`）。也可以改用明確的 `allow_all_paths: true`，此時清單必須是空的 | 不用「空清單代表全部」（理由同 §9.2 的 `ProjectScope`）。不接受 regex，也不從字串前綴推論範圍（`API_CONTRACT.md` §4）。Web 爬蟲事先不知道會走到哪些 path，需要一個明確的「全部」 |
| `excluded_paths` | 0–64 個，語法同上；排除優先於允許 | 例如 `/api/logout`、`/api/admin` |
| path 的語法 | 以 `/` 開頭、只用 ASCII 的 URI path 字元；不可有 `%`、`\`、`?`、`#`、`;`、`*`、空白與控制字元，也不可有空段落（`//`）或 `.`、`..` 段落；每個最長 512 字元 | SEC-08：percent-encoding 與點段落讓同一條 path 有多種寫法 [S50]，無法可靠比對時 fail closed；`;` 會被部分伺服器當成 path 參數，`*` 容易被誤認成萬用字元。比對規則由 T07 與 M2 實作，T06 只定語法 |
| `allowed_methods` | GET、HEAD、OPTIONS、POST、PUT、PATCH、DELETE 的子集，大小寫必須完全一致；TRACE、CONNECT 一律拒絕 | HTTP method 區分大小寫 [S54]。狀態改變的 method 必須明確列出（CLAUDE.md §7）。TRACE 雖是 safe method，但會回顯請求內容，掃描用不到；CONNECT 是建立通道，不屬於對 target 的請求 |
| 重複值 | 任何清單有重複（正規化之後）都拒絕，不默默去重 | 不默默修正輸入，與分頁參數的原則相同 |
| 預算 | `requests_per_second`、`max_requests`、`max_duration_seconds` 三個正整數，上限是 M0–M2 的保守起始值 2、5,000、1,500；沒指定時用上限 | 沿用 `ARCHITECTURE.md` §3.4。上限放在 domain，DB 只檢查大於 0；M3 量測後要提高時，在這裡記錄理由，不需要 migration |
| 期限 | `valid_until` 必填；`valid_from` 預設為申請時間。必須 `valid_from < valid_until`、`valid_until` 晚於現在，期間最長 30 天。先以原本的時區比較，再換算成 UTC；換算時超出 datetime 範圍（例如 `9999-12-31T23:59:59-05:00`）回 422 | 授權不能沒有期限。30 天代表一學期的 lab 大約每月重新核准一次。帶時區的時間之間比較不會溢位，換算成 UTC 卻可能會（審查時發現原本回 500） |
| `authorization_reference` | 必填，1–200 字元 | 對應的授權文件或靶場資產紀錄編號，核准時核對 |

### 10.4 狀態與轉換

- **DB 只存 `pending`、`approved`、`revoked`**。`expired` 由 `valid_until` 推導：pending 或 approved 的 grant，從 `valid_until` 那一刻起就是 expired；revoked 優先於 expired。
  - 不需要排程工作把資料改成 expired，也就沒有「已過期、DB 卻還是 approved」的空窗。
  - 代價：到期的當下沒有 audit 事件；到期時間已記在 `scope_grant.create` 的 audit 中。
- **轉換**：

| 目前狀態 | approve（admin） | revoke（admin） |
|---|---|---|
| pending | → approved（重新檢查期限與 `LAB_CIDR`） | → revoked |
| approved | 409 `INVALID_STATE_TRANSITION` | → revoked |
| revoked | 409 | 200，不改變任何東西，也不重記 audit |
| expired | 409（要重新申請） | 409 |

- 撤銷是安全方向，可以安全重試；核准是放行方向，必須明確，重複核准是錯誤。
- approve 必須附 `note`（核對了什麼），revoke 必須附 `reason`，都寫進 audit。
- **併發**：核准與撤銷以 `SELECT … FOR UPDATE` 鎖住 grant，並以 DB 的最新值判斷（`populate_existing`，同 §9 撤銷 key 的做法）[S57]。同時核准與撤銷時，結果和其中一個先執行的結果相同。
- **時間戳**：
  - `approved_at` 是核准那個 transaction 開始的時間（`now()`）。transaction 在驗證 key 時就開始，早於 service 判斷「尚未到期」的時間，所以 CHECK 的 `approved_at < valid_until` 與 domain 的判斷一致。
  - `revoked_at` 是實際寫入的時間（`clock_timestamp()`）。撤銷的 transaction 可能比一個同時進行的核准更早開始，卻在核准 commit 之後才拿到鎖；若記成 transaction 開始的時間，會早於 `approved_at` 而違反 CHECK，撤銷回 500。審查時重現了這個情境，改用 `clock_timestamp()`，並加上確定性的測試。
- **不可變**：
  - grant 建立後範圍不能改，沒有 PATCH。要改範圍就申請新版本；`version` 是每個 target 各自的流水號，申請時先鎖住 target 再取下一號。
  - 核准新版本不會自動撤銷舊版本：scan 會明確指定使用哪個 grant，舊版本由 admin 自行撤銷。
- **DB 的最後一道防線**：
  - CHECK：各狀態的核准、撤銷欄位成對且一致、時間先後、清單筆數、method 白名單、預算大於 0、文字不空白。
  - trigger：UPDATE 只允許 pending→approved、pending→revoked、approved→revoked，而且只能改狀態與核准、撤銷欄位；DELETE 與 TRUNCATE 一律拒絕。
  - 和 audit 的 append-only trigger 一樣，只能防程式錯誤造成的誤改（§7）。

### 10.5 權限

| 操作 | 需要的權限 | 誰可以 |
|---|---|---|
| 建立 target、申請 grant | `PROJECT_WRITE` | operator、admin |
| 停用或改名 target（`PATCH`） | `PROJECT_WRITE` | operator、admin |
| 查詢 target 與 grant | `PROJECT_READ` | 同專案的 viewer、operator，以及 admin |
| 核准、撤銷 grant | `PLATFORM_MANAGE`＋project_id | admin |

- 其他 project 的 target 與 grant 一律回 404，與不存在相同（§9.2）。
- operator 的緊急停止是停用 target：已核准的 grant 就不能再用來建立新的 scan（§10.6）。但 operator 也能把它重新啟用，所以這不是權威的停止手段；權威的停止是撤銷 grant，只有 admin 能做（`API_CONTRACT.md` §2）。
- admin 可以核准自己提出的申請。目前只有一位管理員，CLI 本來就能再建立 admin key，以 key 區分並不會帶來真正的職責分離；audit 會記下申請者與核准者。

### 10.6 掃描 gate

- `ScopeGrantService.require_usable()` 是「這個 grant 現在能不能用來掃描」的唯一判斷。T09 建立 scan 時在同一個 transaction 呼叫；runner 啟動前（M2）再判斷一次。
- 通過條件：grant 屬於該 target、target 的 origin 在 grant 的範圍內、狀態是 approved、`valid_from <= 現在 < valid_until`、target 未停用、所有 IP 都在當下的 `LAB_CIDR` 內。
- target 的 origin 由 API 保證不可修改；gate 仍自己比對一次，因為 targets 沒有像 scope_grants 那樣的 trigger，直接改 DB 時會不一致（縱深防禦）。
- 以 `FOR SHARE` 依序鎖住 target 與 grant [S57]：撤銷 grant 或停用 target 一旦 commit，之後就不可能再建立使用它的 scan；反過來，正在建立 scan 時，撤銷會等它 commit。撤銷之後停止執行中的 scan，由 T09、T13 處理。
- 鎖的順序固定為 target 先、grant 後；只有 gate 同時鎖兩者，所以不會互相等待而死結。

### 10.7 模組與分層（更新 §9.4）

```text
main | cli → migrations → health | grants → targets → projects → api_keys → audit → security → core
```

| 模組 | 為什麼在這一層 |
|---|---|
| grants | 申請 grant 要鎖住 target 取得版本號，並由 target 得知所屬的 project |
| targets | 建立與列出 target 前要確認 project 存在：admin 指定不存在的 project 時回 404 |

T07 加入 specs 模組，更新後的順序見 §11.7。

### 10.8 不在 T06 範圍

- path 與 method 的比對規則，以及 OpenAPI operation 是否在 grant 範圍內：T07、T11。
- `POST /scans` 呼叫 gate；撤銷 grant 或停用 target 之後，停止執行中的 scan：T09、T13。
- guard 的 DNS/IP 綁定與 redirect 檢查，以及與 mitmproxy 的 URL 解析比對：T11。
- seed path、依量測調整預算上限：M3。
- 全域的待核准清單：目前要從 project → target → grant 逐層查詢，和全域 audit 查詢一起留給 T21。
- 請求大小上限：T07（§9.5）。
- 審查時提出、留給後續的事項：
  - path 比對的語意（T07、T11）：`/api/logout`、`/api/logout/`、`/API/Logout` 在語法上是不同字串，但許多伺服器視為同一個 route。`excluded_paths` 的比對至少要和伺服器一樣寬（例如不分大小寫、結尾斜線視為相同），請求路徑含 `%2e`、`%2f`、`;`、`//`、`/./` 時直接拒絕，不做正規化。
  - lab 網段內的基礎設施位址（M2）：guard 與 canary 也會接 lab_net，位址在 `LAB_CIDR` 內。`check_host` 只排除網段與廣播位址，目前靠 admin 人工核對；M2 加上保留位址清單，或讓靶機使用固定 IP。`localhost.localdomain`、`host.docker.internal` 這類名稱沒有在 API 擋下，由 guard 要求 DNS 結果落在 `allowed_ips` 內來防。
  - gate 的時間與鎖等待（T09）：呼叫端在取得 `FOR SHARE` 之後再取 `now`，並設定 `lock_timeout`（§7 已記錄尚未設定 `statement_timeout`），避免建立 scan 的 transaction 拖長時卡住撤銷。T09 已處理：`require_usable()` 改收 `clock`，連線設定了逾時（§13.8、§13.9）。
  - 報告以 `approved_at` 作為授權成立的時間：`valid_from` 可以早於申請時間（最多約 30 天）。

### 10.9 數量上限（審查後補充）

- 每個 target 最多 10 個待核准的申請（pending 且未過期），每個 project 最多 100 個 target；超過時回 409 `QUOTA_EXCEEDED`。
- 理由：grant 無法刪除（trigger 擋下 DELETE），單筆最大可達約 165 KB（256 個 path，每個 512 字元）。一把外洩的 operator key 只靠申請就能不斷寫入，而速率限制要到 T23 才有。兩個上限一起，讓一個 project 的待核准資料有上界（約 100 × 10 × 165 KB）。
- 已核准、已撤銷與已過期的申請不佔名額：它們要經過 admin 的動作或時間才會增加。
- target 的上限是軟上限：同時建立時可能略為超過，不為此鎖住 project。申請 grant 時已鎖住 target，所以待核准申請的上限是精確的。

### 10.10 文字欄位（審查後補充）

- `require_text`（所有名稱、`authorization_reference`、核准與撤銷的說明）拒絕 Unicode 類別 Cc 與 Cf 的字元：控制字元（ESC、換行、tab…）與不可見的格式字元（零寬空白、BOM、bidi 控制字元…）。這也影響 T05 的 project 與 key 名稱。
- 理由：這些都是單行文字。bidi 控制字元（例如 U+202E）會讓 admin 核准前要核對的授權文件編號、日後的 Markdown 報告顯示成誤導的內容；JSON 會跳脫 ESC，卻不會跳脫 bidi 字元。
- 代價：不接受含零寬連接字元的 emoji 序列；名稱與說明不需要它們。

何時重新檢討：
- 要掃描 lab 以外的目標：先完成 §6 的條件，再設計 `LAB_ONLY=false` 時的規則（例如書面授權的核對方式）。
- 30 天的期限或預算上限妨礙實驗：依量測調整，並在這裡記錄。
- 有多位管理員：考慮禁止核准自己的申請。

## 11. T07 補充決定：OpenAPI 上傳與 operation inventory（2026-10-24）

T07 實作 `PROJECT_PLAN.md` §5.1 的「API 規格」：上傳 OpenAPI 3.0、固定目標 origin、只接受同文件的 `$ref`、不抓外部 URL。規格是不可信的資料：外部參照會讓解析器或掃描工具去抓外部資源（SSRF、讀本機檔），`servers` 可以指向任意位址（SEC-02），YAML 本身也有解析風險（SEC-11、SEC-17）。以下是規劃文件沒有寫到、實作前才定下的細節。

實測依據（M1 Pro，只在記憶體中產生資料）：
- VAmPI 的真實規格（T03 的輸入，sha256 記在 `tests/fixtures/manifest.json`）：19.7 KB、OpenAPI 3.0.1、14 個 operation、1,300 個節點、14 層；`servers` 是 `http://localhost:5000`，沒有 `$ref`、anchor 或 tag。
- 1 MiB 的合成 YAML 規格（約 9.1 萬個節點、9 層）：PyYAML 純 Python 的事件 API 約 1.2 秒，完整載入約 1.5 秒；libyaml 約 0.08 秒。最壞的形態（單行 flow sequence，52 萬個事件）約 5.8 秒。
- 1 MiB 的 JSON：`json.loads` 約 6 ms。

### 11.1 上傳方式與大小

| 項目 | 採用 | 理由 |
|---|---|---|
| 上傳方式 | raw body：`Content-Type` 為 `application/json` 或 `application/yaml`（RFC 9512 [S63]），charset 只能是 UTF-8；其他回 415 `UNSUPPORTED_MEDIA_TYPE` [S64]。不用 `API_CONTRACT.md` §2 原本寫的 multipart | multipart 需要新的依賴 python-multipart，它在 2024–2026 年有多個 DoS 類的 advisory（例如 CVE-2024-24762、CVE-2024-53981、CVE-2026-42561）[S68]；Starlette 也會把超過 1 MB 的上傳檔暫存到磁碟（以 1.8.0 原始碼確認）。一次只上傳一個檔案，raw body 能逐塊精確計算大小，也不留暫存檔。<br>`application/vnd.oai.openapi` 等 OpenAPI 專用的 media type 不在 IANA 的登記表中（查核時只有 `vnd.oai.workflows`），所以不採用 |
| 規格的大小 | 1 MiB：先看 Content-Length，再逐塊累計，超過回 413 `SPEC_TOO_LARGE` [S64]。正規化後的文件最多 2 MiB | contract 的 5 MiB 是規劃值。lab 的規格很小（VAmPI 19.7 KB），而 1 MiB 的 YAML 以純 Python 解析就要 1 秒以上（§11.2）。量測後不夠再放寬 |
| 所有請求的大小 | pure-ASGI middleware：任何請求超過 2 MiB（Content-Length 或逐塊累計）回 413 `REQUEST_TOO_LARGE` | §9.5 的規劃。目前最大的 JSON body 是 grant 的申請（約 170 KB）；FastAPI 會先把整個 JSON body 讀進記憶體 |
| 驗證前的 401 | pure-ASGI middleware：`/api/v1` 的請求沒有 Bearer，或 key 格式不符，就直接回與 `current_principal` 完全相同的 401，不讀 body。格式正確的 key 仍由 `current_principal` 查 DB | §9.5 的規劃：沒有 key 的人不能讓伺服器讀取與解析 body。判斷沿用 `HTTPBearer` 與 `parse_prefix` 的邏輯，日誌也共用同一個函式，並以測試確認兩者的結果一致 |

- middleware 的順序：request_id → key 格式 → 大小上限。沒有 key 的大請求回 401，不是 413。
- key 格式檢查的範圍與路由一致：以 `--root-path` 部署時，先去掉 `root_path` 再判斷是否在 `/api/v1` 底下（同 Starlette 的 `get_route_path`，以性質測試比對）。
- **讀取 body 的時間**（審查後補上）：上傳的依賴在身分驗證之後執行，那時已經取得 DB 連線；很慢的上傳會一直佔住連線，少數幾個就能耗盡連線池。所以讀取 body 的總時間最多 10 秒，超過回 408 `REQUEST_TIMEOUT` [S64]；上傳途中斷線回 400 `INVALID_REQUEST`（原本是 500）。lab 的規格很小，10 秒很寬裕。同時進行的慢速上傳仍會佔用連線，速率限制在 T23。
- 副作用：沒有 key 時，`/api/v1` 底下不存在的路徑與不符的 method 改回 401（原本是 404、405）。有 key 時不變。
- 格式正確但無效的 key：FastAPI 仍會在查 DB 之前先解析 JSON body，語法錯誤時得到 422（§9.5 的已知行為，大小已有上限）。

### 11.2 JSON 與 YAML 的解析

- **解析器**：
  - JSON：標準函式庫 `json` [S66]。
  - YAML：PyYAML 純 Python 的事件 API（`yaml.parse` 搭配 `SafeLoader`）[S65]，由自己寫的迭代式 composer 把事件組成 JSON 值。不用 PyYAML 的 composer 與 constructor，也不用 C 擴充（libyaml）。
  - 理由：不在 API 程序裡用 C 解析不可信的 YAML，行為也不隨環境是否安裝 libyaml 而改變。PyYAML 的 composer 是遞迴的，巢狀太深會 RecursionError；事件 API 是狀態機，超過深度上限就能立刻停下（實測 20 萬層的輸入，在第 65 層就停止）。
  - 代價：比 libyaml 慢約 15 倍。以大小與節點上限控制最壞情況：審查的 PoC 在修正後重跑（M1 Pro，單次，沒有重複取中位數），各種 1 MiB 的形態，被節點上限拒絕的是 1.1–1.7 秒，通過的是 0.5–1.1 秒；速率限制在 T23。
- **共同規則**（兩種格式都是）：
  - 嚴格 UTF-8，不接受 BOM。
  - 最外層必須是物件；巢狀最多 64 層、最多 10 萬個節點。
  - 字串（含 key）不可有 NUL 或孤立的 surrogate：無法編碼成 UTF-8，PostgreSQL 也存不了 NUL。
  - 重複的 key 一律拒絕：RFC 8259 說重複名稱的行為無法預期 [S62]，不同工具可能取到不同的值。
  - 數字必須是有限值；超過 4,300 位的整數拒絕（Python 的上限 [S66]）。
- **JSON**：
  - 拒絕 `NaN`、`Infinity`：Python 的 json 預設接受，但它們不是 JSON [S62]。`1e400` 這類溢位成無限大的數字也拒絕。
  - 在 `json.loads` 之前，以迭代方式檢查巢狀深度並預估節點數，不依賴 RecursionError。預估值是字串外的開括號、逗號與冒號的數量加一，最多是實際節點數的兩倍，所以超過上限的兩倍才拒絕；精確的數量在解析後檢查。理由：`[{},{},…]` 這類 1 MiB 的輸入會先被解析成數十萬個物件（security-reviewer 回報峰值約 70 MiB）。修正後以 tracemalloc 重量：1 MiB 的 `{}` 或 `[]` 陣列峰值 1.0 MiB，1 MiB 的不同浮點數陣列峰值 23.3 MiB，都在預估階段或解析後被拒絕；不含 tracemalloc 的牆鐘時間，`{}` 陣列是 0.07 秒。
- **YAML**：
  - 只接受單一文件；不接受 directive：任何以 `%` 開頭的行都在解析之前拒絕。PyYAML 對保留的 directive（例如 `%FOO`）不產生任何事件，只看事件會漏掉它們（審查發現）。
  - 不接受 anchor 與 alias（billion laughs 的基礎）、任何明確的 tag（`!!python/…`、`!!binary`、`!` …）、複合 key（以 mapping 或 sequence 當 key）與 `<<`（YAML 1.1 的 merge key）。
  - key 一律是字串，值依 YAML 1.2 的 core schema 解讀 [S60]：`null`、`true`／`false`（含首字大寫與全大寫）、十進位與 `0o`、`0x` 整數、浮點數，其他都是字串。所以 `yes`、`no`、`on` 與日期都是字串；`.inf`、`.nan` 拒絕。OAS 3.0 建議 YAML 1.2，tag 只用 JSON schema 的型別，key 一律是字串（`200:` 是字串 "200"）[S59]。
  - 不接受直接出現的 U+0085、U+2028、U+2029：YAML 1.1 把它們當成換行，YAML 1.2 不會 [S60]。
  - 以兩個 `\u` 跳脫寫成的 surrogate pair（例如 `"\uD83D\uDE00"`）會被拒絕：PyYAML 不會把它們合併，解出的是兩個孤立的 surrogate。BMP 以外的字元請直接寫，或用 `\U0001F600`。
  - 超出 Unicode 範圍的 `\U` 跳脫（大於 `\U0010FFFF`）回 422 `INVALID_SPEC`：PyYAML 在這裡拋出的是 `ValueError`／`OverflowError`，不是 YAMLError，原本會變成 500（審查發現）。
- **錯誤訊息只說明原因與位置**：
  - 語法錯誤給行與欄。
  - 結構問題給 JSON Pointer，只由 key 與陣列索引組成，不含任何值；非 ASCII 可見字元以 `\uXXXX` 表示，過長就截斷。
  - 位置字串只在要拋錯時才組，而且組到長度上限就停：合法的文件不付這個成本，很長的 key 也不會讓成本變大（審查發現：原本每個參照都先組一次位置字串，1 MiB 的 key 乘上大量參照就是 CPU 放大）。
  - 理由：規格中的值（URL、example）可能含帳密，所以不回顯；位置是使用者自己文件的結構，指出來才修得了。這是 §10.2「錯誤訊息不回顯輸入」的延伸：key 是文件的結構，值才是內容。

### 11.3 OpenAPI 的支援範圍

- **版本**：只接受 `openapi: 3.0.x`，patch 最多 12 位數（DB 的欄位是 16 個字元，太長的版本號原本會變成 DB 的錯誤）。Swagger 2.0 與 3.1（P1）回 422 `UNSUPPORTED_SCHEMA`。
- **只驗證平台依賴的部分**：
  - 頂層只接受 OAS 3.0 的欄位與 `x-` 擴充。
  - `info` 的 `title`、`version` 必須是字串；`paths` 必須存在。
  - path item 與 operation 必須是物件；`operationId` 在整份文件中唯一，1–200 字元，不含控制字元。
  - `components` 底下 9 個區段（schemas、responses、parameters、examples、requestBodies、headers、securitySchemes、links、callbacks）的名稱必須符合 OAS 3.0 的 `^[a-zA-Z0-9.\-_]+$` [S59]，否則回 422 `INVALID_SPEC`；訊息只說是第幾個名稱，不回顯名稱。理由：名稱本身可以是 URL 或路徑，工具可能把它當成參照（審查發現）。
  - 其他欄位（schema、parameter、response…）當成不透明的 JSON，不逐一驗證。
  - 不引入 openapi-spec-validator 這類套件：它們預設會解析遠端參照，等於多一個會連網的依賴。其他格式問題由工具在 M3 回報。
- **path**：
  - 規格的 path 與 base path 接起來，就是 inventory 中的完整 path，語法與 grant 的 path 相同（`check_path`，§10.3）：佔位必須占滿一整段、名稱以英文字母或底線開頭，不接受 `%`、`;`、`*`、點段落等。
  - 只差在佔位名稱的兩個 route（例如 `/users/{id}` 與 `/users/{name}`）視為重複，拒絕：OAS 也規定它們不可並存 [S59]。
  - 這樣 grant 才寫得出規格中的每一個 route。跨段的佔位（`/files/{name}.json`）留到需要時再支援。
- **一律拒絕的功能**（422 `UNSUPPORTED_SCHEMA`）：
  - `callbacks`、`webhooks`、path item 的 `$ref`。
  - path、operation 層級的 `servers`，以及 Link 的 `server`。
  - server URL 無法解析（例如不合法的 IPv6 括號）回 422 `INVALID_SPEC`，不回顯 URL；原本 `urlsplit` 的 ValueError 會變成 500（審查發現）。
  - `oauth2` 與 `openIdConnect` 類型的 security scheme：裡面的 token、authorization 與 discovery URL 都是工具可能會去連的位址；P0 的認證只有固定的 Bearer、API key 與 Cookie（T08）。
- **上限**：每份規格最多 1,000 個 operation。

### 11.4 外部參照與 servers

- **參照**（文件中任何位置，包含 example 與 `x-` 擴充）：
  - `$ref` 與 `operationRef` 只接受 `#/…` 形式、只有 ASCII 可見字元、不含 `%` 的 JSON Pointer [S61]，而且必須指到存在的節點。RFC 6901 §6 的 URI fragment 表示法會把 `{`、`}` 等字元 percent-encode；不同工具對 percent-encoding 的解碼不一致，所以 P0 一律不接受 `%`，佔位直接寫成 `{id}`（OAS 規格中的範例也是這樣寫）。不以 `#` 開頭的（`http:`、`file:`、`./other.yaml`、`urn:`…）回 422 `EXTERNAL_REF_FORBIDDEN`；`#foo` 這類 anchor 形式、`#` 本身與含 `%` 的回 422 `UNSUPPORTED_SCHEMA`；指不到節點的回 422 `INVALID_SPEC`。
  - 不可形成只由參照組成的循環（`A → B → A`）：工具解析時會無窮迴圈。schema 的遞迴（屬性引用自己）不受影響。
  - 參照鏈最多 32 層。檢查時記住已確認的鏈還剩幾層，很多參照共用同一條鏈時，每條鏈只走一次；還沒確認的鏈走到上限就停（審查發現：原本每個參照都重走整條鏈）。陣列索引最多 9 位數（`int()` 不處理超過 4,300 位的字串，原本會變成 500）。
  - `discriminator.mapping` 的值只接受 `#/components/schemas/<名稱>`，而且必須存在。只寫名稱（`Dog`）回 422 `UNSUPPORTED_SCHEMA` 並提示改寫；其他不以 `#` 開頭的值回 `EXTERNAL_REF_FORBIDDEN`。理由：OAS 規定 mapping 的值可以是名稱或 URI reference，名稱本身又可以長得像 URL，工具可能把它當成參照去抓（審查發現）。
  - **會被拒絕的物件不能透過 `$ref` 繞過**（審查發現）：security scheme（oauth2／OIDC）、response（其中的 link）與 link（`server`）都是要檢查內容的物件；這些位置的 `$ref` 只能指向 `#/components/<同一個區段>/<名稱>`，否則回 `UNSUPPORTED_SCHEMA`。`components` 中的每一項都會被檢查，轉一手也繞不過；同一個物件中 `$ref` 以外的欄位照樣檢查。
  - 一律拒絕 `externalValue`，以及 `$id`、`$schema`、`$anchor`、`$dynamicRef`、`$dynamicAnchor`、`$recursiveRef`、`$recursiveAnchor`：前者會讓工具去抓外部的範例，後者會改變 JSON Schema 工具解析參照的基準。
  - 「任何位置」：寧可誤拒，也不讓某個工具把它當成參照。代價是 example 中剛好有 `$ref` 這個 key 的規格也會被拒絕。
- **servers 一律改綁成 target 的 origin 加 base path**（SEC-02 的「固定綁定到核准 origin」）：
  - base path 取自 server URL 的 path，去掉結尾的 `/`；沒有 `servers` 或是空陣列時為空（OAS 的預設是 `/` [S59]）。
  - URL 必須是 `http(s)://主機/…` 或以 `/` 開頭的 path；不可有變數（`{…}`）、query 或 fragment。所有 server 的 base path 必須相同。
  - 原本的 host 一律丟掉，也不出現在回應與錯誤訊息中（可能含帳密）。正規化文件的 `servers` 只剩一個：`[{"url": "<target origin><base path>"}]`。
  - 例：VAmPI 的 `http://localhost:5000` 綁成 target 的 `http://vampi-vuln:5000`。
- **平台本身不做任何 I/O**：解析與正規化都是純函式，不連網、不讀檔；單元測試以 pytest-socket 封鎖網路，另把 socket 與 `open` 換成會失敗的版本確認。
- **已知限制**：
  - 不展開參照，所以擋不了「參照炸彈」（多層 `allOf` 互相引用，展開後指數成長）。平台本身不展開；M3 的工具容器有記憶體與時間上限，屆時量測工具的實際行為。
  - JSON Schema draft-04 的 `id`（`$id` 的舊名）不拒絕：`id` 是很常見的屬性名稱與 example 欄位，在任何位置拒絕會誤拒大多數的規格。工具是否把 schema 中的 `id` 當成解析參照的基準，在 T14 量測。
  - `externalDocs`、`info.termsOfService`、`contact.url`、`license.url` 等說明用的 URL 原樣保留：平台不連線，工具通常也不會去抓；報告中要安全編碼（T21）。

### 11.5 正規化文件、儲存與版本

- **正規化文件**：以 key 排序、沒有空白的 canonical JSON 保存（`servers` 已改綁）。同一份內容不論以 JSON 或 YAML 上傳，`document_sha256` 都相同；另存上傳檔的 sha256、大小與格式，使用者可以核對自己上傳的是哪一個檔案。
- **存在 DB**（`api_specs.document`，`bytea`）：DB 以 CHECK 確認 `sha256(document) = document_sha256` [S67]。`ARCHITECTURE.md` §6 原本規劃「受控 storage key」，但 artifact storage 要到 M3 才有；存在 DB 可以和 inventory、audit 在同一個 transaction 寫入，不會留下孤兒檔案，大小也有上限（2 MiB）。M3 有 artifact storage 之後再檢討。
- **不可變**：建立後不可修改、不可刪除（trigger 擋下 UPDATE、DELETE 與 TRUNCATE，和 grant 一樣只防程式錯誤造成的誤改，§7）。之後的 scan 會引用規格的版本。對既有的規格再 INSERT 新的 operation 不會被擋下：repository 只在建立規格的同一個 transaction 中寫入 inventory，T09 凍結 scan 的範圍時也會一併保存 operation 的清單。
- **版本**：每個 target 各自的流水號；上傳時先以 `FOR UPDATE` 鎖住 target 再取下一號（同 grant 的申請，§10.4）。解析在上鎖之前完成，不拖長鎖住 target 的時間。
- **數量上限**：每個 target 最多 20 個版本，超過回 409 `QUOTA_EXCEEDED`。理由同 §10.9：不能刪除，一把外洩的 operator key 才不能無限寫入（上界約 100 個 target × 20 × 2 MiB）。

### 11.6 operation inventory 與 path 比對

- **inventory**：每個 operation 一列，包含 method（大寫，含 TRACE）、完整 path 與 operationId，依 path、method 排序。被排除或不在範圍內的 operation 也照樣列出，並附上原因（contract §5：報告要顯示哪些操作未測及理由）。
- **route 層級的比對**（`grants/domain/matching.py`）：pattern（grant 的 path）「涵蓋」route（規格的 path）的條件：
  - 段數相同。
  - pattern 的佔位涵蓋任何一段；pattern 的 literal 只涵蓋相同的 literal，不涵蓋 route 中的佔位（`/users/v1/_debug` 不涵蓋 `/users/v1/{username}`，因為後者還包含其他 path）。佔位的名稱不影響比對。
  - **允許**：大小寫與結尾的斜線都必須一致。
  - **排除**：不分大小寫、忽略結尾的斜線，至少和伺服器一樣寬（§10.8）。
  - 兩者都不從前綴推論：排除 `/api/admin` 不包含 `/api/admin/{id}`，子路徑要另外列出。理由：與 contract §4「完整的 literal path」一致；以前綴推論會讓排除 `/users/v1` 時連帶排除整個使用者 API。
  - 允許往窄、排除往寬，都是安全的一側。M2 的 guard 以同一個函式比對實際的請求（請求的 path 全是 literal）。
- **eligible 與原因**，依序判斷：
  1. `PATH_EXCLUDED`：被任一 `excluded_paths` 涵蓋。
  2. `METHOD_NOT_AUTHORIZED`：method 不在 `allowed_methods`（TRACE 一定不在）。
  3. `PATH_NOT_AUTHORIZED`：沒有 `allow_all_paths`，也沒有被任一 `allowed_paths` 涵蓋。
  都不是才 eligible。
- **預覽**：`GET /api-specs/{id}/operations?scope_grant_id=` 以那個 grant 判斷；grant 必須屬於同一個 target（否則 422），grant 的任何狀態都可以預覽。不帶參數時 `eligible` 與 `reason` 為 null。eligible 只表示「在範圍內」，grant 能不能拿來掃描仍由掃描 gate 判斷（§10.6）。T09 建立 scan 時以同樣的規則凍結 eligible 的 operation。

### 11.7 模組與分層（更新 §10.7）

```text
main | cli → migrations → health | specs → grants → targets → projects → api_keys → audit → security → core
```

| 模組 | 為什麼在這一層 |
|---|---|
| specs | 上傳時要鎖住 target、取得 origin；預覽 inventory 時要讀 grant，並用 grants 的比對規則 |

- specs 的 domain 使用 PyYAML（只用純 Python 的事件 API），仍不得依賴 Web 框架、DB 與 Docker。
- 兩個 middleware：大小上限在 `core/body_limit.py`；key 格式的檢查在 `api_keys/middleware.py`（要用 key 的格式與 401 的回應）。

### 11.8 錯誤碼

| HTTP | code | 情況 |
|---|---|---|
| 413 | `SPEC_TOO_LARGE` | 規格超過 1 MiB，或正規化後超過 2 MiB |
| 413 | `REQUEST_TOO_LARGE` | 任何請求超過 2 MiB（middleware） |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | 上傳的 Content-Type 不是 JSON 或 YAML |
| 408 | `REQUEST_TIMEOUT` | 上傳的規格沒有在 10 秒內讀完（審查後補上） |
| 400 | `INVALID_REQUEST` | 上傳途中斷線（沿用既有的錯誤碼） |
| 422 | `INVALID_SPEC` | 不是合法的 JSON／YAML、編碼錯誤、重複的 key、超過深度或數量上限、缺少必要欄位、path 或 operationId 不合規則、懸空的參照 |
| 422 | `UNSUPPORTED_SCHEMA` | P0 不支援的功能：版本、YAML 的 anchor／tag、`callbacks`、path 層級的 servers、oauth2… |
| 422 | `EXTERNAL_REF_FORBIDDEN` | 參照或 discriminator 的 mapping 指向文件以外 |

### 11.9 不在 T07 範圍

- 建立 scan 時綁定規格的版本與 `document_sha256`、凍結 eligible 的 operation：T09。
- guard 比對實際的請求（先拒絕 `%2e`、`;`、`//` 等寫法）：T11。
- 交給工具的規格（只含 eligible 的 operation）、量測參照炸彈與工具的實際行為：T14。
- 規格的刪除或封存、速率限制、報告中規格文字的安全編碼：T21、T23。
- OpenAPI 3.1、Swagger 2.0、servers 的變數、跨段的佔位、`oauth2`：P1 以後。

何時重新檢討：
- lab 的規格超過 1 MiB 或 1,000 個 operation：依量測放寬，並在這裡記錄。
- 規格需要經常修改、20 個版本不夠：加上刪除或封存（必須保留 scan 引用的版本）。
- 合法的規格因為「任何位置的 `$ref`」或 YAML 的限制被拒絕：記下實例，再決定是否只在特定位置檢查。

T08 加入 auth_profiles 模組，更新後的順序見 §12.7。

## 12. T08 補充決定：auth profile 與 secret 生命週期（2026-10-25）

T08 實作 `PROJECT_PLAN.md` §5.1 的「目標認證」：靜態 Bearer、API key header、既有 Cookie，加密、只寫不讀、以受保護的端點做 preflight。目標的憑證是平台保存的資料中最敏感的一類：DB dump、備份、log、API 回應與 audit 都不能出現明文。以下是規劃文件沒有寫到、實作前才定下的細節。

其中兩項由使用者決定（2026-10-25）：
- 建立新版本時，清除上一版的密文（§12.3）。
- 停用 profile 的端點延後到 T21（§12.6）。

T08 不發出任何流量：preflight 只定義、不執行，T12 才會實際執行。

依據：
- VAmPI 的 `GET /me` 回 `{"data": {"admin", "email", "username"}, "status"}`，是巢狀結構（`tests/fixtures/openapi/vampi-openapi3.yml`）。
- lab 的 VAmPI token 一小時就過期（`compose.lab.yaml` 的 `tokentimetolive: 3600`，`TOOLS.md` §5），每次掃描前都要換 token：更新 secret 會很頻繁。
- `cryptography` 50.0.2：2026-09-30 發布，授權 Apache-2.0 OR BSD-3-Clause，有 macOS arm64 的 abi3 wheel，另依賴 cffi ≥ 2.0.0 [S71]。

### 12.1 加密與金鑰

| 項目 | 採用 | 理由 |
|---|---|---|
| 加密元件 | `security/secret_cipher.py` 的 `SecretCipher` 包裝 MultiFernet：`seal(value, context)`、`reveal(token, context)`、`rotate(token, context)` | CLAUDE.md §9 指定 MultiFernet。Fernet 是 AES-128-CBC 加 HMAC-SHA256，竄改或用錯金鑰都會被偵測；MultiFernet 以第一個金鑰加密，依序嘗試每個金鑰解密 [S69][S70] |
| 綁定 | 加密的內容是 `{"context": "auth_profile:<profile id>:<type>:<header_name 或 ->", "v": 1, "value": <secret>}`；解密時 context 不符就拒絕。context 最長 129 字元，`SecretCipher` 的上限是 256 | Fernet 沒有 associated data。能寫 DB 的人把 A 的密文搬到 B，B 會解不開。也綁送出的方式（審查後補上）：同一個 profile 內，把 bearer 版本的密文搬到 cookie 或另一個 header 名稱的版本，也解不開。不綁版本：新版本沿用 secret 時 type 與 header 名稱一定相同（§12.6），直接複製密文，API 不必解密 |
| 金鑰設定 | `SECRET_ENCRYPTION_KEYS`：逗號分隔的 Fernet 金鑰（url-safe base64 的 32 bytes，44 個字元），1–4 個、不可重複，不可有空白。第一個用來加密，其餘只用來解密 | CLAUDE.md §9「密鑰不放資料庫或 Git」。最多 4 個：換版只需要新舊兩個 |
| 金鑰放在哪裡 | 和 DB 密碼一樣放在 `.env`：`make env` 在缺少時以 `openssl rand -base64 32` 轉成 url-safe 產生一把（只附加，不印出值、不修改既有的值）；`make dev` 也先執行 `make env` | M1 是單一信任區（§7、§9.1）。加密擋得住 DB dump、備份與 SQL injection 讀到的密文。M2 容器化時改用 compose `secrets:`，把金鑰和 DB 帳密分開 |
| 在哪裡檢查 | `Settings` 只以 `SecretStr` 讀入、可以沒有；`create_app` 沒有金鑰或格式不合就啟動失敗，訊息不含金鑰。CLI 的 `create-admin-key` 不需要它 | API 沒有金鑰就不能加密，fail fast；只有用得到的程序才要求它 |

取捨：
- **API 程序持有能解密的金鑰**：Fernet 是對稱加密，能加密就能解密。所以加密擋得住 DB 的外流，擋不住 API 程序本身被入侵，這點不宣稱。程式中沒有解密的路徑（§12.2）；M2 的 runner 會是另一個程序。
- **token 中的建立時間是明文** [S69]：DB 本來就存了 `created_at`，可以接受。
- **金鑰遺失，所有 secret 都解不開**：只能重新設定。這些都是 lab 測試帳號的 token，可以重新登入取得；README 提醒備份 `.env` 中的這一行。

### 12.2 只寫不讀與不寫入 log

- **沒有讀回 secret 的方式**：
  - 回應、audit、log 都沒有 secret，也沒有由它衍生的值。不存 hash：cookie 的值可能是低熵的，hash 會被暴力猜出。
  - API 從不解密：新版本沿用 secret 時，直接複製密文。
  - 以 AST 測試固定：src 中沒有任何模組呼叫 `reveal`（做法同 §9.1 的 `issue_admin_key`）。M2 的 runner 會是唯一的例外，屆時更新測試。
  - 以 import-linter 固定：只有 `security.secret_cipher` 可以 import `cryptography`，其他模組無法繞過 `SecretCipher` 自己解密（含間接 import）。
- **audit 中的 preflight**：記錄 method、path、expected_status 與 JSON Pointer，不記期望值。path 是實際會送出的請求，T09 要拿它和 grant 比對、事後也要能追查，所以照原樣記錄，和 grant 的 path 相同；它可能含帳號名稱（例如 `/users/v1/name1`，審查時指出）。期望值是用來辨識身分的回應內容（帳號、email），不是請求的一部分，所以不記。
- **最小權限**（審查後補上）：只有建立與 PATCH 的路由拿到加密元件；查詢的路由與 service 沒有它，在查詢的 service 上呼叫寫入的方法，會在動到 DB 之前就失敗。
- **不寫入 log**：
  - 請求中的 `secret` 是 `SecretStr`（API 文件標成 writeOnly），domain 物件的 repr 不含它；版本列帶出的密文（`StoredSecret`）repr 也不含 token。
  - 驗證錯誤不回顯任何輸入，沿用 T04 的 422 處理與 §10.2 的原則。`expected_json` 的 key 與值在 domain 檢查，不在 schema：Pydantic 檢查 dict 的 key 時，錯誤的欄位位置（`loc`）會帶出那個 key（審查發現），domain 的訊息只說是第幾項。
  - engine 已設定 `hide_parameters`，SQL 參數不出現在例外與日誌中（`ARCHITECTURE.md` §6.2）。
  - 關閉 FastAPI 內建的 OpenTelemetry（tracing、metrics、logs 與自動設定）：它會匯出驗證錯誤與例外，可能含請求中的 secret。平台不使用它，也不隨環境中的 provider 或 `FASTAPI_OTEL_AUTO_CONFIGURE` 開啟。
  - 測試以 canary 檢查回應、DEBUG 等級的所有 log、audit、DB 中的明文與例外訊息。

### 12.3 換版

**加密金鑰**：
- `secscan-admin rotate-secret-keys`：
  - 在一個 transaction 內，先依 id 的順序以 `FOR SHARE` 鎖住所有 profile，再以 `FOR UPDATE` 鎖住所有密文（鎖的順序見下面）。
  - 以 MultiFernet.rotate 改用第一個金鑰重新加密（保留原本的時間戳記 [S69]），並確認 context 仍然相符。
  - 任何一份解不開就全部回滾、exit 1，訊息只列出 profile id；成功時寫一筆全域 audit。
- 流程（Fernet 文件的做法：新金鑰放最前面、rotate 既有的 token、再移除舊金鑰 [S69]）：
  1. 新金鑰放在第一個，重啟 API：新的 secret 改用新金鑰加密，舊的仍解得開。
  2. 執行 `rotate-secret-keys`。
  3. 移除舊金鑰，重啟 API。
  4. 再執行一次 `rotate-secret-keys`，確認全部解得開。

  第 4 步通過之前，另外保留舊金鑰的備份：萬一有一份密文沒換到，還能放回舊金鑰再做一次。

**profile 的版本**：
- `PATCH` 產生新版本，version 是每個 profile 各自的流水號；舊的 scan 快照不受影響（`API_CONTRACT.md` §2）。
- **建立新版本時清除上一版的密文**（使用者的決定）：secret 只存在於目前的版本，換掉就消失；token 頻繁更換時，舊 token 不會累積。
  - DB 以部分唯一索引保證每個 profile 最多一份密文 [S74]。
  - 舊版本只留定義（type、header 名稱、preflight），回應中是 `secret_configured: false`。
- trigger：版本列只允許兩種 UPDATE，而且其他欄位都不能改：
  - 清除：密文變成 NULL，同時記下 `secret_erased_at`。清除之後不能恢復。
  - 重新加密：密文換成另一份非 NULL 的密文（金鑰換版）。
  - INSERT 必須帶密文；DELETE 與 TRUNCATE 一律拒絕。profile 本身的列完全不可變。
- `secret_erased_at` 用 `statement_timestamp()`，不用 `now()`（審查後修正）：`now()` 是 transaction 開始的時間；PATCH 等鎖期間，另一個 PATCH 建立的版本會比它晚建立，清除時間就會早於建立時間。
- **鎖的順序**：PATCH 與金鑰換版都是先鎖 profile、再鎖版本列，所以不會互相等待而死結，而且兩個方向都互斥：
  - PATCH 以 `FOR UPDATE` 鎖住 profile（版本號依 commit 的先後遞增），再鎖目前的版本列，才讀它的密文。換版還沒 commit 時，PATCH 在鎖 profile 時就會等它，複製到的就是新金鑰加密的密文。版本列的鎖是第二道防線：沒有先鎖 profile、只改版本列的寫入（例如直接以 SQL 重新加密），PATCH 也會等它，不會複製到舊的密文。
  - 換版以 `FOR SHARE` 鎖住所有 profile（審查後補上）。PATCH 還沒 commit 時，換版會等它；否則換版看不到 PATCH 新增的版本，那份以舊金鑰加密的密文會留下，移除舊金鑰後就解不開。

取捨：
- 排隊中、綁定舊版本的 scan：版本被取代後密文已清除，runner 啟動前就會失敗（fail closed），不自動改用新版本（T09、M2）。
- 能寫 DB 的人仍能清除密文（trigger 允許這個轉換）：結果是 scan 失敗，不會洩密。和其他 trigger 一樣只防程式錯誤造成的誤改（§7）。
- **清除只是邏輯上的**：PostgreSQL 的 UPDATE 留下舊的 tuple，直到 VACUUM 回收；WAL 與備份中也還有舊的密文。所以清除不等於從磁碟抹除，舊密文仍受加密金鑰保護。secret 真的外洩時，要到目標系統讓它失效（lab 重新登入換 token），不能只靠清除。

### 12.4 認證類型與 secret 的格式

| type | 送出的 header | secret 的規則 |
|---|---|---|
| `bearer` | `Authorization: Bearer <secret>` | RFC 6750 的 b64token：英數字與 `-._~+/`，結尾可以有 `=` [S72]；1–4,096 字元。不含空白：不要自己加上 `Bearer ` |
| `api_key_header` | `<header_name>: <secret>` | ASCII 可見字元，中間可以有空白；1–4,096 字元。RFC 9110 允許的 obs-text 與 tab 都不收 [S64] |
| `cookie` | `Cookie: <secret>` | RFC 6265 的 cookie-string，例如 `a=1; b=2`：名稱是 token，值是 cookie-octet，可以整個加上雙引號 [S73]；1–32 個，名稱不可重複；最多 4,096 字元 |

- **只接受嚴格的子集**：不同的伺服器與工具對邊緣的寫法解讀不同（例如重複的 cookie 名稱，RFC 6265 §4.2.2 說伺服器不應依賴它們的順序 [S73]）。字元集本身就排除 CR、LF 與 NUL，擋下 header injection [S64]。
- **平台 key 誤貼**：secret 含平台 API key 的樣式（`secscan_<prefix>_<secret>`）就拒絕。平台 key 不可送往被測網站（`API_CONTRACT.md` §1）。
- **header 名稱**（只用於 `api_key_header`）：
  - 只能用英文字母、數字與 `-`，每段以英數字開頭，最多 64 字元。這是 RFC 9110 token 的子集 [S64]，避開 `_`、`.` 這類在某些伺服器會被改寫或丟掉的字元。
  - 可以用 `Authorization`，給非 Bearer 的 scheme，例如 `Token …`。
  - 下表的名稱一律拒絕，不分大小寫：

| 類別 | 拒絕的 header | 理由 |
|---|---|---|
| 連線與訊息框架 | Host、Connection、Keep-Alive、Proxy-Connection、TE、Trailer、Transfer-Encoding、Upgrade、Expect、`Content-*` | contract §6；RFC 9110 §7.6.1 的 connection-specific 欄位 [S64] |
| 代理 | Proxy、`Proxy-*`（含 guard 用的 Proxy-Authorization） | 會干擾 guard；`Proxy` 在 CGI 一類的環境變成 `HTTP_PROXY`，讓伺服器把對外的請求送往指定的代理（httpoxy [S77]） |
| 路由與來源 IP | Forwarded、Via、Max-Forwards、X-Forwarded、`X-Forwarded-*`、X-Real-IP、X-Client-IP、True-Client-IP、X-Cluster-Client-IP、Client-IP、CF-Connecting-IP、X-Originating-IP、X-Remote-IP、X-Remote-Addr | 會干擾 guard 或上游判斷請求的來源（例如以來源 IP 放行的管理介面） |
| 改寫 host、method 或 path | X-Host、X-HTTP-Host-Override [S78]；X-HTTP-Method-Override、X-HTTP-Method、X-Method-Override [S75]；X-Original-URL、X-Rewrite-URL [S76]、X-Original-URI、X-Envoy-Original-Path | 有些框架或代理照這些 header 改 host、method 或路由，會繞過 grant 的 origin、method 與 path 範圍 |
| 其他 | Cookie、Set-Cookie；`X-Secscan-*` | Cookie 用 cookie 類型；`X-Secscan-*` 保留給平台 |

審查後補上的：Proxy、X-Forwarded、X-Client-IP 到 X-Remote-Addr 這 8 個來源 IP 的 header、X-Host、X-HTTP-Host-Override、X-Original-URI、X-Envoy-Original-Path。取捨：拒絕清單不保證完整。主要的防線是嚴格的字元集；實際送出的 header 由 M2 的 guard 檢查。

### 12.5 preflight

- **必填**：CLAUDE.md §9 要求掃描前以已知的受保護端點做 auth preflight。
- **規則**：
  - `method` 只接受 `GET`：preflight 不可改變靶場的狀態。
  - `path`：語法同 grant 的 path（§10.3），但不可有 route 佔位：preflight 是實際送出的請求。它是相對於 target origin 的完整 path（含 base path），method 與 path 的寫法和 inventory 相同（§11.6），T09 可以直接拿 grant 的規則判斷它是否在範圍內。
  - `expected_status`：200–299 的整數。
  - `expected_json`：1–16 項。key 是 JSON Pointer [S61]，必須以 `/` 開頭、`~` 只能接 `0` 或 `1`、最多 256 字元；值是字串（最多 256 字元）、整數（±(2^53 − 1)，RFC 8259 §6 中各家實作一致的範圍 [S62]）、布林或 null。
- **為什麼一定要比對內容**：只看狀態碼分不出登入頁（「200 且回登入頁不能算認證成功」，`API_CONTRACT.md` §6）。VAmPI 的 `/me` 是巢狀的，所以 key 用 JSON Pointer，不只比對最外層。
- **比對的語意**（T08 只定義與驗證，T12 照著實作）：
  - 嚴格相等，型別也要相同：`true` 不等於 `1`，期望值沒有浮點數。
  - JSON Pointer 依 RFC 6901 解析，含陣列索引；指不到就不符合。陣列索引有前導 0（如 `01`）或是 `-`（指向最後一個之後、不存在的元素 [S61]）都算指不到。
  - 回應必須是 JSON；所有項目都符合，而且狀態碼相同，才算成功。

### 12.6 role_label、名稱、上限與權限

- **role_label**：`^[a-z][a-z0-9_]{0,63}$`；`anonymous` 保留給未認證的 scan（`API_CONTRACT.md` §7）。同一個 target 內唯一，重複回 409 `AUTH_ROLE_CONFLICT`。理由：role_label 是 finding fingerprint 中的 auth role（CLAUDE.md §10），兩個 profile 同名，不同身分的結果會混在一起。
- **名稱**：1–100 字元，規則同 §10.10。
- **不可修改**：role_label 與名稱建立後都不能改；要改就建立新的 profile。
- **PATCH 的規則**：
  - 欄位都可以省略，但至少要有一個；不接受 null（同 target 的 PATCH）。
  - 沒給的欄位沿用目前的版本；`preflight` 是整份取代。
  - `type` 或 `header_name` 改變時，必須附上新的 secret；`secret` 省略時直接複製目前的密文。
  - 完全沒有變更（沒有 secret，定義也相同）回 422。
- **數量上限**：每個 target 10 個 profile、每個 profile 100 個版本，超過回 409 `QUOTA_EXCEEDED`。理由同 §10.9、§11.5：不能刪除，一把外洩的 operator key 才不能無限寫入。舊版本不含密文，只有定義：preflight 的期望值以字元計算上限，全用 4 bytes 的字元時每列約 33 KB（DB 的 CHECK 上限是 64 KiB），一般不到 1 KB。
- **權限**：建立與 PATCH 要 `PROJECT_WRITE`（operator、admin），查詢要 `PROJECT_READ`；其他 project 一律和不存在的一樣回 404（§9.2）。停用的 target 仍可設定：設定不會送出任何流量。
- **停用 profile**（使用者的決定）：T08 不做，延後到 T21。要移除外洩的 secret，就用新版本取代，舊密文立刻清除。

### 12.7 模組與分層（更新 §11.7）

```text
main | cli → migrations → health | specs | auth_profiles → grants → targets → projects → api_keys → audit → security → core
```

| 模組 | 為什麼在這一層 |
|---|---|
| auth_profiles | 建立 profile 要鎖住 target，並由 target 得知所屬的 project。不需要 specs 與 grants：preflight 是否在 grant 的範圍內由 T09 判斷 |

- security 加入 `cryptography`（MultiFernet）；仍不得依賴 Web 框架、DB 與 Docker。整個 `secscan` 只有 `security.secret_cipher` 可以 import `cryptography`（import-linter 的第三個 contract，§12.2）。
- CLI 的 `rotate-secret-keys` 用 auth_profiles 的 repository。

### 12.8 錯誤碼

| HTTP | code | 情況 |
|---|---|---|
| 409 | `AUTH_ROLE_CONFLICT` | 同一個 target 已有相同 role_label 的 profile |
| 409 | `QUOTA_EXCEEDED` | 每個 target 的 profile 數，或每個 profile 的版本數已達上限（沿用既有的錯誤碼） |
| 422 | `INVALID_REQUEST` | secret、header 名稱、preflight、role_label、名稱或 PATCH 的規則不合；訊息說明欄位與原因，不回顯輸入（沿用既有的錯誤碼） |

### 12.9 不在 T08 範圍

- 建立 scan 時綁定 profile 的最新版本、檢查 preflight 是否在 grant 的範圍內、未認證的 scan 標記為 anonymous：T09。
- runner 解密並注入 secret（環境變數或 0400 檔，run 結束刪除）、綁定的版本已被取代時啟動前就失敗：M2。
- guard 只把 secret 送往 target 的 origin、跨 origin 的 redirect 移除 Authorization、Cookie 與自訂的 header；執行 preflight 並計入預算：T11、T12。
- 確認三個工具注入 `api_key_header` 與 `cookie` 的方式；證據與報告中以已知的 secret 值精確遮罩：M3。
- 停用 profile、舊版本的封存：T21。速率限制、DDL 與 DML 角色分開：T23。
- OAuth2／OIDC、自動登入與 refresh token、HTTPS 目標：P1 以後。

何時重新檢討：
- 需要 OAuth2 或自動登入：改成由 runner 取得 token，平台只保存登入用的 secret，並重新設計換版與遮罩。
- 每個 profile 100 個版本不夠（例如 token 很快過期、掃描次數很多）：先檢討 lab 的 token 有效期，再考慮封存舊版本。
- 金鑰需要和 API 程序分開（例如 API 對外開放）：改成 runner 才持有解密的金鑰，API 只加密（需要非對稱加密，不再是 MultiFernet）。

## 13. T09 補充決定：scan、工作佇列、idempotency 與 FakeRunner（2026-10-26）

T09 建立 `POST /scans` 與 PostgreSQL 工作佇列（§3），完成 M1：不用真的工具，也能從 API 建立受控的 scan、查詢狀態與事件，並得到 fake runner 明確標記的結果。以下是規劃文件沒有寫到、實作前才定下的細節。

使用者的決定（2026-10-26）：**只開放 fake 引擎**。zap、nuclei、schemathesis 在 Adapter 真正整合之前回 422（§13.1）。

T09 不發出任何流量：fake 引擎與 FakeRunner 都不連任何位址，也不啟動 lab。

依據：
- IETF Idempotency-Key 草案 -08 [S79]：header 是 Structured Field 的 Item，值是 String（範例有雙引號）；缺少 key 時 SHOULD 回 400；同一個 key 搭配不同內容 SHOULD 回 422；同一個 key 的請求還在處理時 SHOULD 回 409；唯一的範圍與保存期限由資源定義；可以搭配由請求內容產生的 fingerprint。
- PostgreSQL 的鎖 [S28][S57]：`SKIP LOCKED` 適合多個 consumer 的佇列型資料表，但看到的資料不一致；指定 `FOR UPDATE OF` 的資料表時只鎖那些資料表的列；READ COMMITTED 下 `ORDER BY` 搭配鎖，可能回傳排序欄位已被改過的列。
- PostgreSQL 的逾時 [S80]：`statement_timeout`、`lock_timeout`、`idle_in_transaction_session_timeout` 預設都關閉；不建議寫在 postgresql.conf（影響所有 session）；`lock_timeout` 對每次取鎖分別計算，大於或等於 `statement_timeout` 就沒有意義。錯誤碼：55P03 `lock_not_available`、57014 `query_canceled`、25P03 `idle_in_transaction_session_timeout` [S81]。
- PostgreSQL 的 identity 欄位與多欄 FK [S82]：`GENERATED ALWAYS AS IDENTITY` 的值不能由 INSERT 指定（除非 `OVERRIDING SYSTEM VALUE`），UPDATE 也不能改；多欄 FK 預設是 MATCH SIMPLE，任何一欄是 NULL 就不檢查。

### 13.1 建立 scan

| 項目 | 採用 | 理由 |
|---|---|---|
| 引擎 | zap、nuclei、schemathesis、fake。T09 只有 `fake` 可用，其他回 422 `ENGINE_UNSUPPORTED`，訊息說明在哪個里程碑整合。fake 必須單獨使用；執行順序固定為 zap → nuclei → schemathesis，與請求中的順序無關 | DB 不會出現「zap 成功、其實沒跑 ZAP」的紀錄（CLAUDE.md §3：Mock 不等於 Adapter 完成）；fake 和真引擎混用會污染結果。M2 的 fake 掃描容器沿用這個引擎 |
| scan profile | `api_active_lab`：必須有規格、target 是 api 或 hybrid、至少一個 operation 在 grant 的範圍內。`web_active_lab`：不帶規格、target 是 web 或 hybrid。不符合回 422 `PROFILE_INCOMPATIBLE` | contract §7 的 profile 是必填；`ARCHITECTURE.md` §8：缺少必需的規格、profile 不相容，在建立時就回 422。名稱沿用 contract 的範例，M3 依 ZAP 實際的設定調整 |
| 預算 | 可省略；省略的項目用 grant 的值，每項不可超過 grant 的值（422）。存在 scan 上，M2 的 guard 強制 | contract §7。T09 不量測用量 |
| 快照 | 以引用不可變的資料為主：複合 FK 指向 target（含 project）、grant、規格、auth profile（含 role_label）與 profile 的版本；另外凍結 target 的 origin；`scan_operations` 保存每個 operation 與建立當時的判斷（在範圍內，或不在的原因）。不複製 grant 的範圍 | grant 的範圍、規格與 inventory、profile 的版本都已由 trigger 保證不可變，複製只是重複。targets 沒有 trigger，所以凍結 origin。inventory 的 INSERT 沒有被擋（§11.5），而且 coverage 的分母要和建立時的判斷一致，所以另存 operation |
| 一個 target 只有一個進行中的 scan | 部分唯一索引 `uq_scans_active_target`（狀態是進行中的）[S74]。先查一次，給出清楚的 409 `TARGET_BUSY`；同時建立時以索引為準 | `ARCHITECTURE.md` §6.1；初版同一個 target 依序執行（CLAUDE.md §4） |
| 數量上限 | 每個 target 在 24 小時內最多 50 個 scan，超過回 409 `QUOTA_EXCEEDED` | scan 不能刪除，每個最多帶 1,000 列 operation；理由同 §10.9，速率限制在 T23。M7 的實驗每個 target 約 15–25 次 |
| 權限 | 建立與取消要 `PROJECT_WRITE`（operator、admin），查詢要 `PROJECT_READ`；其他 project 的 scan，以及以其他 project 的 target、grant、規格、profile 建立，一律和不存在的一樣回 404（§9.2） | 同其他功能 |
| 回應 | 新建立與重送都回完整的 scan（和 `GET /scans/{id}` 相同）。contract §7 原本只回 `scan_id`、`status`、`status_url` | 和其他資源的建立一致；client 不必再查一次 |

### 13.2 Idempotency-Key

| 項目 | 採用 | 理由 |
|---|---|---|
| header | 必填：16–128 個英數字、`-`、`_`（UUID 可用）；也接受加上雙引號的寫法，兩者視為相同。缺少、重複或格式不符回 400 `INVALID_REQUEST`，訊息不回顯 | 400 依草案 [S79]；只收安全的字元，避免日誌注入與歧義 |
| 範圍與保存 | 唯一範圍是 (project, key)，永久保存（scan 不能刪除） | 不同 project 的 key 互不影響，也不洩漏其他 project 用過哪些 key。草案讓資源自己定義期限 [S79] |
| 內容的比對 | fingerprint 是請求內容的 canonical JSON（key 排序、沒有空白）的 SHA-256。engines 先排序；省略 budget 與 budget 的每一項都是 null 相同。比對的是請求的內容，不是伺服器解析出的值（例如 profile 的最新版本） | 同樣的請求重送，不會因為 profile 換過版本就變成 409 |
| 重送 | 同 key、同內容：回原本的 scan，未終止回 202、已終止回 200；不重新判斷 gate，也不寫入任何東西 | contract §7。重送是要知道「當初那一次的結果」，不是再建立一次 |
| 不同內容 | 409 `IDEMPOTENCY_CONFLICT`，什麼都不寫 | CLAUDE.md §8 與 T09 的 DoD 指定 409；草案建議 422 [S79]，這裡依專案的契約 |
| 同時送出 | 後到的在 target 的鎖上等先到的 commit（§13.3 第 7 步），取得鎖之後先重查 key，再回同一個 scan（重送），不回 409；萬一 target 的鎖沒有排隊（例如直接寫 DB），仍以唯一索引為準 | DB 會把它們排成先後，建立只要幾毫秒；比草案的 409 好用，client 不必重試 |
| 先後 | 權限檢查之後才查 key：viewer 拿已用過的 key 重送也是 403 | 不替沒有權限的呼叫者回傳 scan |

### 13.3 建立時的檢查順序

1. 401（middleware 或 key）→ 413 → 422：schema 的型別與長度；未知的引擎或 profile 名稱也在這裡。
2. 400：`Idempotency-Key` 缺少、重複或格式不符。
3. target：不存在或屬於其他 project 回 404；角色不足回 403。
4. key 已用過：同內容重送（202 或 200）；不同內容 409 `IDEMPOTENCY_CONFLICT`。
5. 引擎與 profile 的規則（只需要 target 的種類與請求本身）：先判斷引擎重複、fake 和其他引擎混用（`INVALID_REQUEST`），再判斷 `ENGINE_UNSUPPORTED`，最後是 `PROFILE_INCOMPATIBLE`。都是 422。
6. 409 `TARGET_BUSY`、409 `QUOTA_EXCEEDED`：在取得任何鎖之前先查一次（審查後補上，見下）。
7. gate（`require_usable`，§10.6）：依序鎖住 target（`FOR NO KEY UPDATE`）與 grant（`FOR SHARE`），之後才取時間。grant 不存在或屬於其他 project 回 404；屬於其他 target 回 422；尚未核准、已撤銷、尚未生效回 403 `SCOPE_NOT_APPROVED`；過期回 403 `SCOPE_EXPIRED`；target 停用回 409 `TARGET_DISABLED`；IP 不在 `LAB_CIDR` 內回 422 `SCOPE_OUTSIDE_LAB`。
   取得鎖之後重查一次 key（同第 4 步）：等鎖期間，同一個 key 的另一個請求可能已經 commit，這時回重送或 409，而不是被第 11 步當成 `TARGET_BUSY`。取捨：等鎖期間 grant 剛好被撤銷時，這個同時送出的請求得到 gate 的錯誤；之後以同一個 key 重送，第 4 步就會回原本的 scan（重送不判斷 gate）。
8. 規格：不存在或屬於其他 project 回 404；屬於其他 target 回 422；沒有任何 operation 在範圍內回 422 `PROFILE_INCOMPATIBLE`。
9. auth profile：以 `FOR SHARE` 鎖住 profile 再讀目前的版本。不存在或屬於其他 project 回 404；屬於其他 target 回 422；目前的版本沒有 secret 回 409 `INVALID_STATE_TRANSITION`（只有直接改了 DB 才會發生）；preflight 不在 grant 的範圍內回 422，訊息附原因（例如 `PATH_EXCLUDED`），不附 path。
10. 預算超過 grant：422。
11. 持有鎖時再查一次 `TARGET_BUSY`、`QUOTA_EXCEEDED`（這一次才是準的）。
12. 寫入時撞到唯一索引（在 savepoint 中寫入）：先重查 key（重送或 409），再判斷 `TARGET_BUSY`。

**撤銷不會被持續的建立請求餓死**（安全審查發現，已重現）：PostgreSQL 的列鎖中，新的 `FOR SHARE` 只要和目前的持有者相容就直接取得，不排在已在等候的 `FOR UPDATE` 後面。原本建立 scan 以 `FOR SHARE` 鎖 target 與 grant，一把外洩的 operator key 平行送出註定失敗的建立請求（例如 `TARGET_BUSY`），就能讓撤銷 grant、停用 target 一直等不到鎖，最後被 `statement_timeout` 中止。改成：
- target 以 `FOR NO KEY UPDATE` 鎖住：同一個 target 的建立彼此排隊（它們本來就因 `uq_scans_active_target` 而依序），grant 的 `FOR SHARE` 同時最多只有一個建立請求持有，撤銷與停用在鎖的佇列中依序取得。NO KEY 和 FK 檢查的 KEY SHARE 相容，不擋其他資料表引用這個 target。
- 忙碌與上限先在取鎖之前查一次：target 忙碌時，請求不持有任何鎖就失敗。
- 速率限制與每把 key 的同時請求上限仍在 T23；在那之前，先撤銷外洩的 key（驗證 key 時不鎖 key 的列，撤銷之後請求立刻得到 401）。

### 13.4 狀態機

**run 的轉換**（`scans/domain/lifecycle.py`；表外一律拒絕）：

| 目前 | 可以轉到 |
|---|---|
| queued | preparing（runner 認領）、cancelled（取消） |
| preparing | running、failed（gate 或 profile 的檢查）、cancelling、interrupted |
| running | collecting、failed、timed_out、cancelling、interrupted |
| collecting | collected、failed、cancelling、interrupted |
| cancelling | cancelled、interrupted |
| collected | normalizing（worker 認領） |
| normalizing | succeeded、failed、collected（lease 過期：解析可以重試） |
| succeeded、failed、timed_out、cancelled、interrupted | 終止，不能再轉換 |

- failed、timed_out、interrupted 必須有錯誤碼，其他狀態不能有。
- 只有 prepare 能讓 run 轉到 running（`advance` 拒絕這個轉換）：誤用時也不會跳過 gate 的重新判斷（審查後補上）。只有要求過取消的 scan，run 才能轉到 cancelling（和 DB 的 CHECK 一致）。
- runner 階段：preparing、running、collecting、cancelling。worker 階段：collected、normalizing。
- 「不再送出流量」：collected、normalizing 或終止。後面的 run 要等前面的 run 都到這個狀態才能被認領：失敗的引擎不擋住後面的引擎，部分結果仍然保留。interrupted 也算：只有確定已停止才能標成 interrupted（T09 的 fake 不發流量；T13 的對帳要先封鎖 guard、確認容器已終止）。

**scan 的狀態**由 runs 的狀態與「是否要求過取消」彙總（純函式 `aggregate()`），和 run 的轉換在同一個 transaction 寫入：
- 還有沒終止的 run：
  1. 要求過取消 → cancelling。
  2. 全部 queued → queued。
  3. 只有 queued 與 preparing（第一個引擎準備中）→ preparing。
  4. 有 run 在 preparing 或 running → running。
  5. 有 run 在 collecting 或 collected → collecting。
  6. 有 run 在 normalizing → normalizing。
  7. 其他（有引擎已經結束、其餘還在排隊）→ running。
- 全部終止：有 interrupted → interrupted；否則要求過取消 → cancelled；有 timed_out → timed_out；全部 succeeded → completed；有 succeeded → partially_completed；其他 → failed。

順序的理由：interrupted 排在最前面，因為它無法證明工作已正常停止。要求過取消、但 runner 沒有確認就遺失（lease 過期）時，也不能說是 cancelled：確認之後才是 cancelled（CLAUDE.md §8；審查發現，原本是 cancelled）。要求取消之後，解析中的引擎仍會解析完，結果保留，但 scan 是 cancelled（使用者要求停止，結果不完整）。以 Hypothesis 檢查：結果和 runs 的排列順序無關；全部終止時一定是終止狀態，否則一定不是；要求過取消、還有沒終止的 run 時一定是 cancelling；cancelling 與 cancelled 一定有取消的要求（和 DB 的 `ck_scans_cancel_matches_status` 一致）；全部終止而且有 interrupted 時一定是 interrupted。

**run 的錯誤碼**（DB 只檢查格式：大寫英文字母、數字與底線；清單在 domain，M2 新增時不必改 migration）：

| 錯誤碼 | 情況 |
|---|---|
| `SCOPE_REVOKED`、`SCOPE_EXPIRED`、`SCOPE_NOT_APPROVED`、`SCOPE_NOT_YET_VALID`、`TARGET_DISABLED`、`SCOPE_OUTSIDE_LAB` | runner 啟動前重新判斷 gate 不通過（對應 §10.6 的原因） |
| `SCOPE_MISMATCH` | grant 不屬於這個 target，或 target 的 origin 和快照不同（只有直接改了 DB 才會發生） |
| `AUTH_PROFILE_SUPERSEDED` | 綁定的 profile 版本已被取代、密文已清除（§12.3） |
| `CREATOR_KEY_REVOKED` | 建立 scan 的平台 key 已被撤銷：外洩的 key 排進佇列的 scan 也不會開始（審查後補上；key 到期不算） |
| `ENGINE_FAILED` | 引擎失敗（T09 只有 fake 的失敗腳本） |
| `LEASE_EXPIRED` | lease 過期，無法證明工作已正常停止 |

### 13.5 工作佇列

| 項目 | 採用 | 理由 |
|---|---|---|
| 認領 | runner 認領 queued、worker 認領 collected。都以 `FOR UPDATE OF scans SKIP LOCKED` 先鎖 scan，再改 run。條件：scan 還沒終止；同一個 scan 中前面的 run 都不再送出流量；runner 認領時 scan 沒有被要求取消；引擎在認領者支援的清單中。依 `scans.queue_position`（identity）先進先出。鎖到之後以新的 statement 再確認一次條件，不符就換下一個 | §3、[S28]。所有改 run 的寫入都先鎖 scan，所以持有 scan 的鎖時 run 不會變；`ORDER BY` 搭配鎖可能用到舊的資料，所以要再確認。`created_at` 是 transaction 開始的時間，不能代表 commit 的先後（T04 的交接），所以另用 identity |
| lease | 認領時寫入 `lease_owner`、`lease_expires_at`（DB 時間加 30 秒）與 `heartbeat_at`；每 5 秒心跳一次延長。每次轉換都要 owner 相同、而且還沒過期（fencing）。過期的 lease 不能延長，也不會被別人接手 | `ARCHITECTURE.md` §9：lease 過期不代表工作已經停止 |
| 時間 | 寫入的時間（lease 的期限、心跳、開始、結束、取消）用 `statement_timestamp()`；判斷 lease 是否過期用 `clock_timestamp()` | 等鎖期間 `now()`（transaction 開始的時間）已經過時（§12.3 的同一個問題）。鎖都在前一個 statement 取得，所以 statement 開始的時間不會早於取得鎖；同一列的幾個欄位用同一個時間，「心跳不早於開始」這類 CHECK 才不會因為微秒的差距失敗 |
| 每個操作一個短 transaction | `scans/queue.py` 的 `ScanQueue`：claim、claim_collected、heartbeat、prepare、advance、reconcile_expired 各自開始與結束 transaction；長時間的工作（掃描、等待）不持有 transaction | 持有 transaction 會卡住撤銷與取消，也會被 `idle_in_transaction_session_timeout` 終止 |
| prepare | 鎖 scan 之後：要求過取消 → cancelling；以 `FOR SHARE` 鎖住 target 與 grant，以 `check_usable()` 重新判斷 gate，origin 也必須和快照相同 → 不通過就 failed；以 `FOR SHARE` 鎖住綁定的 profile 版本，密文已清除 → failed；以 `FOR SHARE` 鎖住建立者的 key，已撤銷 → failed（審查後補上）；都通過 → running。這是唯一能讓 run 開始執行的路徑 | T06、T08 的交接：撤銷 grant、停用 target、PATCH profile、撤銷外洩的 key 之後，排隊中的 scan 在送出流量之前就停下（fail closed） |
| 對帳 | `reconcile_expired(engines)`：lease 過期的 run，runner 階段 → interrupted（`LEASE_EXPIRED`），normalizing → collected（解析可以重試）。T09 只對 fake 的 run 執行 | fake 不發流量、沒有容器，lease 過期就可以確定它已停止；容器的對帳在 T13。只有 parser 可以重試（CLAUDE.md §8） |
| 事件 | `scan_events`：每個 scan 各自的 sequence，在持有 scan 的鎖時取 max + 1，所以依 commit 的順序而且沒有間隔；以 `after_sequence` 輪詢。類型：`scan.created`、`scan.status`、`scan.cancel_requested`、`run.status`。payload 只由 enum 與 id 組成，最多 1 KiB | 全域的序號會因 commit 的先後而讓輪詢漏掉事件。事件是狀態轉換的紀錄，runner 的轉換不寫 audit |

**測試的隔離**：佇列會認領任何排隊中的 run，所以佇列、FakeRunner 與需要 runner 的 API 測試，每個測試從 migrated 的 template 複製一個自己的資料庫（`CREATE DATABASE … TEMPLATE`，沿用 template 的角色，用完刪除），不會認領到其他測試留下的 run（T04 的交接）。

**run 與凍結的 operation 只在建立 scan 時寫入**（審查後補上）：trigger 拒絕在其他 transaction 為既有的 scan 新增 run 或 operation（以 scan 的 `created_at` 等於目前 transaction 開始的時間判斷）。事後加入的 run 會被認領，對已終止的 scan 還會卡住佇列；加入的 operation 會改變 coverage 的分母。認領也排除已終止的 scan。和其他 trigger 一樣只防程式錯誤造成的誤改（§7）。

**鎖的順序**（避免死結）：
- 建立 scan：target（NO KEY UPDATE）→ grant（SHARE）→ profile（SHARE）→ 新增 scan。PATCH profile 以 `FOR UPDATE` 鎖 profile，所以會等建立 scan 的 transaction commit，不會綁到即將被清除的版本；反過來，建立 scan 等 PATCH commit 之後，讀到的是新版本。
- 所有改 scan 或 run 的寫入：先鎖 scan（`FOR UPDATE`），再改 run。prepare 之後再加 target、grant、profile 版本與建立者的 key（SHARE）。
- 心跳只改 run 的列，不等 scan 的鎖。
- 沒有任何 transaction 先鎖 target、grant 再等 scan，所以不會形成循環。

### 13.6 取消

- `POST /scans/{id}/cancel`（`PROJECT_WRITE`）：鎖 scan 之後
  - 已終止：回 200，不改變任何東西，也不寫事件與 audit。
  - 已要求過取消：回 202，不重記。
  - 否則記下 `cancel_requested_at`，排隊中的 run 直接 cancelled，重新彙總；scan 已終止回 200（cancelled），否則回 202（cancelling）。
- runner 階段的 run 由 runner 確認：心跳或 prepare 看到取消 → cancelling → cancelled。worker 階段的 run 繼續解析完：解析不發流量，結果保留。所有 run 都終止之後，scan 才是 cancelled（CLAUDE.md §8：確認後才是 cancelled）。
- 取消無法撤銷已送出的請求或回復靶場的資料（CLAUDE.md §8）；T09 的 fake 不送出請求。

### 13.7 FakeRunner

- `runner/fake.py`：只認領 `fake` 的 run，扮演 runner 與 worker：claim → prepare → running（停留 `hold_seconds`，期間每 5 秒以內送一次心跳：lease 失效就停止；要求取消就 cancelling → cancelled）→ 失敗的腳本 failed（`ENGINE_FAILED`），否則 collecting → collected → 認領自己這個 collected 的 run → normalizing → succeeded。每一步都經過佇列的轉換與事件。
- 回應中的 `fixture` 為 true（有 fake 引擎），`results_complete` 只有 completed 才是 true。T21 的報告、T31 的實驗依 `fixture` 排除。
- CLI：`uv run secscan-admin fake-runner [--outcome succeed|fail] [--hold-seconds 0–300] [--once]`。先確認 DB 就緒，再對帳過期的 fake run、解析留下的 collected，然後處理排隊中的 fake run 直到沒有工作（`--once` 只處理一個）。不需要 `SECRET_ENCRYPTION_KEYS`，不解密任何 secret（`reveal` 仍沒有呼叫者，§12.2）。M2 再建立真的 runner 程序。

### 13.8 DB 逾時（更新 §7）

- 每個連線以 libpq 的 options 設定 `statement_timeout` 30 秒、`lock_timeout` 5 秒、`idle_in_transaction_session_timeout` 60 秒；可用 `DB_STATEMENT_TIMEOUT_SECONDS`、`DB_LOCK_TIMEOUT_SECONDS`、`DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS` 調整，`lock_timeout` 必須小於 `statement_timeout` [S80]。API、CLI、migration 與測試的連線都一樣。
- 等鎖或查詢逾時（55P03、57014 [S81]）回 503 `DEPENDENCY_UNAVAILABLE`，加上 `Retry-After: 1`；伺服器只記例外類別與 SQLSTATE（訊息含 SQL）。其他 DB 錯誤仍是 500。
- 理由：建立 scan 的 transaction 不能無限期卡住撤銷，等鎖逾時也不能變成 500（T04、T06 的交接）。`sslmode` 仍留給 M2。

### 13.9 模組與分層（更新 §12.7）

```text
main | cli → migrations → health | runner → scans → specs | auth_profiles → grants → targets → projects → api_keys → audit → security → core
```

| 模組 | 為什麼在這一層 |
|---|---|
| scans | 建立 scan 要用 gate（grants）、inventory（specs）與 profile 的版本（auth_profiles） |
| runner | 只經 scans 的佇列操作 run；M2 的 Docker SDK 也只在這裡（CLAUDE.md §5） |

- `scans/domain/` 放引擎與 profile 的規則、Idempotency-Key 與 fingerprint、狀態機與彙總、事件的 payload，受「不得依賴框架、DB、Docker」的檢查。
- `ScopeGrantService.require_usable()` 改成收 `clock`，取得 target 與 grant 的鎖之後才取時間（§10.8 的交接）；target 改以 `FOR NO KEY UPDATE` 鎖住（§13.3）。
- scans 依賴 api_keys 的 repository：prepare 確認建立者的 key 沒有被撤銷（分層本來就允許）。

### 13.10 錯誤碼

| HTTP | code | 情況 |
|---|---|---|
| 400 | `INVALID_REQUEST` | `Idempotency-Key` 缺少、重複或格式不符（沿用既有的錯誤碼） |
| 409 | `IDEMPOTENCY_CONFLICT` | 同一個 key 搭配不同的內容 |
| 409 | `TARGET_BUSY` | 這個 target 已有進行中的 scan |
| 409 | `QUOTA_EXCEEDED` | 這個 target 24 小時內的 scan 數已達上限（沿用） |
| 422 | `ENGINE_UNSUPPORTED` | 引擎還沒有整合 |
| 422 | `PROFILE_INCOMPATIBLE` | profile 與 target 的種類、規格不相容，或沒有任何 operation 在範圍內 |
| 503 | `DEPENDENCY_UNAVAILABLE` | 等鎖或查詢逾時（沿用；加上 `Retry-After`） |

### 13.11 取捨與不在 T09 範圍

取捨：
- 只有 fake 可用：多個引擎的依序執行與 `partially_completed` 只能在佇列層，以直接建立的 zap、nuclei 資料列測試；要到 M3、M4 才能從 API 走一遍。
- 撤銷 grant 或停用 target 之後，T09 只在 runner 的 prepare 擋下；已在 running 的 fake run 不會被停止。停止真正的流量在 M2 與 T13（guard 的 policy 改成 blocked）。
- FakeRunner 被強制終止時，scan 會停在 running，直到 lease 過期、下一次執行 fake-runner 對帳成 interrupted。
- 彙總的規則是 T09 的定義；M2、T13 有真實的預算與中斷之後可能調整，只改 `aggregate()` 一處，並在這裡記錄。

不在 T09 範圍：
- T10：真的 runner 程序、docker-socket-proxy；`GET /scanners` 與 capability probe。
- T11：由 scan 與 grant 產生 guard 的 policy；取消時先封鎖 guard。
- T12：預算的實際計數與 `budget_usage`、preflight 的實際執行、coverage 的量測（`coverage_measured` 目前一律 false）。
- T13：容器的心跳與對帳（非 fake 的 lease 過期）、timeout、孤兒容器、撤銷或停用之後停止執行中的 scan。
- M3（T14）：zap 可用、`GET /scan-profiles`、依 ZAP 實際的設定調整 profile。M4：nuclei 可用；observation 與 finding。
- T21：報告標示 fixture 的結果。T23：速率限制與每把 key 的同時請求上限；DDL 與 DML 角色分開（應用程式的角色目前能 `DISABLE TRIGGER`）。M2：`sslmode`；需要時加 LISTEN/NOTIFY（目前輪詢）。

審查留給後續的事項（T09 不會觸發）：
- 解析的重試沒有次數上限：lease 過期時 normalizing 退回 collected，會讓解析 crash 的 artifact 一直重試，target 也一直忙碌。M2、M4 的 worker 加上嘗試次數，超過就 failed。
- prepare 對綁定版本的 `FOR SHARE` 只保護 commit 之前：M2 的 runner 要在 prepare 的同一個 transaction 中取得注入用的密文，或在注入時發現密文已清除就失敗。
- guard 逐個請求檢查 grant 的期限（`max_duration_seconds` 可能超過 `valid_until`），並以 origin／IP 合計預算（不同 project 的 target 可能指向同一個 origin）：M2。
- gate 拒絕（403 `SCOPE_*`、409 `TARGET_DISABLED`）寫進安全日誌；事件輪詢的授權只查 project、coverage 的數字在建立時寫進 scans（效能）：之後的加固。

何時重新檢討：
- 同一個 target 需要同時跑多個 scan（例如不同的 auth role）：改成以 (target, auth role) 為單位的忙碌判斷，並檢討共用預算。
- 輪詢事件的負擔太大：加 LISTEN/NOTIFY，sequence 的語意不變。

## 14. T10 補充決定：runner、docker-socket-proxy、ExecutionPlan 與容器限制（2026-10-27）

T10 建立真的 runner 程序：經 docker-socket-proxy 啟動單次容器，送進 Docker 之前先驗證 ExecutionPlan。以下是規劃文件沒有寫到、實作前才定下的細節。

使用者的決定（2026-10-27）：
- socket-proxy 改用 **wollomatic/socket-proxy**（§14.1；原本的文件寫 Tecnativa [S27]）。
- 容器化 **api、runner、worker**；worker 在 T10 只處理 fake 的 normalizing（parser 在 M3）。
- **secret 注入在 T10 做**：runner 是 `reveal` 唯一的呼叫者（§12.2 的交接）。

T10 不送出任何掃描流量：只有 fake 引擎，fake 容器在 scan_net 上不連任何位址（guard 在 T11），也不啟動 lab。

依據：
- wollomatic/socket-proxy [S83]：每個 HTTP method 一個 regex，自動加上 `^`、`$`，沒有設定的 method 一律拒絕；`-allowfrom` 預設只允許 127.0.0.1，可以寫主機名稱；`-allowbindmountfrom` 會檢查 container create 等端點的 body，只放行列出目錄下的 host bind，`VolumesFrom` 一律拒絕，named volume 不算 bind；README 明說它**不限制 privileged、host namespace、capability 與 device**，「is a request filter, not a sandbox」。1.13.0 修補了 bind mount 的檢查；1.13.1（2026-08-15）只升 Go；1.13.2（2026-10-24）只升 Go 與文件，發布未滿兩週，暫不採用。
- Tecnativa 的 haproxy.cfg [S84]：`POST` 是全域開關；`CONTAINERS` 的規則是 `^(/v[\d.]+)?/containers`，沒有結尾錨點，所以 `CONTAINERS=1` 加上 `POST=1` 時，`/containers/{id}/exec`（建立 exec）與 `/containers/{id}/archive`（把檔案寫進容器）都會放行，也能停止、刪除任何容器。
- Docker SDK for Python 7.2.0 [S85]：低階 `APIClient` 給定版本時不在建立時呼叫 daemon；`from_env()` 在沒有 `DOCKER_HOST` 時會改用 Docker CLI 的 context。Engine API 1.45 起支援 volume 的 `Subpath` [S86]。
- 實測（OrbStack，Docker Engine 29.4.0、API 1.54、最低 1.40，2026-10-27）：
  - VM 內的 `/var/run/docker.sock` 是 `root:root 0660`：socket-proxy 以 `65534:0` 執行（非 root 的 uid，group 0 才連得到 socket）。
  - socket-proxy 的 regex 只比對 path，不含 query（`/v1.45/version?x=1` 符合 `/v1\.[0-9]+/version`）。
  - `-allowfrom` 的主機名稱在每個請求時解析（容器停止後，同一個 IP 的其他容器就被拒絕）。
  - `-allowbindmountfrom` 指向不存在的目錄時，`HostConfig.Binds` 與 type 為 bind 的 `Mounts` 都回 403；沒有 bind 的 create 照常 201。
  - 只接 internal network 的容器，publish 的 port 不會生效：api 與 db 另外接一個非 internal 的網路，只用來發布 127.0.0.1 的 port。

### 14.1 docker-socket-proxy

| 項目 | 採用 | 理由 |
|---|---|---|
| 實作 | wollomatic/socket-proxy 1.13.1，以 digest 鎖定（`sha256:3935b709…`） | Tecnativa 只能整段開放 API 區段，做不到 SEC-21 要求的「exec 等 API 回 403」（上方依據） |
| 放行清單 | GET：`/version`、`/containers/secscan-run-<uuid>/json`、`/images/<核准的映像>/json`（逐字比對核准清單、`.` 已跳脫：審查發現原本的通式會放行 `/` 與 `..`）、scan_net、兩個 volume。POST：`/containers/create`、`/containers/secscan-run-<uuid>/(start\|stop)`。DELETE：`/containers/secscan-run-<uuid>`。其他一律 403 | runner 一律以名稱 `secscan-run-<run_id>` 操作容器，proxy 因此能把管理限制在掃描容器，碰不到 db、api 或其他專案的容器。沒有 exec、archive、build、pull、logs，也不能建立 network 或 volume |
| 其他設定 | `-allowfrom=runner`；`-allowbindmountfrom` 指向不存在的空目錄（create 的 `Binds` 與 type 為 bind 的 `Mounts` 都拒絕）；`-watchdoginterval` 加 `-stoponwatchdog`（socket 不可用就結束，由 compose 重啟）；只接 internal 的 docker_net、不發布 port；`65534:0`、`read_only`、`cap_drop: ALL`、`no-new-privileges` | privileged、namespace、capability、volume 的 driver 選項（`o=bind` 的 local volume）與任意的本機映像，proxy 都不檢查，只靠 runner 的驗證（§14.3）。socket 的 `:ro` 不會限制 API 呼叫，不算一道防線（審查指出） |
| 放行清單的來源 | compose 的設定是唯一的來源；單元測試解析 compose，以相同的語意（自動加 `^$`、只比對 path）核對一張「該放行、該拒絕」的對照表 | 改了設定，測試就會指出哪一個端點的結果變了 |

殘餘風險（同 `ARCHITECTURE.md` §2）：
- runner 被攻陷時仍可以建立 privileged 容器（proxy 不檢查 body 的這部分）。緩解是 runner 不解析不可信資料、只掃 lab；要掃 lab 以外的目標，runner 與掃描容器必須移到獨立的 VM。
- 放行的查詢讓被攻陷的 runner 看得到 scan_net 上的容器與 IP、volume 在宿主上的路徑（影響小，記錄於此）。
- `65534:0` 是 OrbStack 的做法（VM 內 socket 是 `root:root 0660`）；原生 Linux 改用 `group_add` 加上 docker socket 的 GID，不改成 root。

### 14.2 Docker 存取

| 項目 | 採用 | 理由 |
|---|---|---|
| SDK | `docker` 的低階 `APIClient`，`base_url` 明確給（預設 `tcp://socket-proxy:2375`），API 版本固定 1.45，不用 `from_env()` | 不受 CLI context 影響；1.45 是 subpath 的最低版本，probe 確認 daemon 的範圍包含它 |
| create 的 body | runner 自己組好整個 body（§14.3），以 `create_container_from_config` 原樣送出 | 驗證的就是實際送出的內容，不經 SDK 再轉換一次 |
| 等待 | 每秒以 `GET /containers/{name}/json` 查狀態，不用長時間阻塞的 wait | 少開放一個端點；等待期間要心跳、檢查取消與時間上限 |
| 唯一 import 的地方 | `runner/docker_runtime.py`（import-linter：其他模組不得 import `docker`） | CLAUDE.md §5 |
| 映像 | runner 不 pull（proxy 也不放行）；`make images` 在宿主以 digest pull。缺少時 probe 不通過、不認領 | 不讓 runner 觸發 daemon 對外連線 |
| 容器名稱 | `secscan-run-<run_id>`：同一個 run 只可能有一個容器，重複 create 得到 409 | 防止重複啟動的最後一道；完整的對帳在 T13 |

### 14.3 ExecutionPlan 與驗證

- **ExecutionPlan**（`scanners/domain/plan.py`，純資料）：run 與 scan 的 id、引擎、映像（`repo:tag@sha256:…`）、entrypoint、args、非秘密的環境變數、要寫進 `in/` 的輸入檔、是否掛載 target 的 secret（只有參照，沒有值）、資源與時間上限。**沒有** host path、網路名稱、user、privileged、capability 這些欄位：由 runner 固定的容器政策決定。
- **建構**：`scanners/domain/fake.py` 依 fake 的腳本建 plan：成功 → `/bin/sleep <秒數>`，失敗 → `/bin/false`；映像是 busybox 1.38.0（digest 鎖定）；寫一個不含秘密的 `run.json` 到 `in/`。
- **驗證**（`runner/domain/admission.py`，純函式）：每個引擎一份政策，plan 必須
  - 使用核准清單中的映像（完整的 ref 逐字比對，tag 或 digest 不同都拒絕）；
  - entrypoint 與 args 符合其中一個指令樣板（每個位置是 literal 或 regex 的完整比對，不能多也不能少）；
  - 環境變數的名稱在白名單、值符合格式；輸入檔的名稱在白名單、大小在上限內；
  - 只有接受 target 認證的引擎才能掛載 secret；資源與時間的上限大於 0 且不超過引擎的上限。
  不符就 `PlanRejectedError(原因)`；訊息只有原因，不含值。
- **再檢查一次 create 的 body**（不變式，縱深防禦）：由 plan 與容器政策組出 body 之後、送出之前，以獨立的規則檢查（自己的一份字面值與掛載規則，不呼叫組 body 的程式、不共用它的常數：審查發現原本共用，改錯時會一起放行）：只有允許的欄位；`Privileged` 為 false；沒有 `Binds`；`Mounts` 只有這個 run 的 volume subpath（而且只有 `out/` 可寫）；`NetworkMode` 是 scan_net；`CapDrop` 是 `ALL`；`no-new-privileges`；唯讀 rootfs；`Init`；`IpcMode`、`CgroupnsMode` 是 `private`（不依賴 daemon 的預設值）；user 是 `10001:10001`；有記憶體（不能用 swap）、CPU、pids 上限；不自動重啟。另外 plan 被拒或 body 不安全時，Docker 一個請求都收不到（測試確認）。
- 核准的映像寫在 runner 的政策裡，和 scanners 的建構各寫一次：驗證是獨立的白名單，不是「建構的結果自己核准自己」。

### 14.4 掃描容器的限制

- user `10001:10001`（和 runner 相同：隔離靠掛載，不靠 uid）、唯讀 rootfs、`CapDrop: ALL`、`no-new-privileges`、`Init: true`（訊號能傳到工具，stop 時不必等到 kill）。
- 只接 scan_net（internal、gateway isolated）；不掛任何 host path，只有 volume subpath：`<runs>/<run_id>/in`（唯讀）、`<runs>/<run_id>/out`（可寫）、`<secrets>/<run_id>`（唯讀，有 secret 時）。
- 記憶體（`MemorySwap` 等於 `Memory`，不能用 swap）、`NanoCpus`、`PidsLimit`、`nofile` 上限；log 用 `json-file` 並限制大小；不自動重啟、不自動刪除（runner 讀完結束的狀態才刪）。fake：64 MiB、0.5 CPU、64 個 pid。
- labels：`secscan.managed`、`secscan.run_id`、`secscan.scan_id`、`secscan.engine`（T13 的對帳用）。

### 14.5 工作目錄、收集與 secret

| 項目 | 採用 | 理由 |
|---|---|---|
| volume | `runs`（`in/`、`out/`、收集的 manifest）與 `run_secrets`（只有 runner 與該 run 的容器掛載）兩個 named volume | M3 的 worker 要讀 `out/`，但永遠不掛 secret 的 volume：以 volume 分開，不靠檔案權限 |
| 收集 | 容器刪除之後，runner 以 `O_NOFOLLOW` 與 `lstat` 走過 `out/`：只接受一般檔案，拒絕 symlink、hardlink（nlink > 1）、device、FIFO、socket、讀不到的條目、非 UTF-8 或含控制字元與格式字元（Cc、Cf）的名稱；限制深度、條目數（目錄也算）、單檔與總大小。逐一走訪、超過上限就停，不先讀完整個目錄（審查發現：工具可以建立數百萬個條目讓 runner 耗盡記憶體）；計算 sha256，寫成 `runs/<run_id>/manifest.json`（在 `out/` 之外，掃描容器改不到）。違反就 failed（`ARTIFACT_REJECTED`） | runner 掛著整個 runs volume，跟著工具建立的 symlink 會讀到其他 run 的資料（SEC-18）。`ARCHITECTURE.md` §12：runner 只收集與計算 hash，不解析 |
| 執行中的用量 | out/ 沒有磁碟配額：容器執行中，runner 每秒以同樣的走訪（只 `lstat`、不開檔、不跟隨 symlink）檢查條目數、深度與總大小，超過就停止容器 → failed（`ARTIFACT_REJECTED`）。這是軟性的上限（寫入速度快時會超過一點）；硬性的配額要有大小上限的檔案系統，在 M3 接真工具時處理 | 審查發現：容器可以寫滿 VM 的磁碟，連 db 都受影響 |
| secret | prepare 在同一個 transaction 中，以 `FOR SHARE` 讀出綁定版本的密文（§13.11 的交接）。runner 在建立容器之前才 `reveal`，寫成 `<secrets>/<run_id>/target-auth`（0400、`O_EXCL`、寫完整），唯讀掛進容器；容器刪除之後立刻刪除。secrets volume 是 tmpfs（只存在記憶體，刪除即抹除）。runner 啟動時清掉殘留的 secret 目錄，但還有其他存活的 runner 時不清（可能正在使用） | CLAUDE.md §9；環境變數會出現在 `docker inspect`（T03），所以用檔案。plan、create 的 body、label、事件、audit、log 都只有參照 |
| fake 與 secret | fake 的政策接受 target 認證：有 auth profile 的 fake scan 會收到檔案，但 fake 不讀它 | 用真的容器驗證注入、權限與刪除；M3 的 ZAP 依自己需要的格式處理 |
| 解密失敗 | failed（`SECRET_UNAVAILABLE`），不啟動容器 | fail closed |

### 14.6 runner 與 worker 的生命週期

**runner**（`runner/service.py` 的 `ContainerRunner`；每一步都經 `ScanQueue`；容器與 secret 在 finally 中刪除，任何結果、任何例外都一樣）：
1. 認領 probe 通過的引擎（T10 只有 fake）；沒有 plan 的引擎直接 failed（`PLAN_REJECTED`），不記下容器與映像。
2. `prepare_launch`：既有的檢查（gate、profile 的版本、建立者的 key）通過時，在移到 running 的同一個 transaction 中寫入 `container_name` 與 `image_ref`（先記下、才呼叫 create），並回傳密文與 scan 的時間上限。
3. 建 plan → 驗證 → 寫 `in/` 與 secret → create → start。工作目錄不可用（權限、磁碟滿）：failed（`WORKSPACE_UNAVAILABLE`）；start 之前 Docker 出錯：failed（`RUNTIME_UNAVAILABLE`）。
4. 等待：啟動後立刻心跳一次（lease 從認領起算），之後每 5 秒一次；每秒查一次容器的狀態與 out/ 的用量。
   - 查不到狀態：重試，連續 3 次才放棄；已確認刪除容器 → interrupted（`RUNTIME_UNAVAILABLE`），刪不掉就不轉換。
   - out/ 超過上限：停止容器 → failed（`ARTIFACT_REJECTED`）。
   - 會停止容器的結果（取消、逾時、超過上限、runner 停止）都要確認容器已刪除才轉換；刪不掉就留給 T13 的對帳。
   - 要求取消：cancelling → stop（寬限 5 秒後 kill）→ cancelled（T11／T13 在 stop 之前插入「封鎖 guard」）。
   - 超過時間上限（scan 的 `max_duration_seconds`，T10 每個 run 各自計算；跨引擎共用在 T12）：stop → timed_out（`TIME_LIMIT_EXCEEDED`）。
   - lease 失效：stop、刪除容器、停止處理，不轉換（無法 fencing；run 留給 T13 的對帳）。
   - runner 收到 SIGTERM：stop、刪除容器 → interrupted（`RUNNER_STOPPED`）。容器確定已經停止，所以可以這樣標。
5. 結束：exit 0 → collecting → 心跳（收集可能要計算大量的 hash）→ 收集 → collected；OOM → failed（`RESOURCE_LIMIT_EXCEEDED`）；其他非 0 → failed（`ENGINE_FAILED`）。不論結果都刪除容器與 secret。

**worker**（`worker/service.py`）：對帳 lease 過期的 normalizing（→ collected，解析可以重試），再認領 fake 的 collected → normalizing → succeeded。fake 沒有東西可以解析，不讀任何檔案；M3 加上 parser。

**和 in-process 的 FakeRunner 並存**：`secscan-admin fake-runner` 保留（不需要 Docker）。兩者都會認領 fake，擇一執行。`reconcile_expired` 的 runner 階段只處理 `container_name IS NULL` 的 run：有容器的 run，lease 過期不代表容器已經停止（`ARCHITECTURE.md` §9），留給 T13 的容器對帳。

### 14.7 capability probe 與 `GET /scanners`

- probe：daemon 的 API 版本範圍包含 1.45；scan_net 存在、internal、gateway 是 isolated；兩個 volume 存在，而且 runner 掛載的目錄可寫（權限錯了要在認領之前發現，審查發現）；每個核准的映像都在本機。結果是每個引擎 `available` 或 `unavailable` 加原因代碼，不含路徑或秘密。probe 不通過就只寫心跳、不認領，每 60 秒重試。
- 心跳表 `runner_instances`：runner 與 worker 每 5 秒更新一次；30 秒內有心跳才算存活。同一個 owner 只更新同一列；啟動時刪掉 7 天沒有心跳的列。
- `GET /api/v1/scanners`：任何有效的平台 key 都可以讀（內容不分 project，也不含秘密）；讀回的映像 ref 不合格式就當成沒有回報，不把任意文字轉給使用者。依引擎列出是否已整合、是否可用、映像、可用的 scan profile、不可用的原因、最後 probe 的時間，以及 runner、worker 是否存活。只有 4 筆，不分頁。
- `/health/ready` 不納入 runner 心跳：API 沒有 runner 也能接受並排入 scan；是否要列入留給 T13。

### 14.8 部署（compose）

- 一個映像（`Dockerfile`，多階段：uv 依 `uv.lock` 建 venv → python 3.12 slim，都以 digest 鎖定；uid 10001；唯讀 rootfs 可以執行）。
- `compose.yaml` 的 `app` profile：`api`、`runner`、`worker`、`socket-proxy`；`make db-up` 不受影響。
  - control_net、docker_net、scan_net 都是 internal；scan_net 另加 gateway isolated（同 T03）。
  - api 與 db 另外接 `default`，只為了發布 127.0.0.1 的 port（上方實測）。
  - runner 接 control_net、docker_net；worker 只接 control_net；只有 socket-proxy 掛 docker.sock。
  - 都以非 root、唯讀 rootfs、`cap_drop: ALL`、`no-new-privileges` 執行，並有記憶體與 pids 上限。
- api 與 runner 仍以環境變數取得 DB 密碼與 `SECRET_ENCRYPTION_KEYS`；proxy 不放行 inspect `secscan-run-*` 以外的容器，runner 讀不到其他容器的環境變數。compose `secrets:` 與拆分 `.env` 仍在 T23（§7）。
- 程序入口：`secscan-admin runner`、`secscan-admin worker`。`cli.py` 改成 `cli/` 套件（`__init__` 與 `services`），維持 800 行以內。

### 14.9 測試隔離與 live 測試

- `tests/isolation.py`（pytest plugin，由 `tests/conftest.py` 載入）：
  - AF_UNIX 的 connect 只允許 pytest 暫存目錄底下的路徑。沒有開關時，防護在 `pytest_configure` 就套用到整個 session（session 範圍的 fixture 也受限，審查建議），每個測試再套用更窄的範圍。
  - `DOCKER_HOST` 設成不存在的 socket，並清掉 `DOCKER_CONTEXT`、`DOCKER_CONFIG`、`DOCKER_TLS_VERIFY`、`DOCKER_CERT_PATH`（子程序的 `docker` CLI 也連不到）。
  - 用了 `enable_socket`／`socket_enabled`、卻沒有標記 `live` 的測試，收集時就讓整個 session 失敗。
- `live` 測試沒有 `ENABLE_LIVE_LAB_TESTS=1` 就 skip；只有 live 測試解除上述限制。`make test` 只跑 `not live`。
- Docker SDK 的測試不開 socket：把 SDK 的 HTTP adapter 換成記錄請求的假實作，確認送出的請求逐一正確。
- `make test-live-runner`：以獨立的 compose 專案（`secscan-live`：自己的 DB volume、網路與 volume 名稱，API 綁 127.0.0.1:8765）建立 → 跑 live 測試 → 一律拆除。不動開發用的 db。

### 14.10 模組與分層（更新 §13.9）

```text
main | cli → migrations → health | runner | worker → scanners → scans → specs | auth_profiles → grants → targets → projects → api_keys → audit → security → core
```

| 模組 | 為什麼在這一層 |
|---|---|
| runner | 認領 run、驗證 plan、經 proxy 啟動容器；唯一能 import `docker` |
| worker | 解析（T10 只有 fake 的 normalizing）；不能 import `docker` |
| scanners | ExecutionPlan 與建構（純函式）、`runner_instances` 與 `GET /scanners`；runner 與 worker 都要寫心跳，所以放在它們之下 |

### 14.11 錯誤碼

| 錯誤碼 | 情況 |
|---|---|
| `PLAN_REJECTED` | plan 或 create 的 body 不符合政策（不呼叫 Docker） |
| `RUNTIME_UNAVAILABLE` | 啟動之前 Docker 出錯（例如 proxy 拒絕、映像不見了） |
| `SECRET_UNAVAILABLE` | 解不開綁定版本的密文 |
| `TIME_LIMIT_EXCEEDED` | 超過時間上限（timed_out） |
| `RESOURCE_LIMIT_EXCEEDED` | 容器因記憶體上限被終止 |
| `ARTIFACT_REJECTED` | 輸出有 symlink、特殊檔或超過上限 |
| `RUNNER_STOPPED` | runner 被要求停止，已停止並刪除容器（interrupted） |
| `WORKSPACE_UNAVAILABLE` | runner 的工作目錄不可用（權限、磁碟滿），或寫不出收集的 manifest（審查後補上） |

DB 只檢查錯誤碼的格式（§13.4），不必改 migration。

### 14.12 取捨與不在 T10 範圍

取捨：
- runner 被攻陷時仍能建立 privileged 容器（§14.1 的殘餘風險）。
- lease 失效、runner 被強制終止或 Docker 中途不可用時，run 停在 running，容器可能還在：要到 T13 的容器對帳才會處理。
- 時間上限是每個 run 各自計算；跨引擎共用預算在 T12。
- 兩種 fake runner 擇一執行。
- out/ 的用量是軟性的上限（每秒檢查）；硬性的磁碟配額在 M3。
- `prepare_launch` 的 `FOR SHARE` 只保證到 commit：之後 PATCH 清除 secret，不會讓已經啟動的 run 失效（同 §13.11 的語意）。
- api 與 runner 都持有 `SECRET_ENCRYPTION_KEYS` 與同一個 DB 角色：「只有 runner 呼叫 reveal」是程式層級的約束（AST 測試），不是權限邊界。分開金鑰與 DB 角色在 T23。
- runs volume 中每個 run 的目錄不會被刪除（保留期限在 M5／T23 定義）。

不在 T10 範圍：
- T11：guard 與 policy；取消時先封鎖 guard；scan_net 隔離的完整收包證據（SEC-06、SEC-07）。
- T12：共享預算與 telemetry；preflight 的實際執行。
- T13：有容器的 run 的對帳（lease 過期時依 label 找容器、確認停止之後才標 interrupted）、孤兒容器清理、`/health/ready` 是否納入 runner 心跳。
- M3：worker 的 parser 與 artifacts 資料表；ZAP 的映像、指令樣板與 secret 格式；工具以 uid 10001 執行的相容性。
- T23：compose `secrets:`、拆分 `.env`；DDL 與 DML 角色；`sslmode`。

## 15. T11 補充決定：egress guard、internal networks 與逐請求的檢查（2026-10-28）

T11 建立 egress guard：掃描容器只能經 guard 連到 grant 核准的 origin，guard 逐請求檢查 origin、DNS／IP、path、method 與 redirect 之後的請求。以下是規劃文件沒有寫到、實作前才定下的細節。

使用者的決定（2026-10-28）：
- guard 以**官方 mitmproxy 12.2.3 映像＋我們的 addon** 執行；啟動程式由我們自己寫，嵌入 mitmproxy（§15.1）。
- fake 引擎**不送流量**（仍是 busybox sleep）；收包證據由 live 測試另外啟動的 probe 容器取得。
- 「grant 撤銷時停止執行中的 scan」留給 **T13**；T11 的 guard 只逐請求檢查期限。

T11 不從產品路徑送出任何掃描流量：live 測試用自己的 live lab 網路與接收端，不啟動 Juice Shop 或 VAmPI。

依據：
- mitmproxy 文件：options [S87]、event hooks [S88]（`server_connect` 中設定 `data.server.error` 就中止連線）；嵌入的用法 [S90]。
- mitmproxy 12.2.3 原始碼 [S89]（從鎖定 digest 的映像中取出閱讀）：
  - `DumpMaster` 在建構時載入預設 addon，addon 的 options 之後才存在；`Master` 必須在 event loop 內建立。
  - `errorcheck`：啟動期間有 ERROR log 就以 1 結束；啟動完成後不再檢查。
  - addon 拋出的例外由 `safecall` 記下（含例外訊息）後吞掉，流程照常繼續。
  - regular mode 的 HTTP/1 請求在 `requestheaders` 之前就改成 origin-form（`authority = ""`）。
  - addon 在 `requestheaders` 設定 response 時，body 仍會讀完、`request` hook 仍會執行，但之後直接回應，不建立上游連線。
  - 設定 `request.host` 會把 Host 改成 `ip:port`。
  - `request.method` 會轉成大寫，轉送的卻是原始的 `data.method`。
- 相依套件：映像內 mitmproxy 12.2.3 要求 `cryptography<=48.1`、`typing-extensions<=4.14` [S91]，我們的 uv.lock 是 50.0.2、4.16.0，不能裝進同一個環境。12.3.x 發布未滿兩週，不採用。映像的 Python 是 3.14.5。
- Docker ≥ 26 不替只接 internal network 的容器轉送外部 DNS [S92]；RFC 9112 §3.2.2：proxy 收到 absolute-form 的請求時，要以 request target 取代 Host [S93]。
- T03 的 spike：addon 的例外被吞掉之後請求照樣放行；`mitmdump -s` 載入失敗時仍繼續當 proxy。
- **實測**（OrbStack，Docker Engine 29.4.0，鎖定 digest 的映像，以 uid 10001、唯讀 rootfs 執行，2026-10-28）：
  1. 啟動：
     - 在 `asyncio.run` 中建立 `DumpMaster(with_dumper=False)`；`confdir` 與核心 options 在建構時給定，addon 的 options 之後設定，都讀得回來。
     - 綁不到位址時，`errorcheck` 讓程序以 1 結束。
     - `add_signal_handler(SIGTERM, master.shutdown)` 讓 `run()` 正常返回。
     - `python -I` 不把 script 所在的目錄加進 `sys.path`，所以啟動程式要自己加。
     - tlsconfig 在第一次 configure 時就在 `confdir` 建立 CA 檔，tmpfs 可以使用。
  2. 拒絕時完全不連上游：`requestheaders` 設定 response 時，以下都是 0 個 `server_connect`、接收端 0 個 accept：
     - GET、帶 Content-Length 的 POST、chunked。
     - `Expect: 100-continue`：mitmproxy 先回 100，再回 403。
     - body 超過 `body_size_limit`：413，`requestheaders` 在檢查大小時就被呼叫。
     - CONNECT：只經過 `http_connect`。
  3. hook 拋出例外時，請求照樣轉送到接收端，log 中有例外的訊息：包裝是必要的，例外的訊息也不能交給 mitmproxy。
  4. 綁定：
     - 設定 `request.host = <IP>` 之後把 Host 寫回 canonical 的 authority，接收端看到 canonical 的 Host。
     - `server_connect` 看到的是 `(IP, port)`；在那裡設定 error 之後回 502、0 個 accept。
  5. 解析的對照（raw request → mitmproxy 解出的值）：
     - origin-form 的 host 與 port 取自 Host；absolute-form 取自 request target，Host 保持原樣（兩者可以不同）。
     - 大小寫、結尾的點、十六進位與整數的 IP 寫法、`[::ffff:…]` 都原樣保留在 `host`。`0080` 解成 port 80，Host 仍是 `…:0080`。
     - 被 mitmproxy 以 400 拒絕：userinfo、host 中的 `\` 或 `%`、path 中的非 ASCII 字元。
     - 照樣交給 addon：path 中的控制字元與 `#`、`OPTIONS *`（path 是 `*`）、absolute-form 的 `https://`（scheme 是 https）。
     - HTTP/1.0 沒有 Host 時 `host_header` 是 None；兩個 Host 會以 `, ` 合併；Host 前後的空白會被去掉。
     - `get` 在 `request.method` 中是 `GET`，轉送時是原始的 `get`。
  6. header：
     - 不刪除 `Proxy-Authorization` 時會被轉送。
     - CL＋TE、兩個 Content-Length：400（`validate_inbound_headers`）。
     - `Upgrade: h2c`：mitmproxy 自己移除後轉送。
     - `Upgrade: websocket`：會轉送，上游回 101 時連線就變成沒有檢查的通道。
     - HTTP/1 的 request trailer：mitmproxy 在讀 body 時就讓那條連線結束（`NotImplementedError`），不會轉送，其他連線不受影響。
  7. options 的預設值：`connection_strategy` 是 eager；`upstream_cert`、`http2`、`http3`、`websocket`、`rawtcp`、`onboarding`、`command_history` 都是 true；`block_global` 是 true（client 是私有 IP，不受影響）；`body_size_limit` 沒有上限。
  8. 網路：
     - internal＋gateway isolated＋`--ip-range x.x.x.0/25`＋固定的 `.254` 可行。
     - isolated 模式不保留 `.1` 給 gateway，動態配發從 `.1` 開始。
     - guard 的 `/proc/net/route` 只有兩條直連的路由，沒有預設路由。
     - guard 解析得到兩個網路上的容器名稱，外部名稱與 `host.docker.internal` 立刻失敗（EAI_AGAIN）；兩個容器共用 alias 時回傳兩個 IP。
     - 掃描容器解析不到 lab 的名稱，也解析不到外部名稱。
  9. 時鐘：容器與宿主的差距在 0.05 秒以內。
  10. 映像內有 `mitmproxy.test.tflow` 與 `taddons`：live 的 contract 測試以真的 flow 物件驅動 addon。

### 15.1 guard 的執行方式

| 項目 | 採用 | 理由 |
|---|---|---|
| 映像 | `deploy/guard/Dockerfile`：FROM `mitmproxy/mitmproxy:12.2.3@sha256:00b77b5d…`，只 COPY guard 需要的模組（import 的封閉集合）與啟動程式，`USER 10001:10001`，ENTRYPOINT 是 `python3 -I /opt/secscan-guard/run_guard.py` | 使用者的決定；相依套件衝突，不能共用 uv.lock |
| 啟動（`run_guard.py`） | 依序：<br>1. 嚴格讀取設定；檢查 `/proc/net/route`：只有 scan 與 lab 兩條直連的路由、沒有預設路由。<br>2. 在 `asyncio.run` 中，以核心 options 建立 `DumpMaster(with_dumper=False)`。<br>3. 設定 addon 的 options，再逐一讀回核對（§15.2）。<br>4. 最後才加入 guard addon。<br>任何一步失敗都以非 0 結束 | 不用 `mitmdump -s`：載入失敗時它仍是沒有檢查的 proxy（T03） |
| addon 的程式 | `src/secscan/guard/` 只用標準函式庫與純 domain（`targets.domain`、`grants.domain`、`core.text`、`core.network`）。不 import mitmproxy：以 Protocol 描述用到的 flow 屬性，建立 response 的方式由啟動程式注入 | 在 3.12 的測試環境中可以完整測試，mypy strict 也涵蓋 |
| 例外 | 每個 hook 只捕捉 `Exception`（`CancelledError` 照常傳遞），一律拒絕或中止連線；log 只記 hook 名稱與例外類別（`# noqa: BLE001`，理由寫在程式中）。放行要有正向的核准紀錄：後面的 hook 找不到核准就拒絕 | mitmproxy 吞掉例外之後會放行（實測 3） |
| 紀錄 | 自己的 JSON handler（`propagate=False`），只記：canonical 的 run_id、決定、原因、method、host、port、path（截斷、不含 query）、上游 IP、status。不記 header 的值、query、token。mitmproxy 自己的 termlog 只輸出 warn 以上 | repo 沒有 logging 設定；mitmproxy 的訊息可能含請求的內容 |
| Python | 映像是 3.14、測試環境是 3.12：guard 的程式只用兩邊都有的功能。subprocess 測試確認 guard 載入的模組；live 測試在映像中實際執行 | 使用者接受的取捨 |
| confdir | `/tmp/mitmproxy`（`/tmp` 是 tmpfs）；映像宣告的 VOLUME（`/home/mitmproxy/.mitmproxy`）另外掛一個空的 tmpfs | VOLUME 所在的 `/home/mitmproxy` 是 0700、屬於 mitmproxy 使用者，uid 10001 進不去（實測）；掛 tmpfs 是為了不讓 Docker 每次建立匿名 volume。P0 不用 CA |

### 15.2 mitmproxy 的 options

啟動時設定，並逐一讀回核對（不符就以非 0 結束）：

| 類別 | 值 |
|---|---|
| 監聽 | `mode` 只有 `regular@<guard 的 scan IP>:8080`（不聽 lab 那一側、不聽 0.0.0.0） |
| 連線 | `connection_strategy=lazy`、`upstream_cert=false`、`http2`／`http3`／`websocket`／`rawtcp`=false |
| 請求 | `body_size_limit=16m`、`stream_large_bodies` 沒有設定（不 streaming：streaming 會在 `request` hook 之前就連上游）、`validate_inbound_headers=true`、`normalize_outbound_headers=true` |
| 不能改寫請求或略過檢查 | `ignore_hosts`、`allow_hosts`、`tcp_hosts`、`udp_hosts`、`map_remote`、`map_local`、`modify_headers`、`modify_body`、`block_list`、`client_replay`、`server_replay`、`scripts` 都是空的；`proxyauth`、`upstream_auth`、`stickyauth`、`stickycookie`、`save_stream_file`、`connect_addr` 都是 None；`anticache`、`anticomp`、`onboarding`、`command_history` 是 false |
| 其他 | `ssl_insecure=false`、`block_global=true`、`block_private=false`、`termlog_verbosity=warn` |

非空的 `ignore_hosts` 或 `tcp_hosts` 會讓流量不經 HTTP 層、也不經 addon 直接轉送，所以必須是空的。

### 15.3 runner 與 guard 交換資料（不經網路，ARCHITECTURE §3.1）

- **volume**（都是 tmpfs，uid 10001、0700；掃描容器與 worker 都不掛）：
  - `guard_policies`：runner 讀寫、guard 唯讀。
  - `guard_status`：guard 讀寫、runner 唯讀。
- **policy**：每個 run 一個 `<run_id>.json`，schema 1，平的結構：
  ```json
  {"schema": 1, "run_id": "…", "scan_id": "…", "state": "active",
   "token_sha256": "<64 hex>", "not_after": 1767600000, "renew_until": 1767598830,
   "origin": "http://lab-target:8080", "allowed_ips": ["10.89.7.20"],
   "methods": ["GET", "POST"], "allow_all_paths": false,
   "paths": ["/api/items/{id}"], "excluded_paths": ["/api/admin"]}
  ```
  - **時間**（整數 epoch 秒）：
    - `not_after` = min(grant 的 `valid_until`, 啟動時間 ＋ plan 的牆鐘上限)。
    - `renew_until` = DB 心跳成功之前讀到的時間 ＋ LEASE_DURATION（30 秒）。
  - **寫入**：以 dir fd、`O_EXCL|O_NOFOLLOW` 的 0400 暫存檔寫入、fsync，再 `os.replace`；封鎖與續約都走同一條路。
  - **guard 的解析**：
    - key 必須完全相符、拒絕重複的 key；布林不能當整數；UUID、IP、origin 都必須是 canonical 寫法；檔名必須等於 run_id。上限 512 KiB（最大的 grant 約 165 KB，§10.9）。
    - 以 `Scope(origins=(origin,), …)` 重建，再交給 `ScopeRules.of`：建構子重跑所有驗證，比對規則和 T09 凍結 operation 時相同。
  - **guard 的讀取**：每個請求 `stat` 一次，inode、mtime 或 size 變了才重讀；`O_NOFOLLOW`、只接受一般檔案；快取有上限，損毀的結果也快取。
- **續約（dead-man switch）**：只在 DB 心跳成功之後重寫 `renew_until`，寫失敗等同 guard 不可用。runner 當掉時，孤兒容器的出站最晚在 30 秒內停止：出站不會比 lease 活得久。
- **guard 的 status**：每 5 秒原子寫入 `status.json`，內容是 schema、`boot_id`（每次啟動隨機產生）、啟動與更新的時間、listen 位址、policy 的 schema 版本、`enforcing`（addon 已載入、自我檢查通過）。runner 判斷 guard 可用的條件：15 秒內有更新、版本相符、listen 位址等於自己設定的 proxy、`enforcing` 為 true。

### 15.4 proxy 憑證

- runner 為每個 run 產生 `secrets.token_urlsafe(32)`；policy 只存它的 sha256。
- 掃描容器拿到 secrets 目錄中的 `proxy-url`（0400）：`http://<run_id>:<token>@<guard 的 scan IP>:8080`。不放在 env、argv、label、事件、audit 或 log；各工具的設定格式在 M3、M4。
- guard 只接受一個 `Proxy-Authorization: Basic`：base64 嚴格解碼、run_id 是小寫的 UUID、token 的格式固定，以 `hmac.compare_digest` 比對 hash。驗證之後刪除所有 `Proxy-*` header（實測 6）。

### 15.5 逐請求的檢查（`requestheaders`，順序固定；拒絕時不建立上游連線）

1. **帳密與 policy**：帳密缺少或錯誤、run 不存在、policy 損毀，一律 407，附 `Proxy-Authenticate: Basic realm="secscan-guard"`（ZAP 的 reactive auth 需要）。真正的原因只寫進 guard 的 log，不讓 client 知道哪些 run 存在。
2. **run 的狀態**（token 驗證通過之後才回 403＋原因）：已封鎖 → `RUN_BLOCKED`；`now >= not_after` → `RUN_EXPIRED`；`now >= renew_until` → `POLICY_STALE`。
3. **請求的形狀**：
   - header 的名稱必須是 token、值不可含 CR、LF、NUL 與其他控制字元（tab 除外）→ 否則 `HEADER_INVALID`（審查後補上：mitmproxy 只檢查名稱，值中的 bare CR、合併的 obs-fold 會原樣轉送，把 CR 當成換行的靶機會看到 guard 沒有檢查的 header 或第二個請求）。
   - CONNECT 在 `http_connect` 一律 403（`CONNECT_DENIED`，P0 不支援 HTTPS）。
   - 有 `Upgrade`、`HTTP2-Settings`，或 `Connection` 含 `upgrade` → `UPGRADE_DENIED`。
   - scheme 不是 http → `SCHEME_DENIED`。
   - method 或 request target 不是可見的 ASCII、含 `#` → `PATH_AMBIGUOUS`。
4. **改寫目的地的 header**：`X-HTTP-Method-Override`、`X-HTTP-Method`、`X-Method-Override`、`X-Original-Method`、`X-Original-URL`、`X-Rewrite-URL`、`X-Forwarded-Host`、`X-Forwarded-Path`、`X-Forwarded-URI`、`X-Forwarded-Prefix`、`X-Forwarded-Server`、`X-Host`、`Forwarded`，或 query 中解碼後（不分大小寫）是 `_method` 的 key → `OVERRIDE_HEADER`。這些會讓靶機改用別的 method 或 path，繞過 grant。header 名稱比對前把 `_` 換成 `-`（CGI／WSGI 把兩者對應到同一個變數；審查發現原本 `X_HTTP_Method_Override` 會放行），刪除 `Proxy-*` 時也一樣。黑名單本身有極限，body 中的 `_method` 也擋不到，都是殘餘風險（§15.10）。
5. **authority**（parser differential）：三個來源都必須和 policy 的 origin 逐字相同，不符 → `ORIGIN_MISMATCH`：
   - mitmproxy 解出的 host 與 port（大小寫、結尾的點都算不同）；
   - 唯一一個 `Host` header（port 是 80 時也接受 `host:80`）；
   - scheme。

   T11 只放行 scan 的 target origin。逐字比對擋下所有替代寫法：大寫、結尾的點、十六進位、整數、前導零、`[::ffff:…]`、userinfo（實測 5）。
6. **path 與 method**：
   - method 以原始的 bytes 比對（實測 5：轉送的是原始的 method）。
   - 去掉 query，先以 `path_problem` 檢查（`%`、`;`、`//`、`.`、`..`、`\`、非 ASCII、超過 512 字元都拒絕）；含 `{`、`}` 的也拒絕（`parse_route` 會把字面的 `{x}` 當成佔位）。這些都回 `PATH_AMBIGUOUS`。
   - 再交給 `ScopeRules.classify`：`PATH_EXCLUDED`／`METHOD_NOT_AUTHORIZED`／`PATH_NOT_AUTHORIZED`。`OPTIONS *` 也因此拒絕。
7. **位址**（只解析 policy origin 的 host，guard 不會變成 DNS 外洩的管道）：
   - origin 是 IP 時不解析；是名稱時以注入的 async resolver 解析（2 秒逾時、答案數量有上限）。
   - **每一個**答案都必須同時是 IPv4、在 `allowed_ips` 中、通過 `LabNetwork.check_host`（網段內，不是網路、廣播或保留給 guard 的位址），而且不是 guard 自己的位址。
   - 不符 → `ADDRESS_NOT_ALLOWED`；解析失敗 → `DNS_FAILED`。
8. **核准與綁定**：設定 `request.host = <IP>`，再把 Host 寫回 policy 的 canonical authority：上游連的是驗證過的 IP、Host 不變，事後重新解析也不會生效（SEC-04）。核准記在 `flow.metadata`，以及 `client.id → {(ip, port): run_id}`。

其他 hook 的防線：
- `request`：已經拒絕的請求不處理；其餘再查一次 policy 的狀態、必須有核准、有 trailer 就拒絕。
- `server_connect`：目的位址必須是這條 client 連線核准過的，而且 run 仍然有效；否則（含例外）設定 `data.server.error`。
- `client_connected`：來源不在 scan_net 的網段就中止；`client_disconnected` 時清掉核准。
- `tcp_start`、`udp_start`、`websocket_start`：一律中止（縱深防禦；這些協定都已關閉）。
- `response`：刪除靶機回應中的 `X-Secscan-Guard`（審查發現：靶機可以冒充 guard 的拒絕，讓 M3 的 parser 丟掉自己的回應），guard 自己的拒絕保留；刪不掉就中止。記錄 status 與實際的上游 IP。
- `request`：拒絕的旗標存在、卻沒有回應（建立回應與中止都失敗過）時中止，不只相信旗標（審查發現）。
- `error`：記錄。
- redirect 不改寫、也不另外分類：工具跟隨 redirect 送出的下一個請求，照上面的順序重新檢查（SEC-03）。

拒絕的回應：403，附 `X-Secscan-Guard: <原因>` 與一行純文字。M3 的 parser 依這個 header 排除 guard 的回應。

### 15.6 網路與位址

| 項目 | 採用 |
|---|---|
| lab_net | 改由 `make lab-net` 建立：internal、gateway isolated、10.89.7.0/24、`--ip-range 10.89.7.0/25`。`compose.lab.yaml` 與 `compose.yaml` 都以 external 引用 `${SECSCAN_LAB_NET:-secscan_lab_net}` |
| scan_net | `make scan-net` 加上 `--ip-range 10.89.8.0/25` 並驗證。guard 停機時，掃描容器也拿不到 guard 的 IP（否則可以冒充 guard，收集其他 run 的帳密） |
| guard 的位址 | 兩個網段的最後一個 host（scan 10.89.8.254、lab 10.89.7.254），在動態配發的範圍之外。guard 啟動時確認：lab IP 是保留的位址、scan IP 不在 LAB_CIDR 內 |
| `LabNetwork` | 保留 LAB_CIDR 的最後一個 host 給 guard：target、grant 與 gate 都拒絕（T06 的交接）。LAB_CIDR 的規則（RFC 1918、/16–/30）抽到 `core/network.py`，config 與 guard 共用 |
| guard 的網路 | 只接 scan_net 與 lab_net；不接 control_net、docker_net、default；不發布 port；只聽 scan 那一側 |
| canary | 只存在於 live 測試，文件寫明 |
| 舊環境 | 已存在、沒有 ip-range 的網路，`make scan-net`／`make lab-net` 的驗證會失敗；README 寫重建的步驟 |

### 15.7 runner 的整合（維持 T10 的生命週期結構）

- **佇列**：`_gate` 改成也回傳 grant；`Launch` 加上 `egress: EgressScope | None`（target 的 origin、grant 的 scope 與 `valid_until`），只在轉到 running 時設定。in-process 的 fake-runner 與 worker 不受影響。
- **secret 檔**：每個容器都會拿到 `proxy-url`，所以 `/scan/secret` 一律掛載；`target_auth` 的語意不變。
  - `write_secrets(run_id, {允許的名稱: 內容})`：只 mkdir 一次，全部成功或什麼都不留。
  - `discard_secrets`：刪掉所有已知的名稱再 rmdir（修正 T10「只刪 `target-auth`，多一個檔案時 rmdir 失敗」的問題）。
- **`runner/egress.py`**：每個 run 的 handle（token、policy、寫入、續約、封鎖、刪除）。
- **啟動**（`_start`）：guard 不可用 → failed（`GUARD_UNAVAILABLE`），不建立容器；心跳 → 寫 secrets（`proxy-url`，有認證時加 `target-auth`）→ 寫 `in/` → 寫 policy（`renew_until` 取自剛才的心跳）→ create → start。
- **停止**：封鎖寫在 `_stop` 裡，每條停止的路徑都先封鎖：lease 失效、runner 停止、逾時、輸出被拒、guard 中斷。取消的順序是封鎖 → cancelling → stop（完成 T10 標記的插入點）。
- **心跳**（`_beat`）：DB 心跳成功之後才續約。以下都是新的結果 `GUARD_LOST`：guard 不可用、`boot_id` 改變（guard 重啟過，可能漏掉請求）、續約寫不出去。`GUARD_LOST` 的處理是封鎖 → stop → **interrupted**（`GUARD_UNAVAILABLE`），和 T10 的「基礎設施中斷」一致，不把工具連不上當成零告警。
- **清理**：封鎖 → 刪容器 → 刪 secrets → 確認容器已刪除才刪 policy；否則保留 blocked 的 policy。
- **迴圈與 probe**：每一輪認領之前都讀 guard 的 status（一個小檔案），結果交給可認領的引擎與心跳，不必等 60 秒的 probe。不可用時，每個引擎都回 `GUARD_UNAVAILABLE`；policy 目錄不可寫也算不可用。啟動時連同 secret 一起清掉殘留的 policy（條件同 T10：沒有其他存活的 runner）。

### 15.8 錯誤碼與能力代碼

| 代碼 | 情況 |
|---|---|
| `RunErrorCode.GUARD_UNAVAILABLE` | 啟動之前（guard 不可用、寫不出 policy）→ failed；執行中（guard 中斷或重啟、續約失敗）→ interrupted。DB 只檢查格式，不必 migration |
| `CapabilityIssue.GUARD_UNAVAILABLE` | `GET /scanners` 的不可用原因；API 與 runner 一起更新（`read_capabilities` 會丟掉不認得的代碼） |

guard 的拒絕原因只出現在 guard 的 log 與回應的 header：
- 帳密與 policy：`PROXY_AUTH_REQUIRED`（log 中再細分 `RUN_NOT_ACTIVE`、`POLICY_INVALID`、`TOKEN_MISMATCH`）、`RUN_BLOCKED`、`RUN_EXPIRED`、`POLICY_STALE`。
- 請求的形狀與 origin：`CONNECT_DENIED`、`HEADER_INVALID`、`UPGRADE_DENIED`、`SCHEME_DENIED`、`OVERRIDE_HEADER`、`ORIGIN_MISMATCH`。
- path 與 method：`PATH_AMBIGUOUS`、`PATH_EXCLUDED`、`METHOD_NOT_AUTHORIZED`、`PATH_NOT_AUTHORIZED`。
- 位址：`DNS_FAILED`、`ADDRESS_NOT_ALLOWED`。
- 內部：`NOT_APPROVED`、`TRAILERS_DENIED`、`GUARD_ERROR`。

### 15.9 模組與分層（更新 §14.10）

```text
main | cli → migrations → health | runner | worker → scanners → scans → specs | auth_profiles | guard → grants → targets → projects → api_keys → audit → security → core
```

- guard 只用 grants、targets、core 的純模組；runner 可以 import guard（policy 的格式只有一份）。
- 新的 forbidden contract：`secscan.guard` 不得 import fastapi、starlette、sqlalchemy、alembic、psycopg、docker、pydantic、pydantic_settings、yaml、cryptography、uvicorn。
- subprocess 測試：`python -I` 載入 guard 之後，`sys.modules` 只有標準函式庫與 `secscan`，而且 `secscan.*` 正好等於 `deploy/guard/Dockerfile` 的 COPY 清單。

### 15.10 取捨與不在 T11 範圍

取捨（殘餘風險）：
- path 中的 `%` 一律拒絕：會擋掉工具放在 path 的 payload，部分 ZAP 檢查無法執行；刻意 fail closed，M3 依量測決定。
- body 中的 `_method`（例如表單欄位）擋不到；lab 的靶機另外確認是否支援這個寫法。
- proxy 憑證沒有綁定來源 IP：P0 只有一個 runner、一次一個掃描容器；ip-range 讓掃描容器拿不到 guard 的 IP。
- mitmproxy 本身可能被惡意的靶機回應攻陷：guard 不接 control_net、docker_net；非 root、唯讀、沒有 capability；policy 唯讀；不持有目標的 secret。
- guard 以 `DumpMaster` 這個半內部的 API 嵌入：以 digest 鎖定版本、啟動時讀回 options 核對、live 的 contract 測試涵蓋。
- 掃描容器若在 proxy 連線上先送 TLS，mitmproxy 會建立 client 端的 TLS（沒有 option 可以關）。內層的請求照樣經過所有 hook（origin-form 的 scheme 是 https 而被拒；absolute 的 `http://` 照常檢查、上游仍是明文），不是繞過，只是掃描容器接觸得到的程式多了 TLS 與憑證產生的部分（審查指出）。
- policy 的時間以 runner 與 guard 共用的 VM 時鐘計算（實測差距 0.05 秒以內）。時鐘往前跳是 fail closed；往後大幅跳會延長 dead-man switch 的時間，延長的量等於跳動的量。
- live 測試的接收端與探針每個請求一條新連線：同一條 keep-alive 連線上交錯的放行與拒絕、pipelining，以及 header 值中夾帶的第二個請求，目前只有單元測試（`HEADER_INVALID`、`request` 與 `server_connect` 的重查）與原始碼的閱讀，沒有 live 的收包證據（安全審查 M2，留待後續補上）。
- 被拒絕的請求不計預算：guard 的 log 以 json-file 限制大小（10 MB × 3）；`body_size_limit=16m` 加上 256 MiB 的記憶體上限，大量同時上傳可能讓 guard OOM（fail closed，run 變成 interrupted），T12 的預算與速率上限之後再量測。

不在 T11 範圍：
- T12：policy schema 2（預算：速率、burst、總請求數、跨引擎共用；額外的 origin 與跨 origin 的認證 header 規則）；telemetry 與計數（以 `boot_id` 銜接重啟）；preflight 的實際執行；ZAP 的 reactive 407 讓請求數加倍，計數時要考慮。
- T13：grant 撤銷或 target 停用時停止執行中的 scan（SEC-01 的後半）；有容器的 run 的對帳與孤兒容器（含 runner 被 kill 之後留下的 policy，reconciler 沿用 `runner/guard.py` 封鎖）；`/health/ready`。
- M3：工具的 proxy 設定格式；HTTPS（CA、上游憑證驗證）；parser 依 `X-Secscan-Guard` 排除 guard 的回應。

## 16. T12 補充決定：共享預算、telemetry 與認證 preflight 的執行路徑（2026-10-29）

T12 讓 guard 強制整個 scan 共用的速率與請求數，記下實際轉送的每一個請求，並建立 preflight 的執行路徑。以下是規劃文件沒有寫到、實作前才定下的細節。

使用者的決定（2026-10-29）：
- **preflight**：T12 就建好執行路徑（不等 M3 的引擎）。
- **多個 origin**：維持只放行 target origin（§15.5）；grant 的其他 origin 與跨 origin 的認證規則延後。所以「token 只送往核准的 origin」由「只有 target origin 會被轉送」直接保證：跟隨 redirect 到其他 origin 的請求一律 403（SEC-03），連同 header 都不會送出。
- **超過速率**：讓請求等待（token bucket），最多 5 秒；等不到才回 403 `RATE_LIMITED`。直接拒絕會讓工具把 403 當成靶機的回應，或耗掉重試。

依據：
- DoD（`TASKS.md` T12）：所有掃描流量共用同一個上限，preflight 也計入；token 只送往核准的 origin；從 telemetry 可以算出實際請求數。
- CLAUDE.md §8：預算跨引擎共用（含爬蟲、preflight、驗證、重試），由 guard 強制。§9：preflight 不能只看 status 200（§12.5 的比對規則）。
- mitmproxy 的 hook 順序（§15 的原始碼閱讀）：`requestheaders` → 讀完 body → `request` → `server_connect`（需要時）→ 送出 → `response`；中途出錯或被中止時呼叫 `error`。
- **實測**（OrbStack，T10 的 busybox 映像、同一個 digest，以 uid 10001、唯讀 rootfs、`--network none` 執行，2026-10-29）：
  - `base64 -w 0` 輸出單行（`<uuid>:<43 字元 token>` 編碼後 108 字元），可以組出 `Proxy-Authorization: Basic …`。
  - `nc <ip> <port>` 搭配 `printf` 送出 HTTP/1.0 請求、讀回完整回應；`printf` 是 ash 的內建指令，`cat` 從檔案讀進管線：secret 不會出現在任何程序的 argv（`/proc/*/cmdline`）。
  - **live 實測（實作之後）**：busybox 的 nc 在 stdin 結束時會半關閉連線（shutdown 寫入端），mitmproxy 把它當成 client 斷線，放行之後丟掉回應（guard 的 log 只有放行、沒有回應；兩個輸出檔都是 0 bytes，結果是 `not_executed`）。對另一個 nc 測試時看不出來（它不理會半關閉）。改成送完請求之後 stdin 再開著 5 秒（`sleep 5`，`nc -w 5`），每個請求最多多花 5 秒；靶機超過 5 秒才回應時沒有回應（`not_executed`）。

### 16.1 policy schema 2

在 §15.3 的平面結構上加四個欄位（schema 改成 2；runner 與 guard 一起更新，status 的 `policy_schema` 不符就不認領）：

| 欄位 | 內容 |
|---|---|
| `requests_per_second` | scan 的速率（1–`MAX_REQUESTS_PER_SECOND`） |
| `burst` | 固定 1：不累積閒置的額度 |
| `max_requests` | **這個 run** 還能轉送的請求數（0–`MAX_REQUESTS`），runner 算好（§16.4） |
| `auth_header` | 送出目標 secret 的 header 名稱（小寫，英數字與 `-`；沒有 auth profile 時是 null） |

`auth_header` 由綁定版本的 `Credential.wire_header` 決定：bearer → `authorization`、cookie → `cookie`、api_key_header → `header_name` 的小寫。guard 只用它判斷請求是否帶著憑證（telemetry 的 `auth`），不改寫、不注入。

### 16.2 guard 的強制（`requestheaders`，接在 §15.5 的 path 與 method 之後）

1. **請求數**：先保留一個名額（`RunLedger`）；已經保留或轉送到 `max_requests` → 403 `BUDGET_EXHAUSTED`，不解析 DNS。同時進行的請求各自保留，不會一起超過上限。保留中、還沒轉送的名額最多 `requests_per_second × 5 + burst` 個（11），超過回 403 `RATE_LIMITED`：名額在 header 階段保留、body 送完才轉送，延遲 body 的工具可以累積已核准的請求再一次送出（security-reviewer 的 M1）；有上限之後，最多一次送出 11 個。
2. **速率**：GCRA（等同容量 `burst` 的 token bucket），以 **scan** 為 key：同一個 scan 的 run 依序執行，preflight 與各引擎共用同一個速率。要等待就 `await sleep`；要等超過 5 秒 → 403 `RATE_LIMITED`，不保留位置。時間用 monotonic 時鐘（wall clock 跳動不影響）。
3. **等待之後再查一次 run**：等待期間可能被封鎖、過期或停止續約。
4. 之後才是 §15.5 的 DNS 與綁定。

名額在 `request` hook（第二道防線通過之後）才**確定**轉送：計入 `forwarded`、寫一行 telemetry。`requestheaders` 之後的任何拒絕（`request` hook 重查、trailer）、`error` hook、例外與取消（`CancelledError`）都釋放名額；釋放以 `flow.metadata.pop` 保證只做一次。沒有呼叫 `request` 或 `error` 的 flow 會一直佔著名額：只會少放行，不會多放行。

**寫不出 telemetry 的請求不放行**（403 `GUARD_ERROR`）：沒有紀錄的流量會讓 runner 算出的剩下預算不可信。

拒絕只計 token 驗證過的 run（407 不知道是哪個 run，不計）。

### 16.3 telemetry

- **volume** `guard_telemetry`：tmpfs（64 MiB、uid 10001、0700）；guard 讀寫，runner（summary）與 worker（jsonl，§16.6）唯讀。掃描容器不掛。
- **檔案**（每個 run 兩個）：
  - `<run_id>.summary.json`（原子寫入，0400）：`forwarded`、各原因的 `denied`、`exhausted`（已轉送到上限）、`first_at`／`last_at`、`boot_id`、`scan_id`。
  - `<run_id>.jsonl`（附加，0600）：每個轉送的請求一行 `{"e":"request","seq","t","method","path","auth"}`；上游的回應一行 `{"e":"response","seq","t","status"}`。path 不含 query；不記 header 的值、body、query。
- **寫入的順序**：轉送時先寫 summary、再附加那一行。中途失敗時 summary 最多多算一個（對預算是保守的方向），記憶體的計數回到轉送之前。拒絕的計數由每 5 秒的 flush 寫入，最多落後一個間隔（只用於報告，不影響預算）。
- **guard 重啟**：第一次看到某個 run 時，由既有的 summary 接續計數與序號：重啟不會讓 run 重新拿到整份預算。summary 讀不出來或屬於別的 scan → fail closed（該 run 的請求回 `GUARD_ERROR`）。runner 仍依 `boot_id` 的改變把 run 標成 interrupted（§15.7）。
- **保留期限**：6 小時沒有更新的檔案由 guard 刪除（每 5 秒的 flush 一併檢查）。runner 在 run 結束之前把 summary 的計數寫進 DB；worker 在解析時直接讀 jsonl（實作時改的：原本打算由 runner 複製進 run 的工作目錄，但 run 結束之後 guard 不會再寫這個檔案，直接唯讀掛載比較簡單）。worker 停擺超過 6 小時，該 run 的 coverage 就沒有量測依據。
- telemetry 目錄不可寫時，guard 的自我檢查失敗（status 的 `enforcing` 是 false），runner 不認領。
- 讀的一方嚴格解析（key 完全相符、型別、canonical），訊息不含內容。

「實際的請求數」以 telemetry 的 `forwarded` 為準，不採用工具自報的數字（`API_CONTRACT.md` §8）。`forwarded` 是「guard 確定轉送」的數量；確定之後 `server_connect` 才被拒絕（run 在兩個 hook 之間被封鎖）或上游連不上的請求也算在內，jsonl 中這類請求沒有回應的那一行。

### 16.4 runner：剩下的預算與結束時的計數

- **剩下的請求數**：scan 的 `max_requests` 減去同一個 scan 之前的容器 run 用掉的數量。用掉的數量：有 `requests_sent` 就用它；沒有（runner 中斷、guard 重啟、telemetry 讀不出來）就以該 run 當初分到的 `requests_allotted` 計算（保守）。只有容器版的 run 記下 `requests_allotted`；in-process 的 fake 不送流量、不佔預算。
- **剩下的時間**：scan 的 `max_duration_seconds` 減去之前的容器 run 的 `traffic_seconds`（不明時以開始到結束的時間計算）；plan 的牆鐘上限與 policy 的 `not_after` 都用剩下的時間。
- **剩 0**（請求數或時間）：不建立容器，run 以 `failed`（`BUDGET_EXHAUSTED`）結束（`preparing` 只能轉到 failed；實作時修正，原本寫 timed_out）。
- **執行中**：每次心跳在續約之後讀 summary；`exhausted` 為 true → 封鎖 → 停止容器 → `timed_out`（`BUDGET_EXHAUSTED`）。summary 讀不出來時不停止（上限仍由 guard 強制），只記 log。
- **結束時**（任何結果，終止的 run 不能再改，所以在最後一次轉換之前寫入）：清理之後讀 summary，把 `requests_sent`、`requests_denied`、`traffic_seconds` 寫回 scanner_runs。
  - 沒寫過 policy（guard 不可用、plan 被拒絕、啟動前取消）：0。
  - 有 summary：以它為準；屬於別的 scan 或超過分到的數量就是不可信，留空。
  - 沒有 summary：guard 每轉送一個請求都先寫 summary，所以同一個 guard（`boot_id` 相同、沒有中斷）就是 0；guard 重啟或中斷過則留空。
  - 容器沒確認刪除（之後可能還在送），或 summary 是另一個 guard 寫的（`boot_id` 不同：重啟之後若 volume 沒有保留，新的 guard 從 0 開始計）：留空（security-reviewer 的 M5）。
- 剛好轉送完分到的最後一個請求、工具本來就要結束時，下一次心跳仍會停止容器（`timed_out`），輸出不收集。只在預算極小時發生，方向是保守的（code-reviewer 的 L6）。
- migration 0007：scanner_runs 加上 `requests_allotted`、`requests_sent`、`requests_denied`、`traffic_seconds`（都是非負整數或 null；有 `requests_sent` 就一定有 `requests_allotted`，而且不超過它）。

### 16.5 preflight 的執行路徑

- **何時**：scan 綁定 auth profile 時，`plan_runs` 在引擎之前加上一個 `preflight` run（sequence 1），fake 的 scan 也一樣（M2 唯一真的送出的流量，只到 lab 的 target，經 grant 與 guard）。preflight 是內部的引擎：請求中指定會回 422 `ENGINE_UNSUPPORTED`、不出現在 `GET /scanners`；runner 的能力回報仍包含它（認領要用）。共用 scan 的預算與速率，並計入請求數。
- **容器**：T10 的 busybox 映像（同一個 digest）與強化設定，命令是 `/bin/sh -c <固定的 script>`（script 是程式中的常數，不含任何輸入）。
  - 輸入：`in/request`（target 的 origin 加上 preflight 的 path；path 在建立 scan 時已確認在 grant 的範圍內，plan 再檢查一次格式）；secrets 目錄的 `proxy-url` 與 `auth-header`（完整的一行 header，例如 `Authorization: Bearer <token>`，0400）。有認證的 run 都會拿到 `auth-header`（M3 的引擎也可以用）。
  - runner 的白名單以 script 的 sha256 核准（`ArgumentDigest`，不在兩處各寫一次全文）；單元測試核對兩者一致，任何改動都要重新審查。
  - 送出兩個 HTTP/1.0 GET（經 guard）：帶認證一次、不帶認證一次，回應存成 `out/authenticated.http`、`out/anonymous.http`（各有大小上限）。
  - secret 只從檔案讀進管線，不進 argv、env、label 或 log。
- **判斷**（worker；§12.5 的純函式）：回應的 status 與 `expected_status` 相同、body 是嚴格的 JSON 且每個 JSON Pointer 都嚴格相等 → `passed`；否則 `failed`。匿名的請求也通過，或匿名的請求沒有有效的回應（沒有輸出、被 guard 拒絕）→ `inconclusive`：證明不了端點有受保護（審查後修正：原本匿名沒有回應仍判 `passed`，security-reviewer 的 M3）。
  - HTTP 回應的 header 以「名稱、冒號、去掉頭尾空白的值」分開比對，是線性的：原本的 regex 在長串空白加一個非法字元時會災難性回溯（靶機控制回應，security-reviewer 的 H1：16,000 個空白約 1.8 秒、平方成長）。
  - `header_line` 自己再擋換行與 NUL（縱深防禦：建立 profile 時的 `check_secret` 已經排除）。guard 拒絕（`X-Secscan-Guard`）→ `blocked`；容器失敗、沒有輸出、回應不是 HTTP 或超過 64 KiB → `not_executed`。
  - worker 以唯讀掛載 runs volume，只讀 manifest 列出的檔案（大小與 sha256 相符、不跟隨 symlink）。
  - 結果寫在 preflight run 的 `scanner_runs.preflight_result`（CHECK：只有 preflight 的 run 有值；實作時改的：原本打算另建 `scan_preflights` 表，一個 scan 只有一個 preflight run，欄位就夠了）。API 以 `auth.preflight` 揭露；還沒結束是 null，結束了卻沒有結果（失敗、取消）是 `not_executed`。
- preflight 不是 `passed` 時，之後的引擎照常執行，但 coverage 的 authenticated 計為 0（不以匿名結果冒充，CLAUDE.md §9）。
- in-process 的 fake runner（不送流量）把 preflight run 標成成功、結果 `not_executed`。
- 測試資料：integration 測試的 scan 預設改成匿名；需要認證的測試明確綁定 profile，並處理最前面的 preflight run。

### 16.6 coverage

worker 解析每個 run 時，把 telemetry 中轉送的請求與它的上游回應（依序號配對）對應到 scan 凍結、在範圍內的 operation：method 相同，operation 的 route 以 §11.6 的規則（不寬鬆）涵蓋請求的 path；同時符合多個時只算最具體的（佔位符最少）。結果寫進 `run_coverage`（run、operation、是否以認證取得回應；不可修改或刪除），並把 run 標成 `coverage_recorded`：
- 只算有上游回應的請求；帶認證 header 的請求取得 401、403 以外的回應才算 authenticated（審查後修正：原本只看送出，會高估，security-reviewer 的 M4）。
- preflight 的請求不算：它是平台的健檢探測，不是安全測試（code-reviewer 的 M2）。preflight 的 run 一律記成已量測、涵蓋 0 個。
- guard 記下沒有轉送任何請求（`requests_sent = 0`）→ 已量測、涵蓋 0 個。
- 有轉送、jsonl 完整（嚴格解析、最後一行有換行、回應都對得到請求）而且行數不超過轉送數 → 對應並標記。
- 轉送數不明或 telemetry 不完整 → 不標記。
- 已經記錄過就跳過：寫入之後、轉成 succeeded 之前中斷，退回 collected 之後重試仍能完成（code-reviewer 的 M1）。worker 遇到 lease 失效時記下來、留給對帳，繼續處理其他 run，不再讓整個程序結束。

API（跨 run 去重）：
- `coverage_measured`：有規格、所有 run 都結束（之後的引擎還會改變數字）、至少一個容器 run，而且每個容器 run 都已標記。observed 只取範圍內的 operation。
- `observed_operations`：有量測依據時的涵蓋數，否則 null。
- `authenticated_operations`：匿名的 scan 是 null；preflight 是 `passed` 時是帶認證 header 的涵蓋數；否則是 0，limitations 加上 `AUTHENTICATION_NOT_VERIFIED`。
- 帶認證 header 不代表伺服器接受了它：認證是否有效由 preflight 判斷（scan 層級），逐請求只排除 401、403。cookie 型的 profile 以 `Cookie` header 判斷：M3 的工具若帶著靶機發給匿名 session 的 cookie，也會被當成帶認證（code-reviewer 的 L3；M3 之前決定是否由 runner 在 policy 放入值的雜湊）。

### 16.7 錯誤碼與 API

- guard 的拒絕原因新增 `BUDGET_EXHAUSTED`、`RATE_LIMITED`（只在 guard 的回應 header 與 telemetry 中）。
- run 的錯誤碼 `BUDGET_EXHAUSTED`：開始之前剩 0 → `failed`；執行中用盡 → `timed_out`。DB 只檢查格式。
- API：scan 的 `budget_usage`（`requests_sent`、`requests_denied`、`traffic_duration_seconds`，跨容器 run 加總；有開始過的 run 任何一項不明時那一項是 null，和剩下預算的口徑一致）、coverage 的 `observed_operations`／`authenticated_operations`、`auth.preflight`。
- migration 0008：engine 的 CHECK 加上 `preflight`、sequence 的上限改成 5；`scanner_runs.preflight_result` 與 `coverage_recorded`；`run_coverage` 表。

### 16.8 取捨與不在 T12 範圍

- 名額在 `request` hook 才確定：少數在兩個 hook 之間失敗、又沒有觸發 `error` 的 flow 會佔著名額直到 run 結束（只會少放行）。
- telemetry 在 tmpfs：VM 重啟會遺失還沒解析的 run 的檔案；預算以 DB 的 `requests_allotted` 保守扣除，coverage 標成未量測。
- 只有被 worker 解析（collected）的 run 會對應 coverage：逾時、失敗、中斷的 run 送過的請求不計入 observed（`coverage_measured` 因此是 false，不會高估）。
- preflight 只送兩個請求：證明的是「這組憑證在這個端點有效」，不證明之後的引擎整段都維持登入狀態（M3 依量測再加上掃描中的重新驗證）。
- 拒絕的計數最多落後 5 秒；不影響預算。
- 速率以 scan 為 key、存在 guard 的記憶體：guard 重啟後第一個請求不必等待（最多多出一個 burst）。
- ZAP 的 reactive 407（先送一次不帶帳密的請求）不計入 run（還不知道是哪個 run）。
- **同時上傳的記憶體上限**（T11 的交接）：mitmproxy 把 body 讀進記憶體，被拒絕的請求 body 也會讀完（§15 實測 2）。曾把 `body_size_limit` 降到 1 MiB，但兩份審查都指出這個 option 可能同時限制回應的 body（**未驗證**：沒有對 mitmproxy 12.2.3 的原始碼或行為確認，也沒有 live 測試），1 MiB 若也限制回應，會擋掉 ZAP 爬取大型 JS，所以維持原本的 16 MiB（行為沒變）。M3 以大於 1 MiB 的回應驗證之後，才決定是否降低、或只限制請求。同時上傳太多時 guard 可能被 OOM 終止（記憶體上限 256 MiB）：guard 重啟，runner 依 `boot_id` 把 run 標成 interrupted（fail closed）。保留中的名額上限（§16.2）限制了每個 run 同時等待轉送的請求，但沒有限制被拒絕前讀進來的 body；M3 依工具的量測再決定是否限制每個 run 的連線數。
- **速率與預算以 scan 為單位**：SECURITY_AND_TESTING 的 SEC-13 寫「target 合計」。P0 只有一個 runner、同一個 target 同時只有一個 scan（409 `TARGET_BUSY`），兩者等價；多個 runner 時要改以 target 為 key（security-reviewer 的 L3）。
- telemetry 的 path 不遮罩：path 參數若是 ID 或 token，會明文留在 guard 的 tmpfs（只有 guard、runner、worker 讀得到，6 小時後刪除）。目前不經 API 輸出；之後放進報告時必須遮罩（security-reviewer 的 L2）。
- migration 0007 之前的容器 run 沒有 `requests_allotted`，轉送數不明時會當成 0。M2 之前沒有任何 run 送過流量，開發用的 DB 也沒有正式資料，所以不另外處理（security-reviewer 的 L4）。
- 不在 T12：grant 的其他 origin 與跨 origin 的認證規則；依量測調整 lab profile 的預算（M3）；`/health/ready`（T13）。

## 17. T13 補充決定：容器的對帳、孤兒容器、撤回授權與解析重試的上限（2026-10-30）

T13 補上 runner 中斷之後的收尾：有容器的 run 由 runner 內的 reconciler 依 DB 的紀錄找到容器、先封鎖 guard 再刪除、確認之後才結算；執行中的 scan 在授權撤回時停止；解析的重試有次數上限。以下是規劃文件沒有寫到、實作前才定下的細節。

使用者的決定（2026-10-29）：
- **`/health/ready`**：維持只檢查 DB 可連線與 schema 版本，不納入 runner、worker、guard 的狀態（它們由 `GET /scanners` 呈現）。ready 表示這個 API 程序能服務：沒有 runner 時 API 仍能接受並排入 scan；runner 重啟時不應讓 API 被判定不可用。
- **停止的條件**：執行中的 scan 在 grant 撤銷、過期、target 停用之外，**建立者的平台 key 被撤銷**時也停止（和 prepare 的檢查一致；key 到期不算，§13.5）。
- **解析重試的上限**：T13 一起做。worker 遇到單一 run 的非預期例外時記下例外的類別、繼續處理其他 run。

依據：
- DoD（`TASKS.md` T13）：重複認領時不會重複啟動容器；中斷後不會永遠停在 running；取消時先封鎖 guard，再回收容器。
- ARCHITECTURE §9：lease 過期不代表舊容器已經停止；runner 內的 reconciler 要核對 label、封鎖 guard、確認容器已終止；不能只因 lease 過期就啟動第二個掃描器。
- CLAUDE.md §8：開始發流量之後中斷就標 interrupted，不自動重跑；只有 parser 可以對不可變的 artifact 重試。
- socket-proxy 只比對 path（§14.1），不能限制 list 的 label 篩選，所以不放行 list：容器只能以 DB 中記下的名稱 inspect。

### 17.1 核心不變式

`renew_until` 在 DB 心跳**之前**讀取時間，只在心跳成功**之後**寫入 policy（§15.7），所以 `renew_until ≤ lease_expires_at`（runner 與 guard 共用 VM 的時鐘，T11 實測差距 0.05 秒以內）。對帳只處理 lease 已過期的 run：那時 guard 已經回 `POLICY_STALE`；凍結之後醒來的 owner 也不能再續約（過期的 lease 不能延長），它寫的 policy 同樣已過期。因此**封鎖是縱深防禦與證據，刪除容器不依賴封鎖成功**：封鎖失敗只記 log，仍然刪除容器。

### 17.2 容器的對帳（`runner/reconciler.py`）

- **誰、何時**：runner 程序內的 `ContainerReconciler`（只有 runner 能經 socket-proxy 操作容器）。啟動時一次，之後每 10 秒一次，在認領之前；單執行緒，監看一個長時間的 run 時不對帳（下一輪再處理）。
- **以 DB 為準**：`scanner_runs` 新增 `container_removed_at`（容器確認不存在的時間）。待處理的 run：`container_name IS NOT NULL AND container_removed_at IS NULL`，而且**不是**「runner 階段（running、collecting、cancelling）且 lease 還有效」。包含 lease 過期的、已結束但容器沒刪掉的，以及 worker 階段（collected、normalizing）但容器沒刪掉的。依建立的順序，每輪最多 20 個（部分索引 `ix_scanner_runs_pending_containers`）。
- **每個 run 的步驟**：
  1. 封鎖 policy：讀回 `<run_id>.json`、改成 blocked 寫回（已是 blocked 或不存在就不寫）。讀不出來、檔案損毀或寫不出去只記 log，繼續。
  2. 刪除這個 run 的 secret 目錄（失敗只記 log）。
  3. 以名稱 inspect，核對 label（`secscan.managed=true`、`secscan.run_id` 是這個 run）。
  4. 是我們的容器 → 強制刪除（SIGKILL，不等 5 秒的寬限：policy 已過期或已封鎖）；404 → 已不存在。
  5. DB（先鎖 scan、再鎖 run，和認領、prepare、取消相同的順序）：重新確認仍待處理，記下 `container_removed_at`；仍在 runner 階段（lease 已過期）→ interrupted（`LEASE_EXPIRED`），用量留空（之後的 run 以分到的數量扣除，§16.4），scan 重新彙總。其他狀態只記下時間，不改狀態。
  6. 結算成功之後才刪除 policy（T11 的「確認容器已刪除才刪 policy」）。
- **label 不符**：名稱唯一、label 在建立之後不能改，`secscan-run-<id>` 沒有我們的 label 就證明我們的容器不存在（或已被刪除後有人用了同一個名稱）。不動那個容器，記 ERROR，照常結算：留著不處理會讓 run 永遠停在 running，也會佔住每輪的名額。
- **Docker 出錯**：這個 run 留到下一輪，policy 保持 blocked，不宣稱已停止。
  - 409（刪除進行中），或 Docker 本身可用（`version` 有回應）、只有這個容器刪不掉（例如 500）：只延後那一個，繼續處理其他的；每個 run 只記一次 ERROR（審查發現：原本把任何錯誤都當成 Docker 不可用而中斷這一輪，排在最前面的壞掉的容器會讓其他孤兒永遠停在 running）。
  - Docker 不可用（`version` 也失敗）：這一輪停止。同一段中斷只記一次 WARNING，恢復時記一次 INFO。
  - inspect 的回應缺少 `Config` 視為格式不符（Docker 錯誤），不當成「不是我們的容器」。
  - **這是 DoD 2 唯一的例外**：Docker 長時間不可用、或某個容器一直刪不掉時 run 停在 running，但 guard 已經拒絕它的流量（policy 是 blocked，加上 dead-man switch），每 10 秒重試。每輪最多 20 個：超過 20 個容器同時一直刪不掉時，較新的要等它們處理完（初版只有一個 runner，記為限制）。
- **lease 過期的 run 一律 interrupted（`LEASE_EXPIRED`），要求過取消也一樣**：runner 遺失時無法證明 10 秒內停止了新的出站（API_CONTRACT §17.2 的語意）。
- **沒有容器的 run**：`reconcile_expired_runner(engines)` 把 runner 階段、lease 過期，而且 `container_name IS NULL`（preparing 時中斷、in-process 的 fake）**或 `container_removed_at IS NOT NULL`**（容器已確認刪除、還沒做最後的轉換就中斷）的 run 標成 interrupted（`LEASE_EXPIRED`），不呼叫 Docker。只看 `container_removed_at IS NULL` 會讓後者永遠停在 running（規劃時的審查發現）。in-process 的 `reconcile_expired` 也使用同樣的條件。
- **runner 自己記下刪除**：`record_usage(..., container_removed=…)` 在 `_cleanup` 確認刪除時寫入 `container_removed_at`（`coalesce`：不覆寫）；plan 被拒絕（從未建立容器）也寫入。正常結束的 run 不會進入待處理。
- **呼叫過 create 但沒有啟動成功**：create 或 start 回錯誤時，容器仍可能已經建立、甚至已經啟動（例如 client 逾時）。之後刪不掉就不轉成 failed（failed 會讓同一個 scan 的下一個引擎開始），run 留給對帳確認之後才結算（審查發現）。容器已結束（EXITED）而刪不掉的照常轉換：它不再送出流量，由對帳補刪。
- **不重複啟動（DoD 1）**：既有的 `FOR UPDATE … SKIP LOCKED` 認領、每次轉換都 fencing、過期的 lease 不能延長也不會被接手、容器名稱固定（重複 create 得到 409）。T13 再加上：
  - **建立容器之前再心跳一次**（secret 與 policy 寫好之後、create 之前）：lease 已失效 → `LeaseLostError`，不建立容器。縮小「凍結的 owner 在對帳之後才建立容器」的時間窗。
  - 下一個引擎要等前一個 run「不再送出流量」（`TRAFFIC_STOPPED_RUN_STATUSES`，§13.4）才可認領：lease 過期、容器還沒確認刪除的 run 仍是 running，同一個 scan 的下一個引擎不會開始。
- **殘餘風險**：owner 在建立前的心跳之後凍結、對帳在這段期間刪了它的 secret 與 policy、owner 醒來建立容器之後又馬上死掉：那個容器沒有 secret 的 subpath（預期無法啟動）、沒有有效的 policy，DB 也已結算，留下一個停止的容器。機率極低（兩個故障要剛好落在毫秒級的時間窗），記為已知限制。

### 17.3 `container_removed_at` 與 trigger（migration 0009）

- 欄位 `scanner_runs.container_removed_at timestamptz NULL`；CHECK：`container_removed_at IS NULL OR (container_name IS NOT NULL AND container_removed_at >= started_at)`。
- 只改 `scanner_runs_guard()`（巢狀的 IF：TRUNCATE、DELETE 時 NEW 是 NULL）：
  - `container_removed_at` 只能寫入一次（不能改、不能清除）。
  - 已終止的 run 只允許一種 UPDATE：`container_removed_at` 由 NULL 變成有值，其他欄位完全不變（`to_jsonb(NEW) - 'container_removed_at' = to_jsonb(OLD) - 'container_removed_at'`：之後新增的欄位也自動凍結）。
  - `scanner_runs_container_guard` 不必改：它先執行（trigger 依名稱的字母順序），名稱與映像不變時直接放行。
- 部分索引 `ix_scanner_runs_pending_containers (created_at) WHERE container_name IS NOT NULL AND container_removed_at IS NULL`。
- 不回填：升級之前的容器 run 都會成為待處理，由對帳每輪 20 個逐一確認（404 就結算）。
- 不用另一張表：待處理的查詢會變成對全部歷史的 anti-join，還需要另外的 trigger 與外鍵。

### 17.4 啟動時依證據清理（取代 §14.6 刪除全部的 sweep）

舊的做法在沒有其他存活的 runner 時刪除全部 secret 與 policy：孤兒容器的 policy 在容器確認刪除之前就被刪掉（違反 §15.7），runner 在 30 秒內重啟時又會整個跳過。改成：
- 列出 policy 目錄的 `<run_id>.json` 與 secrets 目錄的 `<run_id>/`，向 DB 查這些 run：
  - 待處理（容器還沒確認刪除），或 lease 還有效（另一個 runner 正在使用）→ 跳過，由對帳或 owner 處理。
  - 已結算，或 DB 沒有這個 run → 封鎖 policy → inspect，是我們的容器就強制刪除 → 刪除 secret 與 policy。刪不掉容器就保留 blocked 的 policy，下次啟動再處理。
- policy 目錄的暫存檔（`.tmp-*`）超過 60 秒才刪（可能是另一個 runner 正在寫的）。
- 列出之後才消失的條目跳過；目錄讀不出來時記 ERROR、跳過這次清理，不讓 runner 啟動失敗（對帳照常進行）。
- secret 目錄以 dir fd 加 `O_NOFOLLOW` 刪除：目錄被換成 symlink 時拒絕，不刪它指向的地方。
- 不再依賴 `others_alive()`。

### 17.5 授權撤回時停止執行中的 scan（SEC-01 後半）

- **心跳回報停止的原因**：`Heartbeat.stop_reason`。lease 有效、沒有要求取消時，以**不加鎖、重新 SELECT 的讀取**重新判斷 gate（`check_usable`、origin 與快照相同）與建立者的 key：
  - 不加鎖：心跳不等撤銷或停用的 `FOR UPDATE`；READ COMMITTED 下，已 commit 的撤銷在下一次心跳就看得到。停止的時間通常是 5 到 7 秒（心跳間隔加上監看迴圈的 1 秒與查詢的延遲）；runner 卡住時由 dead-man switch 在 lease 到期（30 秒）時擋下。撤銷、停用、撤銷 key 的 API 都不改（它們不鎖 scan，也就不會和 prepare 形成相反的鎖順序）。
  - 以 `populate_existing` 讀取，不用 session 中可能過時的物件。
  - 綁定的 profile 被 PATCH 不算（§14.12：已啟動的 run 不受影響）。
- 抽出 `scans/gate.py`（`RunGate`）：`locked` 給 prepare（照舊 `FOR SHARE`、時間在取得鎖之後才取），`current` 給心跳；兩者共用同一個判斷，prepare 的順序與錯誤碼不變。
- **runner**：心跳的處理順序是 lease 失效 → 要求取消 → `stop_reason` → 續約 → 預算用盡。`stop_reason` → 先封鎖、再停止容器 → **failed**（該錯誤碼），不收集輸出。建立容器之前的兩次心跳看到 `stop_reason` → 不建立容器 → failed。collecting 階段的心跳不理會（容器已結束，不再送出流量）；worker 不理會。
- **in-process 的 FakeRunner**：hold 期間看到 `stop_reason` → failed（該錯誤碼）。
- 不經 cancelling：只有要求過取消的 scan 能轉到 cancelling（DB 也這樣要求）。running → failed。
- grant 在執行中到期，現在以 `SCOPE_EXPIRED` 停止，不必等到 `TIME_LIMIT_EXCEEDED`（guard 原本就以 `not_after` 拒絕）。

### 17.6 解析重試的上限

- 不需要 migration：嘗試次數 = 這個 run 轉到 normalizing 的 `run.status` 事件數（`scanner_run_id` 與 payload 的 `status`；事件不可修改，計數不會被改小）。
- lease 過期的 normalizing：已嘗試 3 次（`MAX_PARSE_ATTEMPTS`）→ failed（新的錯誤碼 `PARSE_ATTEMPTS_EXHAUSTED`），否則退回 collected。worker、in-process 的 FakeRunner 與 runner 的對帳共用這段。
- worker：單一 run 的非預期例外只記 run_id 與例外的類別（輸出是不可信的資料，訊息可能含它的內容），繼續處理其他 run；那個 run 等 lease 過期之後由上面的規則處理。`LeaseLostError` 照舊；`SQLAlchemyError` 照舊讓程序結束（DB 不可用時繼續也沒有意義）。

### 17.7 錯誤碼

| 錯誤碼 | 情況 |
|---|---|
| `SCOPE_REVOKED`、`SCOPE_EXPIRED`、`SCOPE_NOT_APPROVED`、`TARGET_DISABLED`、`SCOPE_OUTSIDE_LAB`、`SCOPE_MISMATCH`、`CREATOR_KEY_REVOKED`（既有） | 也用於執行中：封鎖 guard → 停止容器 → failed |
| `LEASE_EXPIRED`（既有） | 也用於有容器的 run：對帳確認容器已刪除之後 → interrupted |
| `PARSE_ATTEMPTS_EXHAUSTED`（新） | 解析 3 次都沒有在 lease 內完成 → failed |

DB 只檢查錯誤碼的格式，不必為錯誤碼改 migration。

### 17.8 取捨與不在 T13 範圍

- Docker 長時間不可用時 run 停在 running（§17.2）；guard 仍拒絕流量。
- 預算：對帳結算的 run 用量留空（runner 遺失，無法確認 guard 的計數屬於哪一個 guard）。請求數以當初分到的數量扣除，而分到的是當時剩下的全部（§16.4），所以**同一個 scan 之後的引擎會以 `BUDGET_EXHAUSTED` 失敗、不送流量**；時間以開始到結束計算，把對帳的延遲（最多約 30 秒的 lease 加上 10 秒的間隔）也算進去。scan 本身已經是 interrupted（彙總時優先），方向是保守的；integration 測試以這個結果確認不重複啟動。
- trigger 放寬了已終止的 run：只允許單一欄位由 NULL 變成有值，其餘欄位以 `to_jsonb` 比較。
- 單執行緒的迴圈在長時間的 run 期間不對帳；初版只有一個 runner。
- inspect 到 remove 之間的 TOCTOU：socket-proxy 只允許以名稱刪除（不能用容器 ID），名稱固定是 `secscan-run-<run_id>`（DB 的 CHECK 與 proxy 的 regex）；要在毫秒內刪除並以同名重建，需要能直接操作 Docker。記為已接受的殘餘風險（security-reviewer 的 L3）。runner 自己的 `_cleanup` 也是以名稱直接刪除。
- 不在 T13：queued 的 scan 的時間上限（runner 長期不在時，使用者可以取消）；多個 runner 同時運作（目前的設計對兩個 runner 是安全的，但 proxy 憑證、速率與預算仍以單一 runner 為前提）；worker 解析時的心跳（M3 的真 parser 可能超過 30 秒）；runs volume 的保留期限（M5／T23）；T11 的證據缺口（同一條連線上多個請求的收包證據）；預算以 target 合計（多個 runner 時）。

## 18. T14 補充決定：ZAP 的 ExecutionPlan、capability probe 與容器政策（2026-10-30）

T14 讓 runner 以強化的單次容器執行 ZAP：伺服器產生 Automation Framework（AF）plan，容器的政策、secret 與輸出的收集都配合一個真的工具調整。以下是規劃文件沒有寫到、實作前才定下的細節，以及推翻既有文件的地方。

使用者的決定（2026-10-30）：
- **zap 在 T15 才對操作者開放**（和 parser 一起），`GET /scan-profiles` 也移到 T15（推翻 §13.11 的交接、`TASKS.md` T09 的「M3（T14）：開放 zap」與 `API_CONTRACT.md` 的對應列）。理由：worker 只認領 fake 與 preflight，COLLECTED 只能轉 NORMALIZING、取消也移不動；parser 之前開放，zap 的 run 會停在 collected，scan 永遠不結束（同一個 target 一直回 409）。T14 的 API 照舊回 `ENGINE_UNSUPPORTED`；live 測試以只在 `secscan-live` 設定的預覽開關建立 zap scan（§18.9），T15 移除。
- **capability probe 以執行容器驗證**：以和掃描相同的強化設定實際啟動 ZAP，確認版本、add-on、規則白名單與輸出可寫（ARCHITECTURE §5：檢查實際的 executable、版本、設定檔與輸出）。

依據：
- DoD（`TASKS.md` T14）：使用 `-silent` 與伺服器產生的 AF plan；auth 以 `ZAP_AUTH_HEADER*` 環境變數注入、沒有 auth 的 profile 明確標為 anonymous；API spec 的 origin 綁定到核准目標、profile 與 method 不相容時拒絕。
- ZAP 的原始碼與鎖定映像的實測（`TOOLS.md` §7；離線量測一律 `--network none`）：
  - `ZAP_AUTH_HEADER_SITE` 以 `getHostName().contains(site)` 比對（子字串，不含 port）；header 以 `setHeader` 覆寫同名的 header（`HttpSenderAuthHeaderListener`）。
  - AF 的 `env.parameters.maxDuration` 單位是秒，到期時 `stopPlan(false)`：沒有 `alwaysRun` 的 job 被略過，`alwaysRun: true` 的 report 仍會執行；退出碼：plan 有錯誤是 1、有警告是 2（`failOnWarning: false` 也一樣）、否則 0（`ExtensionAutomation`）。job 的 duration 單位是分鐘，0 是不限。
  - AF 的參數支援 `${環境變數}` 的代換。
  - `zap.sh` 只認 cgroup v1 的記憶體上限（OrbStack 是 v2，會算出 VM 的 1/4），但會讓 `-Xmx…` 參數覆寫。
  - 映像以 uid 1000、`HOME=/home/zap/` 為前提，並宣告 `HEALTHCHECK`（每 30 秒在容器內執行 curl）。
  - **`-configfile` 套用時會以 INFO 記下 `Setting config … = <值>`**（含 proxy 的密碼；T03 的結論只在當時的組合成立）。加上 `-nostdout` 時 stdout 沒有這一行（實測 0 次）；ZAP home 中的 `zap.log` 仍有，home 在 tmpfs、隨容器刪除。
  - network add-on 的速率限制以 `network.ratelimit.rules.rule(i).{description,enabled,matchStr,regex,reqsPerSec,groupBy}` 設定（以 host 完整比對），`-configfile` 寫入的值以 API 讀回確認生效。
  - `activeScan-policy` 遇到不存在的規則 ID 會警告（`Unrecognised active scan rule ID`），退出碼是 2。

### 18.1 推翻或修改既有文件的地方

| 原本 | 改成 | 理由 |
|---|---|---|
| T14 開放 zap 與 `GET /scan-profiles` | 移到 T15 | 使用者決定（上方） |
| §14.6 第 5 步：非 0 的退出一律 `ENGINE_FAILED`、不收集 | 每個引擎宣告要收集的退出碼：fake、preflight 是 {0}，zap 是 {0, 1, 2}；manifest 記下 `exit_code`，退出碼的語意由 T15 的 parser 判斷 | AF 有警告就以 2 退出；T15 的 DoD「非零退出不一律當成 crash」 |
| §14.4、SEC-21 的竄改表：`Tmpfs` 一律拒絕 | 只接受引擎政策宣告的固定值（zap 的 `/tmp`）；送出前的檢查以自己的一份字面值核對 | ZAP 需要可寫的 home 與 JVM 的暫存；放在 out/ 會收集到 session DB（含注入的認證）與 `config.xml`（含 proxy 的密碼） |
| §14.4：create 的 body 只有 7 個頂層欄位 | 所有引擎都加 `Healthcheck: {"Test": ["NONE"]}`，逐字核對 | 不讓 Docker 在掃描容器內定期執行映像宣告的指令 |
| ARCHITECTURE §6：`engine_version` 在 M3 | 版本由 probe 依映像 digest 取得、顯示在 `GET /scanners`；每個 run 的版本與輸入的 hash 由 T15 的 artifacts 資料表保存，T14 先寫進 manifest | T14 不加 migration（規劃時的審查建議） |

### 18.2 ZAP 的執行方式

- 映像：T03 鎖定的 `zaproxy/zap-stable:20261016@sha256:5ccfff9a…`（2.17.0）。`make images` 以 digest pull；socket-proxy 的映像白名單同時加入。
- 指令：`/bin/sh -c <script>`，script 以 sha256 核准（同 preflight；`scanners/domain/zap/script.py`）。只用 shell 內建的指令處理 secret（不會出現在任何子程序的 argv），不印出任何一行：
  - `SECSCAN_TARGET_AUTH=none`：`unset ZAP_AUTH_HEADER*`；secret 目錄中有 `auth-header` 就 exit 64。
  - `SECSCAN_TARGET_AUTH=header`：`ZAP_AUTH_HEADER` 必須有值；以 `IFS= read -r` 讀 `auth-header`，前綴必須是 `"$ZAP_AUTH_HEADER: "`（否則 exit 64），去掉前綴之後 `export ZAP_AUTH_HEADER_VALUE`。
  - 其他值 exit 64；out/ 寫不了 exit 65（不用 `set -eu`：dash 在這些錯誤時以 2 退出，會和 AF 的「有警告」混淆）。
  - 最後 `exec /zap/zap.sh -Xmx1536m -cmd -silent -nostdout -dir /tmp/zap -configfile /scan/secret/zap.properties -autorun /scan/in/plan.yaml > /scan/out/zap.log 2>&1`。`-nostdout` 是安全上必要的旗標（上方依據）。
- plan 的環境變數（非秘密；政策以 regex 核對）：`SECSCAN_TARGET_AUTH`；header 模式另外有 `ZAP_AUTH_HEADER`（credential 的 wire header 名稱）與 `ZAP_AUTH_HEADER_SITE`（target 的 host）。`ZAP_AUTH_HEADER_VALUE` 永遠不能出現在 plan（白名單沒有它）。admission 另外要求：`SECSCAN_TARGET_AUTH=header` 若且唯若 `plan.target_auth`，header 模式一定有另外兩個變數、none 模式一定沒有。
- **anonymous 是明確的值**：plan builder 的認證輸入是 `ZapAuth`（`ANONYMOUS` 或某個 header 名稱），沒有預設值；scan 的 `auth_role` 照舊是 `anonymous`。
- `ZAP_AUTH_HEADER_SITE` 只算縱深防禦（子字串比對）；邊界是 guard 只放行 target origin（§15.5）。
- 容器：uid 10001、唯讀 rootfs、`CapDrop ALL`、no-new-privileges、`Init`（同 §14.4）；`Tmpfs {"/tmp": "rw,noexec,nosuid,nodev,size=768m,mode=1777"}`（實測 `noexec` 可用）；記憶體 3 GiB（含 tmpfs，不能用 swap）、`-Xmx1536m`、2 個 CPU、1024 個 pid、`nofile` 1024（共用的值）。都是起始值，live 量測之後在 T16 調整。
- stop 的寬限維持 5 秒：先封鎖 guard，ZAP 之後送出的請求都被拒絕；SIGTERM 之後的行為在 live 量測（§18.10）。

### 18.3 proxy 與速率的設定檔

- runner 寫一個新的 secret 檔 `zap.properties`（0400；加入 `SECRET_FILES`：容器刪除之後和其他 secret 一起刪掉，T13 啟動時的清理也認得它，否則 `rmdir` 會失敗）：
  - `network.connection.httpProxy.{enabled,host,port,authEnabled,username,password,realm}`：username 是 run_id、password 是 token。
  - `network.ratelimit.rules.rule(0)`：`matchStr=.*`、`regex=true`、`reqsPerSec` 是 scan 的速率、`groupBy=RULE`（所有 host 共用一個上限）。ZAP 自己限速，guard 仍然強制。
  - 每個值以嚴格的字元集核對（token 是 43 個 base64url 字元；host 是 IPv4 或名稱）。ZAP 對不認得的 key 不報錯：live 一定要確認 guard 有轉送（forwarded > 0），否則設定沒有生效也看不出來。
- 三種 auth 都是一個 header：bearer → `Authorization: Bearer …`、`api_key_header` → 自訂的名稱、cookie → `Cookie`。

### 18.4 AF plan（`scanners/domain/zap/`，純函式）

- 輸出 JSON（也是合法的 YAML 1.1；測試以 PyYAML 解析，和 ZAP 的 SnakeYAML 一樣），寫成 `in/plan.yaml`。
- **context**：一個，`urls` 是 origin 加上起點。`includePaths` 由 grant 的 path 翻譯：literal 與 `{name}` 的路由（佔位符是 `[^/?#]+`）；英數字以外的字元一律以反斜線跳脫（Java 與 Python 的 regex 都當成字元本身，測試因此能以 Python 對照）；後面接 `(?:\?.*)?`；`allow_all_paths` 是整個 origin。`excludePaths` 不分大小寫，語意和 `covers(…, lenient=True)` 相同（排除路由本身與它底下的 path）。
- 輸出的任何字串含 `${` 就拒絕：AF 會代換環境變數，可能把 secret 帶進 plan 或請求。
- **web（`web_active_lab`）**：`spider` 從 `/` 開始，`threadCount 1`；`postForm` 只在 grant 允許 POST 時打開；`parseRobotsTxt`、`parseSitemapXml` 只在 `/robots.txt`、`/sitemap.xml` 在範圍內時打開；Git、DS_Store、SVN 一律關閉。
- **api（`api_active_lab`）**：`openapi`（`apiFile: /scan/in/openapi.json`，`targetUrl` 是 origin 加 base path）。
- **共同**：`passiveScan-config`（`scanOnlyInScope`）→ `passiveScan-wait` → `activeScan`（`threadPerHost 1`；inline 的 `policyDefinition`：**`defaultThreshold: off` 加上審查過的規則白名單**，web 與 api 各一份，起始強度 low）→ `report`（`alwaysRun: true`；範本**只能是** `traditional-json`：`-plus` 含請求的 header，也就含注入的 secret；`/scan/out/zap-report.json`）。
- `env.parameters`：`failOnError: true`、`failOnWarning: false`、`progressToStdout: true`、`maxDuration`（§18.5）。
- **規則白名單**（`TOOLS.md` §7 列出 53 條規則的審查）：以類別排除 OAST 與 OUT_OF_BAND（Log4Shell、XXE、SSTI Blind）、HTTPS 與非 HTTP 的協定（HTTPS Content Available via HTTP、HTTP Only Site、Heartbleed）、DoS 類（Buffer Overflow、Format String、Billion Laughs）、需要瀏覽器的（DOM XSS）、會改 Host 的（Cloud Metadata）、script 規則、SOAP、alpha 的規則、雜訊（User Agent Fuzzer）、時間型的注入（會讓靶機延遲回應、耗掉時間預算；T16 再評估）。web 以全部 53 條為基準去掉上述類別；api 以 ZAP 自己的 API-Minimal policy 為基準去掉上述類別。GET for POST 會把 POST 改成 GET，只放在 web（web 一定允許 GET）。probe 確認每一條都存在。

### 18.5 時間與預算

- `maxDuration` = min（剩下的時間、`floor(分到的請求數 / 速率)`、grant 的 `valid_until − now`）− 60 秒（JVM 啟動與報告的保留時間）。預算或時間用完之前 ZAP 自己停止，report 仍會寫出（退出碼 2）。job 的上限以分鐘計，至少 1（0 是不限）。
- 算出來不到 60 秒：不建立容器，failed（`BUDGET_EXHAUSTED`，不送流量）。
- runner 的牆鐘上限照舊是硬性的上限（`TIME_LIMIT_EXCEEDED`）；guard 回報預算用盡時照舊立刻停止、不收集（T15／T16 檢討：ZAP 自己的速率加上這裡的計算，正常情況下不會先用完請求數）。

### 18.6 交給 ZAP 的規格（API profile）

- `specs/domain/tool_document.py`（純函式）：只留下 scan 建立時判斷為 eligible 的 operation（method 加上含 base path 的 path）；保留 path 層級的 `parameters`；刪掉沒有 operation 的 path item 與 `x-` 開頭的 path key；以 `check_references` 重新檢查（`operationRef` 或 `#/paths/…` 指到被刪的 operation 時 fail closed）；斷言 `servers` 恰好是 `[{"url": scan 的 origin + base path}]`（上傳時已改綁，不符代表資料損毀 → `PLAN_REJECTED`）；輸出和 `openapi.py` 相同的 compact JSON。
- 只有 zap 的 api profile 在 prepare 中讀出文件、sha256 和 DB 中的值核對，以及 eligible 的 operation。兩者都不可變，不另外加鎖（維持 scan → run 的鎖順序）；過濾在 transaction 之外進行。

### 18.7 profile 與 method

- 建立 scan 時（只在 engines 含 zap 時）：`web_active_lab` 需要 grant 允許 `GET /`（spider 的起點固定是 `/`）；`api_active_lab` 照舊需要至少一個 eligible 的 operation。不符 → 422 `PROFILE_INCOMPATIBLE`。只檢查 zap：fake 不送流量，不需要起點。
- runner 端的 plan builder 再檢查一次（`PLAN_REJECTED`）；plan 也依 grant 調整（`postForm`、robots 與 sitemap），白名單不收會改 method 的規則（api）。
- runner 的加固：`_plan` 依引擎完整分派、沒有預設的分支（原本 zap 的 lease 會拿到 fake 的 plan、記成 zap）；admission 核對 plan 的引擎等於 lease 的引擎、映像等於 prepare 記下的 `image_ref`。

### 18.8 capability probe（`runner/engine_probe.py`）

- runner 對 zap 的映像 digest 執行一次 probe 容器：同一套 `build_container`（uid 10001、唯讀、tmpfs、`-dir`）；每次用新的 uuid4（workspace 的目錄不會重用）；建立空的 secret 目錄（runner 中斷時，T13 的啟動清理依它找回容器並刪除）；不寫 guard 的 policy（不需要網路）。
- probe 的 script（另一個以 sha256 核准的樣板）：`ls /zap/plugin` 寫到 `out/plugins.txt`，再以一個 JVM 執行最小的 AF plan：兩個 `activeScan-policy`（web 與 api 的白名單）加上 `report`；context 是 `.invalid`，不送任何請求。
- 檢查：退出碼 0（白名單的規則都存在，否則 AF 警告、退出 2）；報告的 `@version` 等於鎖定的版本；`plugins.txt` 中必要的 add-on 都在、而且是審查過的版本（同一個 add-on 有多個檔案時取最大的版本，和 ZAP 的載入規則相同）。輸出都是不可信的資料：有大小上限、逐行以 regex 解析。
- 非阻塞：runner 的迴圈每圈前進一步（建立、查狀態、讀結果、刪除），probe 期間照常認領 fake 與 preflight；容器有牆鐘上限（180 秒）。成功以 digest 快取（同一個程序不再執行）；失敗以 10 分鐘的退避重試。runner 停止時刪除執行中的 probe 容器。
- capability 只記版本與必要 add-on 的版本（JSONB ≤ 4096 bytes）；`GET /scanners` 加上 `version`。新的能力代碼：`ENGINE_PROBE_PENDING`（還沒驗證完）、`ENGINE_PROBE_FAILED`（容器失敗、逾時或輸出讀不到）、`ENGINE_INCOMPATIBLE`（版本、add-on 或規則不符）。API 與 runner 同時更新（§15.8）。

### 18.9 預覽開關（T15 移除）

- API 的 `SCAN_PREVIEW_ENGINES`：預設是空的、只接受 `zap`、啟動時記一筆 WARNING。開啟時 `POST /scans` 接受 zap，`GET /scanners` 的 zap 以 runner 回報的 probe 結果判斷是否可用（`integrated` 仍是 false：`integrated=false` 而 `available=true` 只會出現在這個開關）。
- 只有 live 的 compose（`make test-live-zap`）設定它。開關打開時建立的 zap scan 會停在 collected（worker 還不解析），所以只在拆除的 live 環境使用。

### 18.10 量測的交接（live）

- path 中的 `%` 與 body 的 `_method`（§15.10）、大於 1 MiB 的回應（§16.8）、cookie 與 ZAP 自己的 session cookie 怎麼合併（決定 §16.6 的 `auth` 旗標）、ZAP 收到 SIGTERM 之後的行為（§17.8）、參照炸彈、discriminator 與 links、說明用的 URL（§11.9）：都在 `make test-live-zap` 量測，結果記在 `TOOLS.md` §7。T14 不放寬 guard 的任何檢查。

### 18.11 錯誤碼與能力代碼

| 代碼 | 情況 |
|---|---|
| `PROFILE_INCOMPATIBLE`（既有，422） | 也用於：zap 的 web profile，但 grant 不允許 `GET /` |
| `PLAN_REJECTED`（既有） | 也用於：servers 不符、引擎或映像和 lease 不一致 |
| `BUDGET_EXHAUSTED`（既有） | 也用於：剩下的時間或請求數不夠 ZAP 執行（不建立容器） |
| `ENGINE_FAILED`（既有） | 退出碼不在收集的清單中（含 script 的 64、65） |
| `ENGINE_PROBE_PENDING`、`ENGINE_PROBE_FAILED`、`ENGINE_INCOMPATIBLE`（新，能力代碼） | probe 還沒完成、失敗、版本或 add-on 或規則不符 |

### 18.12 殘餘風險與不在 T14 範圍

- 認證值在容器內的 `/proc/<pid>/environ` 讀得到（同一個 uid，也就是 ZAP 本身）；不在 Docker 的設定、argv、label 中。
- ZAP 的 session DB、`config.xml` 與 home 的 `zap.log`（含 proxy 的密碼）在 tmpfs，隨容器刪除。
- `out/zap.log` 與報告的 evidence 可能含有靶機回應的內容（不可信的資料）；以已知的 secret 精確遮罩在 T15。
- guard 回報預算用盡時不收集（T15／T16）；ZAP 分到 scan 剩下的全部預算（§16.4），M4 加入 Nuclei 時檢討。
- `ZAP_AUTH_HEADER_SITE` 是子字串比對；預覽開關存在於 T14 與 T15 之間。
- 不在 T14：parser、觀察、退出碼的語意、排除 guard 的回應、遮罩（T15）；Juice Shop、VAmPI、預算的調整、token 失效（T16）；HTTPS、AJAX spider、queued scan 的時間上限、多個 runner；T11 的證據缺口（同一條連線上多個請求的收包證據）仍記為未實作。

## 來源

`[Sxx]` 對照見 `docs/SOURCES.md`。
