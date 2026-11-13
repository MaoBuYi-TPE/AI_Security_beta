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
  - **已由 §31（T23b-b1）處理**：schema 改由 owner 角色擁有，應用程式角色只有逐表 DML（audit_events 只有 SELECT、INSERT）。共用角色等剩餘風險見 §31.9。
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
  - API 從不解密：新版本沿用 secret 時，直接複製密文。（T23a 更新：API 仍從不解密**目標的 secret**；另外持有報告內容與人工複測摘錄的金鑰，只在報告下載與 triage 事件中解密，見 §30.2。）
  - 以 AST 測試固定：src 中沒有任何模組呼叫 `reveal`（做法同 §9.1 的 `issue_admin_key`）。M2 的 runner 會是唯一的例外，屆時更新測試。
  - 以 import-linter 固定：只有 `security.secret_cipher` 可以 import `cryptography`，其他模組無法繞過 `SecretCipher` 自己解密（含間接 import）。（T23a 更新：另加 `security.blob_cipher`，見 §30.2。）
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
| normalizing | succeeded、failed、timed_out（T15：引擎在自己的時間上限停止）、collected（lease 過期：解析可以重試） |
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
- **T15 修改（§19.8）**：preflight 不算結果引擎。全部終止時，timed_out、completed、partially_completed 只看掃描引擎；掃描引擎全部 succeeded 而 preflight 沒有成功是 partially_completed；掃描引擎都沒有成功是 failed（原本 preflight 成功、zap 失敗是 partially_completed）。interrupted 仍看所有的 run。

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
- api 與 runner 都持有 `SECRET_ENCRYPTION_KEYS` 與同一個 DB 角色：「只有 runner 呼叫 reveal」是程式層級的約束（AST 測試），不是權限邊界。分開金鑰與 DB 角色在 T23。（T23a 更新：新增的原始證據金鑰只給 runner、內容金鑰只給 api 與 worker，見 §30.2；`SECRET_ENCRYPTION_KEYS` 仍由 api 與 runner 共用，DB 角色的分開仍在 T23b。）
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

拒絕的回應：403，附 `X-Secscan-Guard: <原因>` 與一行純文字。M3 的 parser 依這個 header 排除 guard 的回應（T15 修改：ZAP 允許的報告範本沒有 header，改成 §19.4 的分層判斷；preflight 仍依這個 header 判斷）。

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
- path 中的 `%` 一律拒絕：會擋掉工具放在 path 的 payload，部分 ZAP 檢查無法執行；刻意 fail closed，M3 依量測決定。T16 的量化見 §20.7；2026-11-01 使用者決定有條件放寬（T33），目前暫緩，規則不變（§21）。
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
- M3：工具的 proxy 設定格式；HTTPS（CA、上游憑證驗證）；排除 guard 的回應（T15 的做法見 §19.4）。

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
| ARCHITECTURE §6：`engine_version` 在 M3 | 版本由 probe 依映像 digest 取得、顯示在 `GET /scanners`；每個 run 的版本與輸入的 hash 由 T15 的 artifacts 資料表保存；T14 的 manifest 先記下退出碼與輸入檔的 hash（映像的 digest 在 DB 的 `image_ref`，每個 run 的 ZAP 版本在 T15 記錄） | T14 不加 migration（規劃時的審查建議） |

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
- **context**：一個，`urls` 是 origin 加上起點。`includePaths` 由 grant 的 path 翻譯：literal 與 `{name}` 的路由（佔位符是 `[^/?#]+`）；英數字以外的字元一律以反斜線跳脫（Java 與 Python 的 regex 都當成字元本身，測試因此能以 Python 對照）；後面接 `(?:\?.*)?`；`allow_all_paths` 是整個 origin。`excludePaths` 的語意和 `covers(…, lenient=True)` 相同（段數相同、不分大小寫、忽略結尾的斜線；不涵蓋底下的 path）。AF 會把每個 context 的 `urls` 加成 `url + ".*"` 的 include（不跳脫，`TOOLS.md` §7.2），只靠 `includePaths` 擋不住範圍外的 path：`excludePaths` 另加一條「完整比對不到任何一條允許的 regex」的負向前瞻 `(?!(?:A|B)(?![\s\S])).*`（`scope.py`；和 guard 的 `covers()` 以性質測試對照；結尾不用 `$`：它在結尾的換行之前也成立）。
- 輸出的任何字串含 `${` 就拒絕：AF 會代換環境變數，可能把 secret 帶進 plan 或請求。
- **web（`web_active_lab`）**：`spider` 從 `/` 開始，`threadCount 1`；`postForm` 只在 grant 允許 POST 時打開；`parseRobotsTxt`、`parseSitemapXml` 只在 `/robots.txt`、`/sitemap.xml` 在範圍內時打開；Git、DS_Store、SVN 一律關閉。
- **api（`api_active_lab`）**：`openapi`（`apiFile: /scan/in/openapi.json`，`targetUrl` 是 origin 加 base path）。
- **共同**：`passiveScan-config`（`scanOnlyInScope`）→ `passiveScan-wait` → `activeScan`（`threadPerHost 1`；inline 的 `policyDefinition`：**`defaultThreshold: off` 加上審查過的規則白名單**，web 與 api 各一份，起始強度 low）→ `report`（`alwaysRun: true`；範本**只能是** `traditional-json`：`-plus` 含請求的 header，也就含注入的 secret；`/scan/out/zap-report.json`）。
- `env.parameters`：`failOnError: true`、`failOnWarning: false`、`progressToStdout: true`、`maxDuration`（§18.5）。
- **規則白名單**（`TOOLS.md` §7 列出 53 條規則的審查）：以類別排除 OAST 與 OUT_OF_BAND（Log4Shell、XXE、SSTI Blind）、HTTPS 與非 HTTP 的協定（HTTPS Content Available via HTTP、HTTP Only Site、Heartbleed）、DoS 類（Buffer Overflow、Format String、Billion Laughs）、需要瀏覽器的（DOM XSS）、會改 Host 的（Cloud Metadata）、script 規則、SOAP、alpha 的規則、雜訊（User Agent Fuzzer）、時間型的注入（會讓靶機延遲回應、耗掉時間預算；T16 再評估）。web 以全部 53 條為基準去掉上述類別；api 以 ZAP 自己的 API-Minimal policy 為基準去掉上述類別。GET for POST 會把 POST 改成 GET，只放在 web（web 一定允許 GET）。probe 確認每一條都存在。

### 18.5 時間與預算

- `maxDuration` = min（剩下的時間、`floor(分到的請求數 / 速率)`、grant 的 `valid_until − now`）− 60 秒（JVM 啟動與報告的保留時間）。預算或時間用完之前 ZAP 自己停止，report 仍會寫出（退出碼 2）。job 的上限以分鐘計，至少 1（0 是不限）。**T16 推翻**：job 的上限一律是 0，只由 plan 的 maxDuration 限制（§20.5）。
- 算出來不到 60 秒：不建立容器，failed（`BUDGET_EXHAUSTED`，不送流量）。
- runner 的牆鐘上限照舊是硬性的上限（`TIME_LIMIT_EXCEEDED`）；guard 回報預算用盡時照舊立刻停止、不收集（T15／T16 檢討：ZAP 自己的速率加上這裡的計算，正常情況下不會先用完請求數）。

### 18.6 交給 ZAP 的規格（API profile）

- `specs/domain/tool_document.py`（純函式）：只留下 scan 建立時判斷為 eligible 的 operation（method 加上含 base path 的 path）；保留 path 層級的 `parameters`；刪掉沒有 operation 的 path item 與 `x-` 開頭的 path key；以 `check_references` 重新檢查（`operationRef` 或 `#/paths/…` 指到被刪的 operation 時 fail closed）；斷言 `servers` 恰好是 `[{"url": scan 的 origin + base path}]`（上傳時已改綁，不符代表資料損毀 → `PLAN_REJECTED`）；輸出和 `openapi.py` 相同的 compact JSON。
- 只有 zap 的 api profile 在 prepare 中讀出文件、sha256 和 DB 中的值核對，以及 eligible 的 operation。兩者都不可變，不另外加鎖（維持 scan → run 的鎖順序）；過濾在 transaction 之外進行。

### 18.7 profile 與 method

- 建立 scan 時（只在 engines 含 zap 時）：`web_active_lab` 需要 grant 允許 `GET /`（spider 的起點固定是 `/`）；`api_active_lab` 照舊需要至少一個 eligible 的 operation。不符 → 422 `PROFILE_INCOMPATIBLE`。只檢查 zap：fake 不送流量，不需要起點。
- runner 端的 plan builder 再檢查一次（`PLAN_REJECTED`）；plan 也依 grant 調整（`postForm`、robots 與 sitemap），白名單不收會改 method 的規則（api）。
- **會改 method 的規則依 grant 篩選**（T14 的審查 L5；live 量到 grant 只允許 GET、HEAD 時仍有 52 個 POST 被 guard 擋下，§18.10）：ZAP 的原始碼中，20018（CVE-2012-1823 RCE）與 40048（React2Shell）一律送 POST，40045（Spring4Shell）先送 GET、再送 POST，10058（GET for POST）把 POST 改成 GET。grant 不允許那個 method 時，`policy_definition` 不放進那條規則（`METHOD_SWITCHING_RULES`）。依據是 zap-extensions main 分支的原始碼，不是鎖定的 ascanrules 84 的原始碼；live 以 method 分別計數驗證。guard 仍是邊界，其他規則送出 grant 以外的 method 時照樣被拒絕。
- runner 的加固：`_plan` 依引擎完整分派、沒有預設的分支（原本 zap 的 lease 會拿到 fake 的 plan、記成 zap）；admission 核對 plan 的引擎等於 lease 的引擎、映像等於 prepare 記下的 `image_ref`。

### 18.8 capability probe（`runner/engine_probe.py`）

- runner 對 zap 的映像 digest 執行一次 probe 容器：同一套 `build_container`（uid 10001、唯讀、tmpfs、`-dir`）；每次用新的 uuid4（workspace 的目錄不會重用）；建立空的 secret 目錄（runner 中斷時，T13 的啟動清理依它找回容器並刪除）；不寫 guard 的 policy（不需要網路）。
- probe 的 script（另一個以 sha256 核准的樣板）：`ls /zap/plugin` 寫到 `out/plugins.txt`，再以一個 JVM 執行最小的 AF plan：兩個 `activeScan-policy`（web 與 api 的白名單）加上 `report`；context 是 `.invalid`，不送任何請求。
- 檢查：退出碼 0（白名單的規則都存在，否則 AF 警告、退出 2）；報告的 `@version` 等於鎖定的版本；`plugins.txt` 中必要的 add-on 都在、而且是審查過的版本（同一個 add-on 有多個檔案時取最大的版本，和 ZAP 的載入規則相同）。輸出都是不可信的資料：有大小上限、逐行以 regex 解析。
- 非阻塞：runner 的迴圈每圈前進一步（建立、查狀態、讀結果、刪除），probe 期間照常認領 fake 與 preflight；容器有牆鐘上限（180 秒）。成功以 digest 快取（同一個程序不再執行）；失敗以 10 分鐘的退避重試。runner 停止時刪除執行中的 probe 容器。每次 probe（成功、失敗或沒有啟動）的 `in/`、`out/` 和掃描的 run 一樣留在 runs volume（保留期限在 M5／T23）；退避讓失敗時每 10 分鐘最多多一個目錄。
- capability 只記版本（JSONB ≤ 4096 bytes）：必要 add-on 的版本由 probe 核對、不另外保存（每個 run 的版本與 add-on 在 T15 的 artifacts 資料表）；`GET /scanners` 加上 `version`。新的能力代碼：`ENGINE_PROBE_PENDING`（還沒驗證完）、`ENGINE_PROBE_FAILED`（容器失敗、逾時或輸出讀不到）、`ENGINE_INCOMPATIBLE`（版本、add-on 或規則不符）。API 與 runner 同時更新（§15.8）。

### 18.9 預覽開關（T15 已移除，§19.10）

- API 的 `SCAN_PREVIEW_ENGINES`：預設是空的、只接受 `zap`、啟動時記一筆 WARNING。開啟時 `POST /scans` 接受 zap，`GET /scanners` 的 zap 以 runner 回報的 probe 結果判斷是否可用（`integrated` 仍是 false：`integrated=false` 而 `available=true` 只會出現在這個開關）。
- 只有 live 的 compose（`make test-live-zap`）設定它。開關打開時建立的 zap scan 會停在 collected（worker 還不解析），所以只在拆除的 live 環境使用。compose 以 live 專用的 `SECSCAN_LIVE_PREVIEW_ENGINES` 插值，`make up` 明確清空它、`make dev` 明確清空 `SCAN_PREVIEW_ENGINES`（環境變數優先於 `.env`）：`.env` 中留著 zap 也不會讓一般的 stack 接受 zap（T14 的審查 L4）。

### 18.10 量測的交接（live）

- path 中的 `%` 與 body 的 `_method`（§15.10）、大於 1 MiB 的回應（§16.8）、cookie 與 ZAP 自己的 session cookie 怎麼合併（決定 §16.6 的 `auth` 旗標）、ZAP 收到 SIGTERM 之後的行為（§17.8）、參照炸彈、discriminator 與 links、說明用的 URL（§11.9）：都在 `make test-live-zap` 量測，結果記在 `TOOLS.md` §7。T14 不放寬 guard 的任何檢查。

結果（2026-10-31，`TOOLS.md` §7.5）與對決定的影響：

- **path 中的 `%`**：ZAP 對 path 參數的攻擊有 83% 以 `PATH_AMBIGUOUS` 被拒，§15.10 的取捨維持。放寬會讓 guard 必須判斷解碼之後的 path 是否仍在範圍內；覆蓋的缺口在 T16 以 VAmPI 量化，並在報告中揭露。
- **body 的 `_method`**：還沒量到，小型網站的表單沒有這個欄位（T16）。
- **大於 1 MiB 的回應**：2 MiB 的 JS 取得成功，`body_size_limit` 維持 16 MiB。
- **cookie**：值正確、沒有和其他 cookie 合併。小型網站不發 `Set-Cookie`，和 ZAP session cookie 的合併還沒量到，所以 §16.6 的 `auth` 旗標維持只看名稱，T16 以 Juice Shop 再決定。
- **SIGTERM**：ZAP 約 2 秒結束，在 5 秒的寬限之內；封鎖之後的請求都被拒絕，寬限維持。
- **參照炸彈、discriminator、links、說明用的 URL**：在容器的上限內完成，canary 沒有連線，§11.9 的取捨維持。
- **grant 不允許的 method**：ZAP 在 `postForm` 關閉時仍送出 52 個 POST，guard 全部拒絕。來源是三條會改 method 的規則，改成依 grant 篩選（§18.7）之後重跑，POST 是 0。規則白名單與 plan 的開關只是縮小工具的行為，不能取代 guard 逐請求的 method 檢查（§15；同 §18.2 對 `ZAP_AUTH_HEADER_SITE` 的定位）。

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
- probe 容器與掃描容器可能同時在 scan_net 上（probe 期間照常認領）。scan_net 不能關閉容器之間的互通（掃描容器要連到 guard）；probe 沒有 secret，ZAP 的 `-cmd` 也不開埠。M4 之後同時有多個掃描容器時再檢討（T14 的審查 I3）。
- 不在 T14：parser、觀察、退出碼的語意、排除 guard 的回應、遮罩（T15）；Juice Shop、VAmPI、預算的調整、token 失效（T16）；HTTPS、AJAX spider、queued scan 的時間上限、多個 runner；T11 的證據缺口（同一條連線上多個請求的收包證據）仍記為未實作。

## 19. T15 補充決定：ZAP 的 parser、觀察輸入契約、輸出的遮罩與結果入庫（2026-10-31）

T15 讓 worker 解析 ZAP 的輸出、結果入庫並能查詢，然後對操作者開放 zap（T14 的預覽開關移除）。以下是規劃文件沒有寫到、實作前才定下的細節，以及推翻既有文件的地方。

使用者的決定（2026-10-31）：
1. **結果入庫並提供查詢**：T15 建立 observations 與 artifacts，run 的結果入庫；新增 `GET /scans/{scan_id}/observations`，`GET /scans/{id}` 的每個引擎顯示結果。T19 再在 observation 上加 rule group、fingerprint 與 finding。run 的結果比照 `preflight_result` 存成 `scanner_runs` 的欄位（run 結束時由既有的 trigger 凍結），新的資料表是兩張。
2. **ZAP 在 plan 的 maxDuration 自行停止 → run `timed_out`（`ENGINE_TIMEOUT`）**，observation 照常入庫，scan 依既有的規則是 `timed_out`。
3. **`aggregate()` 不把 preflight 算成結果引擎**：掃描引擎都沒有成功時 scan 是 failed（原本 preflight 成功、zap 失敗是 partially_completed）。

依據（鎖定的映像離線實測，`--network none`、掃描容器的強化旗標；`TOOLS.md` §7.6）：
- plan 的 `maxDuration` 到期時**中斷執行中的 job**（`Job delay interrupted`），`alwaysRun` 的 report 照樣寫出，退出碼 2。log 的結尾是 `Automation plan warnings:`，下一行是 tab 加 `Plan stopped after reaching maximum duration of 20 second(s)`；進度中也有同一句（沒有 tab）。
- spider 連不到 host：退出碼 1，報告照樣寫出（`site` 是空的），結尾是 `Automation plan failures:` 與 tab 開頭的訊息（訊息含 URL）。錯誤加上警告：先 failures、後 warnings，退出碼 1。沒有錯誤與警告：`Automation plan succeeded!`，退出碼 0。摘要一定在 log 的最後。
- ZAP 不認得的啟動參數（JVM 之後才檢查）：印出 usage、退出碼 1、**沒有報告**。`-Xmx` 大到無法配置時 JVM 被 kill（137，不在收集的退出碼中，照舊是 runner 的 `ENGINE_FAILED`）。
- `traditional-json` 的報告沒有 response 的 header 與 status（`-plus` 含注入的 secret，T14 已禁止）：DECISIONS §15 的「parser 依 `X-Secscan-Guard` 排除 guard 的回應」做不到，改成 §19.4 的分層判斷。

### 19.1 推翻或修改既有文件的地方

| 原本 | 改成 | 理由 |
|---|---|---|
| §13.11、T19：observation 在 M4 | T15 建 observations（不含 finding、rule group），T19 加 fingerprint、rule group、finding | 使用者決定 1 |
| §15（拒絕的回應與 M3 的交接）、`guard/addon.py`：parser 依 `X-Secscan-Guard` 排除 guard 的回應 | 分層判斷（§19.4） | 允許的報告範本沒有 header |
| §13.4、ARCHITECTURE §8：normalizing 只能 succeeded、failed、collected | 加上 normalizing → timed_out（必須有錯誤碼） | 使用者決定 2 |
| §13.4 的彙總：每個 run 都算結果 | preflight 不算結果引擎（§19.8） | 使用者決定 3 |
| §14.5、`runner/workspace.py`：runner 只計算 hash，不讀內容 | zap 的輸出由 runner 在收集時以已知的 secret 做位元組層級的遮罩，再計算 hash；仍不解析 | secret 只在 runner 的記憶體中；worker 不該拿到 secret 或金鑰 |
| `API_CONTRACT.md`：`GET /scan-profiles` 是「同專案」 | 已授權的 key（同 `GET /scanners`） | profile 不屬於任何 project |
| `TASKS.md` T14 的交接：「新的錯誤碼要改 DB 的 CHECK」 | DB 只檢查錯誤碼的格式（§13.4、§17.7），不必 migration | T14 的文件錯誤 |

### 19.2 退出碼與結果的語意（`scanners/domain/zap/results.py`，純函式，依序判斷）

| # | 條件 | run | 錯誤碼 | observation |
|---|---|---|---|---|
| 1 | 退出碼 1，沒有報告（ZAP 啟動失敗等） | failed | `ENGINE_FAILED` | 無 |
| 2 | 報告或 log 缺少、不合法、`@programName` 不是 ZAP、`@version` 不是鎖定的版本、超過上限；AF 的結尾摘要不存在或和退出碼矛盾（0 ⇔ succeeded，1 ⇔ failures，2 ⇔ 只有 warnings） | failed | `OUTPUT_INVALID` | 無 |
| 3 | 退出碼 1，報告有效 | failed | `ENGINE_REPORTED_ERRORS` | 入庫（部分結果） |
| 4 | guard 記下轉送 0 個請求，或 telemetry 中沒有任何請求得到上游的回應（未掃到端點） | failed | `NO_TARGET_TRAFFIC` | 無 |
| 5 | 退出碼 2，摘要的警告中有 plan 的 maxDuration | timed_out | `ENGINE_TIMEOUT` | 入庫 |
| 6 | 其他（退出碼 0，或 2 只有其他警告） | succeeded | — | 入庫；0 個是乾淨的結果 |

- 第 3 條排在第 4 條之前：AF 的錯誤通常就是沒有流量的原因（例如 spider 連不到），錯誤碼指向原因；轉送數照樣顯示在 `budget_usage`。
- 警告只分兩種：`max_duration` 與 `other`；錯誤與警告只計數，不保存文字（訊息可能含 URL 或靶機的內容）。spider、passiveScan-wait、activeScan 自己的上限是 plan 的設計，不算 timed_out（它們不在摘要中）。
- 第 4 條的「沒有上游回應」來自錄製的 `unanswered` 情境：target 的 port 沒有人聽時，guard 轉送 71 個請求、全部由 mitmproxy 回 502，AF 的 spider 只留下一個警告（退出碼 2），ZAP 對 mitmproxy 的錯誤頁回報 3 種告警（共 9 個 instance：缺 CSP、Private IP Disclosure、`Server: mitmproxy 12.2.3`）。原本的判定會是 succeeded、0 個 observation，和乾淨的結果分不開（CLAUDE.md §8：未掃到端點是不同的語意）。
- 轉送數不明（guard 的 summary 讀不到）時不套第 4 條，結果標 `traffic_verified: false`。
- 不在 {0, 1, 2} 的退出碼照舊是 runner 的 `ENGINE_FAILED`、不收集；runner 的牆鐘上限照舊是 `TIME_LIMIT_EXCEEDED`；guard 回報預算用盡照舊立刻停止、不收集（T16 檢討）。

### 19.3 觀察輸入契約與 ZAP 的 parser

- **契約**（`scans/domain/observation.py`，純 domain、與引擎無關；分層是 `worker → scanners → scans`，parser 與 worker 都能 import）：`ObservationInput`（識別、規則、工具自己的等級與名稱、位置、遮罩並截斷的文字）、`ArtifactRecord`、`RunOutcome`（狀態與錯誤碼）、`ParsedRun`（parser 與 engine 的版本、observation、排除與重複的計數、警告的種類、`traffic_verified`、判定）。等級的名稱由 parser 寫入（`scans` 不能 import `scanners`）。M4 的 Nuclei parser 輸出同一個契約。
- **識別**：`source_event_id` 是遮罩之後的 (alertRef, method, uri, param, attack, evidence, otherinfo) 的 sha256，不含 ZAP 的 instance `id`（每次執行都不同）；重複的只留第一個，計數 `duplicate`。`ordinal` 是入庫的順序，`source_index` 是在報告中的位置。
- **ZAP 的 parser**（`scanners/domain/zap/report.py`、`log.py`、`results.py`）：
  - `PARSER_VERSION = "zap-traditional-json/1"`；只接受 `@programName == "ZAP"`、`@version` 等於鎖定的版本。
  - JSON 嚴格解析：拒絕重複的 key、NaN 與 Infinity、浮點數；接住 `ValueError`（超長的整數）與 `RecursionError`；巢狀深度有上限。
  - 欄位的型別要正確：數值都是字串、`riskcode` 0–3、`confidence` 0–4、`pluginid` 是數字、`alertRef` 是 `數字(-數字)?`、method 是 HTTP method。缺少必要的 key 整份 `OUTPUT_INVALID`；未知的 key 忽略（範本更新多出的欄位）。
  - 上限：報告 8 MiB（量測：解析 1.3 秒、程序的峰值 RSS 約 106 MiB，worker 的 `mem_limit` 256m 不必改；`TOOLS.md` §7.6）、16 個 site、1,024 個 alert、20,000 個 instance，每個字串的長度（截斷並計數）。
  - 根的 URI 沒有結尾的 `/`（`http://host:3000`），視為 `/`。
  - 文字以 `core/text.py` 的 `display_text` 把 NUL、孤立的 surrogate、bidi 與其他控制字元換掉之後才入庫（PostgreSQL 的 text 不接受 NUL，否則 worker 反覆崩潰）。文字保留 ZAP 寫出的原文，不轉換（實測 evidence 是原始的 HTML，例如 `<form action="/login" …>`）；API 以 JSON 字串輸出，報告（T21）負責編碼。
  - `desc`、`solution`、`reference` 是規則固定的說明（含 HTML），不存。
  - `log.py` 只以整行比對 AF 的結尾摘要（實測的文字）。

### 19.4 排除 guard 的回應（分層，不排除真的結果）

1. instance 的 URI 不是 target 的 origin → `out_of_scope`。
2. **重算 guard 的靜態規則**：`guard/domain/requests.py` 的 `request_reason` 中與請求本身有關的部分抽成純函式 `scope_reason`，guard 改呼叫它（行為不變，guard 的測試照舊）。parser 以同一個函式判斷 instance：guard 一定會拒絕的 → `guard_denied`。涵蓋 `PATH_AMBIGUOUS`（T14 的 api 情境 163 個中有 136 個）、範圍外的 path 與 method。
3. telemetry 完整時，(method, path) 沒有任何得到上游回應的轉送 → `not_answered`：涵蓋 guard 的拒絕與 mitmproxy 自己產生的回應（502 等）。
4. telemetry 讀不到（guard 6 小時後刪除、格式不符）時少了第 3 層，改看 evidence 或 other info 是否含 guard 的拒絕訊息 → `guard_response`，結果標 `traffic_verified: false`。有 telemetry 時不看內容：內容是目標控制的，目標放進這段文字不能讓自己的告警消失（T15 的安全審查；誤丟真的結果比多一筆雜訊糟）。
- 剩下的情況：同一個 path 有上游回應、也有動態的拒絕（`RATE_LIMITED`、預算用盡）：對 guard 回應的告警會入庫（evidence 看得到拒絕的文字）。T16 量測；若 guard 的 403 被告警，再為拒絕回應加上安全 header。

### 19.5 遮罩（runner 在收集時；只對 zap）

- 只對 zap：以引擎政策的 `redact_outputs` 開啟。preflight 存的是原始的 HTTP 回應（§16.5），遮罩會讓 Content-Length 不符，而且不對外提供。
- **遮罩的值在 `_provision` 時建立**（解密之後），帶到收集；不第二次解密（換金鑰時可能失敗）、不寫檔、不進 log。值包括目標的 secret、送出的整個 header 值、cookie 中長度 ≥ 8 的每個值，以及 proxy 的 token 與 ZAP 送出的 `base64(run_id:token)`。
- **形式**（`security/secret_masking.py`，純函式）：原樣、JSON 跳脫、HTML entity、百分比編碼（大小寫、`+`）、JSON 包 HTML。字元集由 `auth_profiles/domain/credentials.py` 限定（沒有 CR、LF、NUL；最長 4096）。以 `bytes.find` 搜尋（最壞的情況也是線性時間；每個形式只有一個搜尋位置，記憶體不隨比對的次數增加；目標收得到 secret，可以在回應中放任意多的片段），由左到右、同一個位置取最長的形式；串流處理，保留最長形式的重疊，不論怎麼切塊結果都相同。
- **收集**：先走訪完 out/，再把遮罩後的內容寫到 runner 私有的暫存檔、`os.replace` 取代；遮罩的過程中呼叫心跳。manifest 記下每個檔案的遮罩次數。替換字串是 `[REDACTED:target-secret]`、`[REDACTED:proxy-token]`（不含引號與反斜線，JSON 仍然合法）。
- 邊界：替換讓檔案超過上限 → `ARTIFACT_REJECTED`；secret 剛好是 JSON 語法的一部分（例如 `true`）可能讓報告不合法 → `OUTPUT_INVALID`（fail closed）。
- **worker 端**：`security/redaction.py` 新增 `redact_url`（以 `is_sensitive_key` 遮罩 query 的值與 userinfo，補 T05 的缺口）與 `redact_text`（Bearer、Basic、JWT 與 `key=value` 的樣式）；入庫前套用、之後截斷。URL 中敏感參數的值也在 evidence 等文字中遮掉：值來自目標控制的 URL，最多 32 個，超過就整個欄位遮掉（T15 的安全審查：原本組成一個 regex，數量沒有上限）。

### 19.6 資料表（migration `0010`；都在 scans 模組）

- 結果要和 lease 的 fencing 在同一個 transaction 寫入（§16.6 的 coverage 的模式），所以放在 scans。
- **只以複合 FK `(scanner_run_id, scan_id) → scanner_runs(id, scan_id)` 引用**（同 `run_coverage`），不直接 FK 到 `scans`：對帳先鎖 scans 再鎖 run，worker 持有 run 的鎖時檢查 scans 的 FK 可能死鎖。
- `scanner_runs` 新增：`results_recorded`、`parser_version`、`engine_version`、`exit_code`、`observation_count`、`result_details`（JSONB ≤ 4 KiB：排除與重複的計數、AF 的摘要、警告的種類、add-on 的版本、`traffic_verified`、判定）。CHECK：`results_recorded = (parser_version IS NOT NULL)`、計數 ≥ 0、退出碼 0–255。run 結束之後由既有的 trigger 凍結。
- add-on 的版本：映像以 digest 鎖定、`-silent` 不更新 add-on，run 的 add-on 就是 probe 對這個 digest 核對過的 `REQUIRED_ADDONS`。
- `artifacts`：每個 run 的輸入與輸出檔（manifest 的 `inputs` 與 `files`）：kind、path、sha256、size、遮罩次數、classification（output 是 masked）、`encrypted`（false）、storage key（runs volume 中的相對路徑）。唯一 `(scanner_run_id, kind, path)`。保留期限與下載在 T23／M5。
- `observations`：契約的欄位、`auth_role`（來自 scan；ZAP 對 target 的每個請求都帶認證 header，§18.2）、報告的 artifact、parser 的版本。唯一 `(scanner_run_id, source_event_id)`、`(scanner_run_id, ordinal)`。`finding_id`、`rule_group` 由 T19 加入。
- 兩張表都以 `scan_records_guard()` 拒絕 UPDATE、DELETE、TRUNCATE。
- 寫入：fenced update 設定 `results_recorded` 與判定，同一個 transaction 插入兩張表；重試時看到已記錄，直接以存下的判定結束，不再解析。

### 19.7 worker

- 認領 zap；`service.py` 依引擎分派，ZAP 在 `worker/zap.py`。
- manifest 嚴格解析（含退出碼）。
- **心跳**：解析期間每 5 秒延長 lease（失效 → 留給對帳），同時寫 fleet 的心跳。不看取消：沒有 normalizing → cancelled，要求取消時解析照常完成，scan 由彙總成為 cancelled（§13.4）。
- 資料的問題一律走判定（§19.2），不丟例外；只有程式錯誤走既有的重試（§17.6）。

### 19.8 狀態機與彙總

- normalizing → timed_out（必須有錯誤碼）。
- `aggregate(runs, *, cancel_requested, checks=())`：`checks` 是 preflight 的狀態，呼叫端依引擎分開傳入。全部終止時：有 interrupted（含 preflight）→ interrupted；要求過取消 → cancelled；掃描引擎有 timed_out → timed_out；掃描引擎全部 succeeded：preflight 也都 succeeded → completed，否則 partially_completed；掃描引擎有 succeeded → partially_completed；其他 → failed。進行中的規則不變（看所有 run）。
- M2 的撤銷授權 live 測試（preflight 成功、zap 前被撤銷）改成 failed。

### 19.9 fixture 與錄製

- `make record-fixtures`（需要 `ENABLE_LIVE_LAB_TESTS=1`）：同一個 live 流程，只執行 anonymous 的錄製情境（沒有目標的 secret 可以寫進輸出），輸出到 gitignore 的 `recordings/zap/`；人工審查之後才搬進 `tests/fixtures/zap/<情境>/`（`report.json`、`zap.log`、`telemetry.jsonl`，manifest 記下退出碼、情境、映像、版本與錄製日期）。錄製的情境：`findings`、`clean`、`timeout`、`unanswered`。
- 離線的情境（`--network none`，手動錄製）：`unreachable`（連不到 host，退出碼 1、有報告）、`engine-error`（ZAP 啟動失敗，退出碼 1、沒有報告）。
- 真實的命中（active scan 的告警）要到 T16：小型網站沒有弱點，T15 的 `findings` 只有 passive 的告警。
- 壞掉的輸出在測試中由真實報告的位元組衍生，不存成檔案。

### 19.10 API、開放 zap、移除預覽開關

- `GET /scans/{scan_id}/observations`：同專案（viewer 以上），其他 project 與不存在的一樣 404；page／limit（上限 100），可依引擎篩選；只有遮罩後的欄位，附 ZAP 自己的等級名稱。正規化的 severity 在 T19。
- `GET /scans/{id}` 的每個引擎加上 `result`（沒有解析過是 null）。
- `GET /scan-profiles`：已授權的 key；每個 profile 的 target 種類、是否需要規格，以及可用的引擎（版本、規則數、規則定義的 sha256）。
- zap 開放（可和自動加入的 preflight 一起，不能和 fake 一起）；建立時不看 probe 的當下狀態：zap 不可用時照常排隊，runner 在 probe 通過之後才認領。
- 移除 T14 的預覽開關（§18.9）：API 的設定、dependency、compose 與 Makefile 的插值。

### 19.11 錯誤碼

| 代碼 | 情況 |
|---|---|
| `OUTPUT_INVALID`（新） | 報告或 log 缺少、不合法、版本不支援、超過上限、摘要和退出碼矛盾 |
| `ENGINE_REPORTED_ERRORS`（新） | AF 回報錯誤（退出碼 1），報告有效；部分結果入庫 |
| `NO_TARGET_TRAFFIC`（新） | guard 沒有轉送任何請求 |
| `ENGINE_TIMEOUT`（新） | ZAP 在 plan 的 maxDuration 停止（timed_out） |
| `ENGINE_FAILED`（既有） | 也用於：退出碼 1 而且沒有報告 |

### 19.12 殘餘風險與不在 T15 範圍

- 同一個 path 有上游回應、也有動態的拒絕時，對 guard 回應的告警會入庫（T16 量測）。
- 惡意的目標收得到 secret：把它轉成任意的形式（base64、hex、倒寫）再放進回應，遮罩認不出來，同專案看得到觀察的人解得回來。編碼列舉不完，平台保證的是工具與 proxy 自然寫出的形式。
- log 是工具的輸出，訊息可以有換行：夾帶摘要的文字會讓判定變成 `OUTPUT_INVALID`（整個 run 沒有 observation）或多一個 `max_duration`（timed_out）。都是看得見的失敗，不會把錯誤變成成功（摘要和退出碼矛盾就是 `OUTPUT_INVALID`）；T16 確認實際的訊息是否帶得出目標的內容。
- secret 含 `"` 或 `\` 而且剛好和報告的語法相鄰時，位元組層級的遮罩可能讓 JSON 不合法 → `OUTPUT_INVALID`（fail closed）。
- 精確遮罩只認得已知的 secret 與列舉的形式；靶機自己發的 token（例如 Juice Shop 的 JWT）只靠樣式遮罩。
- evidence、attack、other info 是靶機的不可信內容：API 只以 JSON 字串輸出，報告（T21）必須編碼。
- 退出碼 1 的部分結果入庫：run 是 failed，observation 仍查得到。
- 報告超過上限是 `OUTPUT_INVALID`：大型靶機的上限在 T16 以真實報告重新確認。
- telemetry 少了最後一行時，該 path 的 observation 可能被排除（計數揭露）。
- ZAP 報告的 URI 和實際送出的 target 是否逐字相同：T15 的真實報告都相同，但小型網站沒有 active scan 的命中。若 ZAP 以未編碼的形式寫出 attack 的 query（空白、非 ASCII），第 2 層會把真的結果排除（計數揭露）；T16 以 Juice Shop、VAmPI 的真實命中確認。
- 收集中途中斷時（run 留在 collecting，由對帳標成 interrupted），out/ 可能還有沒遮罩的檔案：沒有 manifest，worker 不會讀；runs volume 的保留期限在 T23。
- 不在 T15：Juice Shop、VAmPI 的 e2e 與預算調整、token 失效、path 中 `%` 的覆蓋缺口、cookie 的合併、`_method`（T16）；rule group、正規化的 severity、fingerprint、finding（T19）；報告與 artifact 的下載、原始證據加密、runs volume 的保留期限（T21／T23）；HTTPS、AJAX spider、多個 runner；T11 的同一條連線證據缺口仍記為未實作。

## 20. T16 補充決定：Juice Shop、VAmPI 的真實 e2e、token 失效、run 的版本與 guard 的流量明細（2026-10-31）

T16 讓平台以真的 ZAP 掃描兩個標準靶機（OWASP Juice Shop v20.3.0、VAmPI 的弱點版與安全版），產生正例／負例、token 失效、工具超時與取消的真實證據，並依量測調整 lab profile 的預算。以下是實作前定下的細節與推翻既有文件的地方；量測的數字在 §20.6 與 `TOOLS.md` §7.7。

使用者的決定（2026-10-31）：
1. **Token 失效 → 量測＋偵測揭露**：以短 TTL 的 VAmPI 誘發真實失效；worker 從 guard 的 telemetry 判斷憑證在掃描中途失效，coverage 加上 `AUTHENTICATION_LOST`，不把失效後的結果當成已認證。**不做掃描中重新登入**（§16.8 的重新驗證延後）。
2. **預算用盡 → 維持不收集＋量測佐證**：量測確認 ZAP 以 plan 的 maxDuration 在預算之前自行停止（`timed_out`／`ENGINE_TIMEOUT`，有收集）；更正 ARCHITECTURE 的矛盾，`BUDGET_EXHAUSTED` 的行為不變。
3. **版本與流量 → 擴充並持久化**：每個 run 記下實際執行的 plan 與 profile 定義的 sha256（migration 0011），guard 的流量明細寫進 `result_details`，API 揭露。
4. **正例／負例 → 只做兩個靶機的小型集**：以官方的弱點清單為來源（`SOURCES.md` S103、S104），建立足以驗證 ZAP e2e 與 vulnerable／secure 對照的小型案例表（`SECURITY_AND_TESTING.md` §4）；完整的 12+12、6+6 資料集與自製的 fixture app 留給 T30。

### 20.1 推翻或修改既有文件的地方

| 原本 | 改成 | 理由 |
|---|---|---|
| ARCHITECTURE §3.4「預算用盡時……保存已有資料」；§19.2「guard 回報預算用盡……不收集（T16 檢討）」 | 維持不收集（`BUDGET_EXHAUSTED`、`TIME_LIMIT_EXCEEDED` 的 out/ 沒有遮罩，不交給 worker）；ARCHITECTURE 更正 | 使用者決定 2。§18.5 的公式讓 plan 的 maxDuration 比剩下的時間與請求數都短 60 秒，ZAP 會先自行停止並寫出報告；T16 以量測確認（§20.6） |
| §16.8：preflight 不證明之後整段維持登入狀態，「M3 依量測再加上掃描中的重新驗證」 | T16 只做偵測與揭露（§20.4）；掃描中的重新驗證與重新登入延後（不在 M3） | 使用者決定 1、CLAUDE.md §9「失效時標記覆蓋不足，不以匿名結果冒充」 |
| §19.10：profile 的 `definition_sha256` 只在 `GET /scan-profiles` 即時計算 | 每個 run 記下 `plan_hash` 與 `profile_definition_sha256`（§20.2） | 使用者決定 3、CLAUDE.md §8「調整需記錄 profile hash 並在報告揭露」 |
| guard 的拒絕原因、是否用盡、時間只在 tmpfs 的 summary（6 小時後刪除）；DB 只有拒絕的總數 | 解析時寫進 `result_details.guard_traffic`（§20.3） | 使用者決定 3 |
| §18.5：job 的上限以分鐘計、至少 1（spider 1/4、passiveScan-wait 1/10、activeScan 全部與每條規則 1/4） | job 的上限一律是 0（不限），只由 plan 的 `maxDuration` 限制（§20.5） | T16 量測：activeScan 在自己的上限停止時 AF 回報成功，截斷的掃描看起來是完整的 |
| §18.4：時間型的注入規則「T16 再評估」 | 維持排除（§20.5） | 兩個靶機沒有可以受益的注入點 |

### 20.2 run 的版本（migration `0011`）

- `scanner_runs` 新增 `plan_hash`、`profile_definition_sha256`（都可為 null）。
- **`plan_hash`** = `scanners/domain/plan.py` 的 `plan_hash(plan)`：runner **準備執行**的 ExecutionPlan 的 canonical JSON（引擎、映像的 tag 與 digest、entrypoint、參數、非秘密的環境變數、每個輸入檔的名稱與 sha256、是否掛 secret、記憶體／CPU／pid／牆鐘上限）的 sha256。profile 的規則、強度、門檻與 maxDuration 都在 plan.yaml 中；速率與請求數是 scan 的 `budget`（已揭露），由 guard 執行，不在 plan 中。
  - 不含 ExecutionPlan 的 run 與 scan 的 id，但輸入檔的內容可能含有：fake 的 `run.json` 有 run 與 scan 的 id，每個 run 的值都不同；zap 的 maxDuration 與牆鐘上限取決於剩下的預算與 grant 的剩餘時間，grant 的期限是限制因素時也會逐 run 不同（T16 的審查）。所以 hash 相同代表執行的內容相同，反之不成立。
- **`profile_definition_sha256`**：zap 的 run 開始時，`scanners/domain/profiles.py` 的 `zap_definition_sha256(profile)`（和 `GET /scan-profiles` 同一個算法）。之後改了規則，已執行的 run 仍是當時的定義。
- **寫入時間**：runner 在 plan 通過 `build_container` 之後、確認 guard 可用與建立容器之前，以 lease 做 fenced update（條件 `plan_hash IS NULL`，只能一次）。所以不收集的 run（`TIME_LIMIT_EXCEEDED`、guard 回報 `BUDGET_EXHAUSTED`、取消、`ENGINE_FAILED`）也留得住版本，之後才失敗的 `GUARD_UNAVAILABLE`、建立容器失敗、建立之前取消的 run 也有（沒有送出流量）。null 的只有 plan 沒有產生的 run：沒有開始執行（排隊中取消、prepare 時 gate 不通過）、`PLAN_REJECTED`、剩下的時間或請求數不夠 ZAP 執行（`BUDGET_EXHAUSTED`，沒有容器）。
- CHECK：sha256 的格式（64 個小寫 hex）；有 `plan_hash` 就一定已在 prepare 時記下容器名稱；profile 定義只屬於 zap，而且要和 `plan_hash` 一起。trigger `scanner_runs_plan_once`：`plan_hash` 有值之後兩個欄位都不能再改（DB 層的保護，T16 的安全審查，比照 0009 的 `container_removed_at`）。run 結束之後由 0009 的 trigger 凍結。
- API：`GET /scans/{id}` 的每個引擎加上兩個欄位（`API_CONTRACT.md` §17）。

### 20.3 guard 的流量明細（`result_details.guard_traffic`）

- worker 解析 zap 的 run 時，`TelemetryReader` 另外讀 guard 的 `<run>.summary.json`（嚴格解析、不跟隨 symlink、64 KiB 上限；讀不到或格式不符是 null，原因記在 log）。純函式 `scans/domain/traffic.py` 的 `guard_traffic(summary, exchanges, probe=…)` 算出：轉送數、各原因的拒絕數、是否用盡預算、第一個與最後一個轉送的時間、得到上游回應的數量，以及 §20.4 的認證計數。
- telemetry 讀不到或和 summary 的轉送數對不上（§16.6 的條件：最多少一行）時，回應數與認證的計數是 null：殘缺的檔案不能當作依據。轉送 0 個時沒有 telemetry 的檔案也是有依據的（回應數 0，和 zap 的判定相同）。summary 不存在（guard 沒有這個 run 的紀錄）、或屬於另一個 scan 時整個是 null。
- **summary 的範圍**（T16 的審查）：guard 寫的 summary 仍是不可信的輸入。時間要在 9999-12-31 之前、計數不超過 10^12（`guard/domain/telemetry.py` 的 `MAX_EPOCH_SECONDS`、`MAX_COUNT`），超過位數上限的整數也是格式不符（`strict.py` 原本只接 `JSONDecodeError`，會冒出未處理的 `ValueError`；runner 讀 summary 也受益）。否則轉成日期或寫進 4 KiB 的 `result_details` 時會丟例外，整個 run 在重試 3 次之後失去結果。
- 不論判定都寫入（`OUTPUT_INVALID`、`ENGINE_REPORTED_ERRORS` 的 run 也有），和判定在同一個 transaction。大小：21 種拒絕原因與每個計數都是 10^9 時，整個 `result_details` 仍在 4 KiB 以內（單元測試）。
- 只有 zap 的 run（preflight 與 fake 沒有 `result_details`）；不收集的 run 沒有（residual：只有 `budget_usage` 的總數）。

### 20.4 憑證在掃描中途失效（偵測與揭露，不重新登入）

- 訊號只來自 guard 的 telemetry（guard 記下每個轉送的請求是否帶認證 header，以及上游的 status），不看工具的輸出。只看帶認證 header、得到上游回應的請求；401、403 是被拒絕（和 §16.6 相同）。
- **退化**：同一個 (method, path) 接受過憑證、最後一次卻被拒絕。只看「最後一次」：被拒絕之後又接受（例如某個 payload 讓端點回 401）不算。不管憑證的公開端點拿過期的 token 仍回 200（VAmPI 的 `/books/v1`、`/users/v1`），所以不能只看最後幾個請求是否都被拒絕。
- **探針**：auth profile 的 preflight 端點（method 與 path，§12.5）是已知需要認證的。掃描中帶憑證打它被拒絕，憑證在那時已經無效。這也涵蓋 preflight 之後、ZAP 的第一個請求之前就過期的情形（沒有任何接受過的請求，看不出退化）。
- **只有被拒絕**（T16 的審查）：帶認證的請求一個都沒有被接受、只有被拒絕。ZAP 沒有打到探針、而且靶機的端點都需要認證時，這是唯一看得出的訊號。
- **判定**：退化的 operation 達到 2 個、探針被拒絕，或只有被拒絕 → `lost`。一個 operation 的最後一次被拒絕可能是 payload 造成的，所以退化要 2 個以上；探針沒有 payload 的問題（preflight 是固定的 GET、不帶參數），1 次就算。門檻在 §20.6 以量測檢查（同一個靶機、正常的 token 時不應判定為失效）。
- **揭露**：
  - `result_details.guard_traffic.auth`（accepted、rejected、regressed、probe_rejected、lost）。
  - scan 綁定了 auth profile、任何一個 run 判定 `lost` 時，coverage 的 `limitations` 加上 `AUTHENTICATION_LOST`，而且 `authenticated_operations` 是 null：過期的 token 打到公開端點仍是 200，會被算成已認證（T16 的安全審查）。
  - 綁定了 auth profile、有解析過的 run 沒有認證的計數（guard 沒有紀錄、telemetry 不完整、T16 之前的結果）時，加上 `AUTHENTICATION_HEALTH_UNKNOWN`：沒有 `AUTHENTICATION_LOST` 不等於憑證整段有效（T16 的審查）。
  - run 與 scan 的狀態不變（工具本身沒有失敗）；observation 仍標 scan 的 `auth_role`，以 limitation 揭露「部分結果不是以這個身分取得的」。
- **偵測的限制**（訊號是靶機自己回的 status，平台證明不了憑證有效）：
  - 過期時回 302（導向登入頁）、200 的登入頁、400、404 或 5xx 的靶機看不出來；web profile 的偵測力因此低於 api。
  - 只有一個受保護 operation、而且 ZAP 沒打到探針的 API，最多退化 1 個，看不出來。
  - WAF 或封鎖讓多個先前 200 的 operation 改回 403 時，會被判定為失效（偏向安全的方向）。
- **不做**：掃描中重新驗證、重新登入（§16.8 原本寫在 M3，使用者決定延後）；判斷失效發生在哪個時間點之後的 observation（observation 沒有對應到 telemetry 的請求序號）。T19 的 fingerprint 與複掃比較要讀 run 的 `auth.lost`：失效的 run 的 observation 不能併入已認證身分的 finding，也不能據以把複掃標成 `not_observed`（交接）。

### 20.5 lab profile 的預算：依量測的調整

量測（§20.6、`TOOLS.md` §7.7）之後的結論與調整：

| 項目 | 量測 | 決定 |
|---|---|---|
| **job 自己的時間上限**（spider `maxDuration`、`passiveScan-wait` `maxDuration`、activeScan `maxScanDurationInMins`、`maxRuleDurationInMins`；§18.5 原本是 plan 時間的 1/4、1/10、全部、1/4，至少 1 分鐘） | 預算 150 秒（plan 90 秒）的 VAmPI：activeScan 在自己的上限（1 分鐘）停止，只轉送 107 個（完整的掃描是 425 個），AF 回報 `succeeded`、log 沒有任何警告：**被截斷的掃描看起來是完整的** | **改成 0**（AF 的「不限」），只由 plan 的 `maxDuration` 限制。plan 到期是警告 → `timed_out`（`ENGINE_TIMEOUT`、`time_limit_reached`），截斷看得見（CLAUDE.md §8）。推翻 §18.5「job 的上限至少 1（0 是不限）」。代價：一條慢的規則或很大的網站可能用掉整個 plan，結果是看得見的 `timed_out`。第二輪：預算 180 秒的 run 是 `timed_out`（§20.6） |
| 速率、請求數、時間的上限（`grants/domain/scope.py`：2 req/s、5,000 次、1,500 秒） | VAmPI 的 api scan 約 310 秒、轉送 425 個；Juice Shop 的 web scan 約 200 秒、256 個。用到時間上限的 21%、請求數上限的 9%；實際速率約 1.5 req/s（上限 2）。沒有任何 run 撞到預算（`exhausted` 都是 false） | **維持**。兩個靶機的檢出受限於「找得到的注入點」與 guard 的 path 規則（§20.7），不是預算；提高速率只讓掃描變快，不會多檢出。M5 的 bench 以 fixture app 再檢討 |
| 容器的資源（記憶體 3 GiB、2 CPU、1,024 pids；JVM heap 1,536 MiB、tmpfs 768 MiB） | ZAP 的記憶體峰值 619–1,265 MiB（兩輪；Juice Shop 帶 bearer 最高）；靶機 111–212 MiB | **維持**：heap 與 tmpfs 的上限加起來接近 2.3 GiB，3 GiB 留有餘裕 |
| 強度 `low`、門檻 `medium` | 掃描都在預算的 1/4 以內結束 | **維持**：提高強度只增加同一批注入點的 payload，量測沒有顯示會多檢出；T30 的 fixture app 有可達的注入點之後再比較 |
| 時間型的注入規則（40019–40022、40027、90037；§18.4「T16 再評估」） | 鎖定映像的時間型 SQLi 規則只針對 MySQL、Hypersonic、Oracle、PostgreSQL、MSSQL（`TOOLS.md` §7.4），兩個靶機都是 SQLite；VAmPI 的注入點在 path，被 guard 拒絕；兩個靶機的已知清單沒有 OS 命令注入（90037；Juice Shop 的 RCE 是反序列化與 SSTi，在 traditional spider 走不到的端點）。開了也只是多送沒有作用的 payload | **維持排除** |
| `RESERVED_SECONDS = 60` | run 的總時間比流量的時間多約 30 秒（JVM 啟動、報告、收集） | **維持** |

- 每個 run 的 `plan_hash` 已包含這些值（§20.2）：調整前後的 run 以 hash 區分，報告揭露。
- runner 的牆鐘上限（`runner/domain/policy.py` 的 1,500 秒）與 `MAX_DURATION_SECONDS` 相同，沒有調整，所以不必連動。

### 20.6 量測（`make test-live-lab`，2026-10-31）

第二輪（job 的上限是 0、修正第一輪的測試之後；8 passed，26 分 15 秒）：

| 情境 | profile／認證 | run | 秒 | 轉送 | 拒絕（原因） | 407 | 觀察 | ZAP 峰值 |
|---|---|---|---|---|---|---|---|---|
| VAmPI 弱點版 | api／bearer | succeeded | 312 | 425 | 258（`PATH_AMBIGUOUS` 232、`PATH_NOT_AUTHORIZED` 26） | 139 | 11（passive 3 種） | 632 MiB |
| VAmPI，預算 180 秒 | api／anonymous | **timed_out**（`ENGINE_TIMEOUT`） | 139 | 204 | 60（`PATH_AMBIGUOUS`） | 40 | 11 | 683 MiB |
| VAmPI，取消 | api／anonymous | cancelled | 取消後 9 秒 | — | — | — | — | — |
| VAmPI 安全版 | api／bearer | succeeded | 310 | 425 | 258（同上） | 139 | 10（passive 3 種） | 653 MiB |
| VAmPI，token 90 秒 | api／bearer | succeeded | 307 | 425 | 230（`PATH_AMBIGUOUS` 204） | 125 | 11 | 722 MiB |
| Juice Shop | web／anonymous | succeeded | 193 | 256（回應 253） | 0 | 110 | 9（passive 3 種） | 846 MiB |
| Juice Shop | web／bearer | succeeded | 204 | 256（回應 253） | 0 | 110 | 9 | 916 MiB |
| Juice Shop 的 REST 搜尋 | api（操作者的規格）／anonymous | succeeded | 51 | 59 | 6（`PATH_NOT_AUTHORIZED`） | 4 | 2（含 **SQL Injection**） | 654 MiB |

- **token 失效**：90 秒的 token，接受 351、拒絕 74、退化 2 個 operation、探針 0（ZAP 只在匯入時打過一次 `/me`）→ `lost`，coverage 是 `AUTHENTICATION_LOST`。兩輪結果相同。正常的 token（3600 秒）的 bearer 掃描：拒絕 0、退化 0（門檻 2 沒有誤判）。
- **工具超時**：job 的上限改成 0 之後，預算 180 秒（plan 120 秒）的 run 是 `timed_out`、`time_limit_reached: true`、觀察入庫，不是 runner 的 `TIME_LIMIT_EXCEEDED`。plan 的 maxDuration 中斷的是 activeScan（§19 的離線量測是 `delay` job）。
- **預算用盡不收集的佐證**：所有 run 的 `exhausted` 都是 false。§18.5 的公式讓 plan 在預算之前停止，正常的情況不會先撞到 guard 的預算。
- **preflight 不被 200 騙過**：第一輪以 Juice Shop 的 `/rest/user/whoami` 當 preflight。這個端點只看 cookie，帶 bearer 與匿名都回 200 `{"user":{}}`，平台判定 `failed`、coverage 是 `AUTHENTICATION_NOT_VERIFIED`（CLAUDE.md §9 的「不能只用 200 判定成功」）；同一個掃描中帶 bearer 的 253 個請求都被接受（`/api/*` 以 Authorization 驗證）。第二輪改用 `/api/Addresss`，`passed`。
- **guard 的 403 沒有被告警**：所有 run 的 `excluded.guard_denied`、`guard_response` 都是 0。拒絕的回應沒有成為 instance，不為拒絕回應加安全 header（§19.4 的交接）。
- **URI 與 telemetry**：每個觀察的 (method, path) 都是 guard 為這個 run 轉送過的請求（live 測試的斷言）。Juice Shop 有 3 個請求沒有上游回應，排除 2 個 instance（`not_answered`）。
- **報告大小**：5.9–15.2 KB，遠低於 8 MiB 的上限。
- **AF 的訊息**：正常的 run 只有 plan 的 URL 與數量（`Job spider found 51 URLs`、`Job openapi added 10 URLs`），沒有靶機的內容。
- **reactive 407**：每個 run 4–139 個，不計入預算（§16.8）。
- 第一輪（job 有自己的上限）的差異：預算 150 秒的 run 被 activeScan 自己的上限截斷、回報 `succeeded`（§20.5）；7 個測試在斷言時失敗（`definitions` 在 ZAP 可用之前讀取，`/scan-profiles` 是空的），量測本身有效，數字和第二輪相近。

### 20.7 正例與負例（小型集；`SECURITY_AND_TESTING.md` §4 的案例表）

- **Juice Shop 的 REST 搜尋的 SQLi**（S104 的 Database Schema、User Credentials）：經完整的平台（API → runner → guard → ZAP → worker → 查詢）**命中**：`40018 SQL Injection`，`GET /rest/products/search`，參數 `q`（query），attack `apple'`，ZAP 的等級 High、信心 Low，evidence 是 500 回應。注入點是前端呼叫的 API，traditional spider 走不到，以操作者上傳的一個 operation 的規格掃描。
- **VAmPI 的 SQLi**（S103；`/users/v1/{username}` 以字串組 SQL）：ZAP 送出了探測（`/users/v1/name1%27`），guard 以 `PATH_AMBIGUOUS` 拒絕（§15.10 的取捨），探測沒有到達靶機，**平台漏報**。量化：每次 VAmPI 的掃描有 232 個 path 參數的攻擊被拒（`/users/v1/…` 106、`/books/v1/…` 126），佔 guard 判斷的請求的 34%。
- **對照實驗**（不經平台；同一個鎖定的映像、第一輪實際使用的 plan.yaml 與規格；只接一個 internal 的網路，沒有 guard 與速率限制）：弱點版 34 秒內命中 `40018 SQL Injection`（High，`GET /users/v1/%27`，參數 `username`），安全版沒有。結論：漏報完全來自 guard 的 path 規則，ZAP 本身判斷正確。是否放寬 §15.10（解碼之後再比對範圍）是需要使用者決定的安全取捨，T16 不改（只量化與揭露，§18.10 的決定）。後續：使用者在 2026-11-01 決定有條件放寬（T33），目前暫緩（§21）。
- **VAmPI 的負例**：安全版沒有任何 active scan 規則的告警（live 測試的斷言）；但弱點版也只有 passive 的告警，所以這組對照在平台上**分不出**弱點版與安全版（原因同上）。
- **設定類的正例**（passive，以實際的回應 header 可確認）：Juice Shop 缺 CSP（10038）、`Access-Control-Allow-Origin: *`（10098）；VAmPI 缺 `X-Content-Type-Options`（10021）、`Server` header 透露版本（10036）。VAmPI 的兩種在弱點版與安全版都有（和 `vulnerable` 開關無關）。
- **漏報、不在 ZAP 能力範圍**：BOLA、mass assignment、未授權改密碼、使用者列舉、JWT 弱金鑰、缺速率限制（VAmPI）；Juice Shop 的 DOM／Reflected XSS 與大部分 challenge 在前端路由，traditional spider 只走到靜態資源與 `/ftp`。Juice Shop 的 `/ftp` 目錄列表（Confidential Document，回 200、標題 `listing directory /ftp`）有被請求，但 Directory Browsing（0）沒有告警。

### 20.8 殘餘風險與不在 T16 範圍

- guard 的 path 規則讓 path 參數的注入測不到（§20.7）：報告必須揭露；放寬需要使用者決定（2026-11-01 已決定有條件放寬，暫緩中，§21）。
- 認證失效的偵測有限制（§20.4）：靶機以 302 或 200 的登入頁表示過期時看不出來；observation 仍標 scan 的身分（T19 要讀 `auth.lost`）。
- 不收集的 run（guard 回報預算用盡、runner 的牆鐘上限、取消）沒有 `guard_traffic`，只有 `budget_usage` 的總數與 `plan_hash`。
- `plan_hash` 不含 runner 的容器政策（網路、capability、掛載）：那些是 runner 固定的設定，不隨 run 改變。
- 正例與負例只是小型集：完整的 12＋12、6＋6、可切換弱點與修補的 fixture app 在 T30；cookie 與 ZAP 自己的 session cookie 的合併、body 的 `_method`（T14 的交接）在 T16 沒有量到（兩個靶機都用 bearer、都不支援 method override），留給 T30 的 fixture app。
- Juice Shop 只能以 bearer 認證 `/api/*`：它的頁面與 `/rest/user/whoami` 看 cookie，web profile 帶 bearer 的掃描大部分仍是匿名的內容。
- 不在 T16：掃描中重新驗證與重新登入、預算用盡時收集部分輸出（使用者決定）；Nuclei（T17、T18）；rule group、fingerprint、finding（T19）；HTTPS、AJAX spider、多個 runner；T11 的同一條連線的證據缺口仍記為未實作。

## 21. T33：guard 的 path 編碼，有條件放寬（暫緩，2026-11-01）

狀態：**暫緩**。實作在本機分支 `feat/t33-guard-encoded-params`，沒有合併、沒有推送，live 的 A/B 也沒有完成。使用者決定（2026-11-01）先把問題記錄下來，main 回到 PR #19（`c61a5e8`）的狀態。

目前的行為不變：
- path 含 `%` 一律以 `PATH_AMBIGUOUS` 拒絕（§15.10）。
- VAmPI 的 path 參數 SQLi 仍然漏報（§20.7），報告必須揭露（§20.8）。
- DB 與 API 沒有 guard policy 的版本欄位。

### 21.1 使用者的決定與要求

採用「有條件放寬＋安全的路徑正規化」，不全面放行含 `%` 的請求。列為 T30 的前置工作：先完成獨立的安全設計、測試與驗證，再決定是否正式啟用。

- **解析與解碼**：先依 RFC 3986 解析 URL 的結構，再做受控的解碼；不可以把整個 URL 解碼之後，以字串前綴判斷授權。
- **範圍**：維持 grant 對 origin、HTTP method、path 與明確授權的路由參數的限制；只考慮放行確認不會改變路由邊界的編碼參數。
- **fail closed**：編碼的分隔符、雙重編碼、路徑穿越、無效的編碼，以及 guard 與目標伺服器的解析可能不同的情況。
- **對照實驗**：以隔離的 Juice Shop、VAmPI 對照修改前後的 ZAP 結果。確認 VAmPI 的 SQLi 能不能在既有的 grant 內被偵測，而且沒有新增任何超出授權範圍的請求。
- **證據**：保留原始請求、guard 的判斷、靶機實際收到的請求與安全的流量統計，並記下 Guard Policy Version，讓實驗可以重現。
- **測試**：unit、integration、contract、live 涵蓋正常的 path、編碼的路由參數、歧義的 path、越權的 path 與不同的 URL 解析行為。
- **預設嚴格**：證明安全之前，預設維持現行的嚴格行為，不開放給一般掃描。
- **T30**：正式的 ground truth 評估在這之後進行，避免把 guard 已知的阻擋混入漏洞偵測的量測。

### 21.2 嘗試的做法（摘要）

完整的設計在分支的 `docs/T33_IMPLEMENTATION_PLAN.md` 與該分支的 §21。要點：

- **版本**：`strict-1`（預設，凍結 T11–T16 的判斷）與 `encoded-params-1`（實驗）。每個 run 記下版本（migration `v0012`、API、guard log）。一般的 compose 寫死 `strict-1`，實驗版本只出現在 live 專用的 override 檔。
- **解析**：
  - 在原始的 `?` 切出 path，以原始的 `/` 分段。
  - 每個 `%HH` 只解碼一次，解出的位元組必須落在白名單內。白名單不含 unreserved、分隔符、`%`、`*`、控制字元與非 ASCII。
  - 段落只剩點、空白與 `+` 時也拒絕。
  - 解碼的值只用於比對，guard 轉送的位元組不變。
- **比對**：
  - 編碼段只能由 grant 的 `{佔位}` 涵蓋，literal 不涵蓋。
  - `allow_all_paths` 遇到編碼段就拒絕。
  - 排除的 pattern 可能和編碼段重疊時拒絕；多個編碼段一起判斷。
  - 對外的 reason 維持 `PATH_AMBIGUOUS`，細分只寫進 guard log。
- **一致性**：telemetry、coverage、parser 與認證健康度都依版本處理。worker 以 run 的 grant 與版本重算每一筆轉送；不一致時不記 coverage，`traffic_verified=false`。

規模：到 `e107911` 為止，相對 `c61a5e8` 改了 102 個檔案（+6,533／−153 行），範圍涵蓋 guard、grants、runner、migration、worker、parser、coverage、API 與 live harness。分支的 §21.5 記有離線測試與突變檢查的結果，那些都不是 live 的證明。

### 21.3 暫緩的原因

1. **live 的 A/B 沒有完成**（2026-11-01 的第一次執行；本機的 `recordings/guard-paths-attempt-1/`，加密）：
   - `strict-1` 組先跑完 guard 的邊界語料、route echo（Flask、Express）、固定探針與 VAmPI 的掃描，都留下了分析紀錄。
   - 接著以 `strict-1` 掃描 Juice Shop 的 path 參數規格時，量測中途失敗：只留下 4 個檔案，沒有分析。
   - `encoded-params-1` 組沒有執行。所以沒有任何 A/B 的比較，也沒有「沒有越權請求」的靶機端證據。
2. **Juice Shop 的 reviews 端點會讓靶機崩潰**（隔離的診斷；本機的 `recordings/guard-paths-diagnostic/`，加密）：
   - 這是直接對 lab 送出的請求，不經平台，不是政策的驗證。映像是 `compose.lab.yaml` 鎖定的 `bkimminich/juice-shop:v20.3.0@sha256:cea5a4af…`。
   - 對 `/rest/products/{id}/reviews` 送兩個 GET：第一個回 200；第二個沒有得到回應，容器在啟動約 5 秒後以 exit code 1 結束（不是 OOM）。
   - log 是 `ReferenceError: get is not defined`，堆疊停在 MarsDB 執行 `$where` 的地方（`marsdb/dist/DocumentMatcher.js`）。看起來是例外沒有被接住，Node 的程序隨之結束。
   - 兩個請求的 path 都不含 `%`，以現行的規則重算也都在 `{id}` 的範圍內，所以 `strict-1` 一樣會轉送。這是靶機本身的行為，不是放寬造成的；但靶機在掃描中途結束時，兩個版本無法在相同的條件下比較。
   - T16 的掃描沒有碰到這個端點（REST 的規格只有 `/rest/products/search`，spider 只走到靜態資源與 `/ftp`）。之後的規格只要包含它，一般的掃描也會讓靶機中途結束。
   - 第一次執行時沒有保存靶機的 log，所以還不能確定那次失敗就是這個崩潰。快照 commit（§21.4）改成失敗時先加密保存所有證據，並加上重現原始失敗的 live 測試；兩者都還沒有執行。
3. **能驗證的範圍有限，殘餘風險多**：
   - 能驗收的只有鎖定的 Flask／Werkzeug 與 Express 的解析鏈。其他的 URL 模型（會解碼再重組請求的 proxy、去副檔名、IIS／Windows 等）只是探索，不能宣稱安全；分支的計畫保留一個去副檔名的反例。
   - telemetry 的逐筆紀錄只有 method 與 path，不能單獨證明沒有越權的流量，需要靶機端的獨立證據。
4. **改動大、牽動多**：policy、status 與 telemetry summary 的格式都要升版，runner、guard 與 worker 必須一起更新。兩個版本都要一直保留，舊的 run 才能照樣解析。
5. **授權的語意還沒決定**：runner 層級的開關一啟用，所有含佔位的 grant 都會一起放寬，不必管理員重新核准。要全域啟用，還是每個 grant 自己選擇加入，需要使用者決定。

### 21.4 保留的紀錄

- 分支 `feat/t33-guard-encoded-params`（2026-11-01 推送到 origin 備份；未開 PR、未合併）：
  - `9536ce8`：設計與驗收界線的文件。
  - `124346e`：版本化的 policy、path 的核心與 lab harness。
  - `d996fc1`、`e107911`：測試與證據的補強。
  - `41e1901`：暫緩時尚未提交的修改的快照（Juice Shop 崩潰的診斷），未完成、未驗證。
- 本機的錄製（gitignore，以 Fernet 加密，金鑰是同一個目錄的 `.evidence.key`）：`recordings/guard-paths-attempt-1/`、`recordings/guard-paths-diagnostic/`。
- 分支已在 origin 備份；錄製只在這台電腦上（gitignore），刪除之後無法還原。

### 21.5 恢復之前要處理或決定的事

- **Juice Shop 的崩潰**：先以會保存完整證據的 harness 確認第一次失敗的原因。然後決定 A/B 的 Juice Shop 規格是否排除 reviews 端點，或把靶機中途結束當成量測失敗（記錄下來，不算 A/B 的結果）。不能為了讓量測跑完而放寬 guard 的規則或改變預設。
- **重跑完整的 A/B**：兩個版本都完成，而且有靶機端的證據之後，由使用者決定是否正式啟用，以及要全域啟用還是每個 grant 自己選擇加入。
- **T30**：依 §21.1，正式的 ground truth 評估排在 T33 之後。T33 暫緩期間有兩種做法，由使用者決定：
  - 等 T33 完成。
  - 先以 `strict-1` 進行，把被 guard 擋下的案例另外分類為平台阻擋，不計入掃描器的漏報。

## 22. T30：自製 fixture app 與 ground truth 初稿（strict-1 進行，2026-11-01）

依 §21.5 的兩個選項，使用者（2026-11-01）決定：**T33 暫緩期間，T30 先以 `strict-1` 進行，把被 guard 擋下的案例另記為「平台阻擋」，不計入掃描器的漏報**。正式的 ground truth 指標評估（recall/precision）仍依 §21.1 排在 T33 之後，不在 T30 範圍（屬 T27/T28）。

### 22.1 fixture app 的形態

- **自製、可切換弱點版（insecure）與修補版（secure）的靶機**，放在 `tests/live/fixture_app/`，只在隔離的 lab_net 上執行，只為量測服務（`SECURITY_AND_TESTING.md` §5.1）。
- **跑在既有的 guard 映像的 python（stdlib）**，以 bind-mount 掛入、`python3 -I -B -u -c` 設好 `sys.path` 後匯入（比照 `tests/live/zap_site.py`）。不另建映像、不鎖新 digest、不改 `compose.yaml`／`.dockerignore`／`test_deployment.py`。弱點／修補以啟動參數切換（沿用 VAmPI `vulnerable=1|0` 的慣例）。
- 處理邏輯是純函式 `handle(mode, request, state) -> Response`，由薄的 `http.server` 外殼呼叫，所以單元測試不開 socket（pytest-socket）就能逐案例驗證（`tests/contract/test_fixture_cases.py`）。
- 弱點的實作集中在 `insecure.py`；SQL 字串拼接對 ruff 的 S608 於 pyproject 對該檔忽略（這正是要量測的注入，不是程式缺陷）。

### 22.2 案例集與可達性

- 依 §5.1：12 個安全正例（＋12 個修補負例）、6 個 contract/robustness 正例（＋6 個修補負例），事實來源是 `cases.py`，與 `SECURITY_AND_TESTING.md` §5.1 的案例表、OpenAPI 規格三者對齊。
- **多數安全正例放在 query／form／body／header／cookie**（strict-1 下 guard 可達）：query SQLi、反射型 XSS、表單 SQLi、錯誤訊息洩漏、缺安全 header、CORS `*`、cookie 旗標、開放轉址、敏感檔案、BOLA（數字 id 路徑段）、mass assignment、過度資料暴露。
- **平台阻擋（另記、不計入上面 12）**：path 參數的 SQL 注入（`/users/{username}`）的探測需要 path 中的 `%27`，strict-1 下 guard 以 `PATH_AMBIGUOUS` 擋下（§15.10、§20.7），探測不會到達靶機。這和 §20.7 把 VAmPI 的 path SQLi 當成平台漏報（而非 ZAP 漏報）的處理一致；T33 的 `encoded-params-1` 放寬後此案例才可達。
- 標記依 §5.2：由本人以修補 diff／重現／程式測試標記；保留約 25% 為 holdout（在案例表標明、凍結）；指導教授／同學抽樣複核 ≥20% 列為後續人工步驟與效度威脅（未在 T30 內完成）。

### 22.3 驗證與量測

- live：`make test-live-fixture`（弱點版與修補版各跑一次 web 與 api 掃描）。每個 run 的 plan_hash、profile 定義、guard 流量明細與「observed ⊆ forwarded」「guard 只看到 target」等不變條件沿用 T16 的量測工具。量測見 `TOOLS.md` §7.8。
- 修補版是負例的對照組：active scan 規則不應有告警。
- 不連網的單元/contract 測試（`test_fixture_cases.py`）逐案例驗證弱點版呈現、修補版修正。

### 22.4 殘餘風險與不在範圍

- 正式指標評估（recall/precision、holdout 跑分）排在 T33 之後。
- path 編碼案例在 strict-1 下無法量測命中，只能證明「平台阻擋」；T33 放寬後補量。
- Nuclei／Schemathesis 對這些案例的偵測在 M4/M6。
- 人工複核（§5.2 的 ≥20% 抽樣）尚未進行。
- 不涵蓋 HTTPS。

## 23. T17：凍結 Nuclei 的 HTTP 模板清單與執行設定（2026-11-01）

M4 的第一步。只凍結「清單與執行設定」，作為 T18（Adapter、JSONL parser、e2e）、T19（rule group、OWASP、fingerprint）的資料基礎。使用者（2026-11-01）決定：範圍採**精選、對準 lab**；本輪**離線產生真清單並提交**；列舉以 **`nuclei -tl`** 為準。

### 23.1 選取方式：精選的 template id 白名單（對 §2 row20／§4 的落實與細化）

- 既有決定（§2 row 20、§4）是「依 tag/類型產生固定 template ID 清單，以類別為單位審查」。實測整包 v10.5.0 有 14,036 個 yaml；即使只取 http 偵測類別、再以 severity／tag 過濾，misconfiguration 仍有 552、exposures 711、technologies 1,157，且**多數是本 lab 不存在的特定產品模板**（WordPress、Jenkins…），對 Juice Shop／VAmPI／fixture 跑起來只是雜訊，也吃掉共享預算（2 req/s、5,000 次、25 分鐘）。
- 因此這裡把該決定**細化**為：比照 ZAP 的規則白名單（`zap/policy.py` 的 `WEB_RULES`／`API_RULES`），**以類別為單位人工審查後，精選對任何 HTTP 應用都適用的通用模板，加上對準 lab 技術棧的辨識模板**。型別判斷（只收 http、排除 OAST）交給 nuclei 自己：產生器以 `nuclei -tl -id <清單> -pt http -ni -duc` 列舉並驗證（比照 ZAP probe「以工具實際行為為準」）。這不是推翻決定，而是在「精選、對準 lab」的範圍下把「數千個無法逐一審查」落到可逐條審查的規模。
- 結果：**42 個模板**，5 類：exposures(8)、miscellaneous(15)、misconfiguration(4)、technologies(9)、vulnerabilities/generic(6)。涵蓋安全 header／cookie SameSite／CORS／方法／目錄列舉／robots·security.txt／API 規格暴露／git·phpinfo·.DS_Store 暴露、通用與技術棧辨識（tech-detect、flask、werkzeug-debugger、angular、express…），以及會和 ZAP 主動規則**刻意重疊**的通用主動探測（SQLi、反射 XSS、CRLF、open redirect、CORS），作為 M4「同一問題多來源」的候選。清單與逐類別審查見 `TOOLS.md` §2.1。
- 初版曾選 46 個；code-reviewer 與 security-reviewer（2026-11-01）發現其中 3 個內嵌非 http 區塊，`-pt http` 擋不住（nuclei 以第一個協定歸類），違反「只收 http、禁 code／非 http 協定」（CLAUDE.md §7）：`cookies-without-httponly`／`-secure` 有 `javascript:`（加 `flow:`），`directory-listing` 有 `flow:`（且帶 `fuzz` tag、請求數不定）。另 `host-header-injection` 會把 Host 改成隨機值，guard 一律 `ORIGIN_MISMATCH` 擋下、永遠無訊號（和 ZAP 排除「會改 Host 的規則」一致）。這 4 個移除後為 42 個，並加上內容閘門（§23.3）讓此規則落實在程式與測試。

### 23.2 凍結的形態與產生

- 清單存成 `src/secscan/scanners/domain/nuclei/templates.lock.txt`，每行 `id sha256 path`（沿用 spike `templates.lock.txt` 的格式）。這是 **src/ 下第一個簽入的資料檔**，因清單太大不宜寫成 Python tuple，以大小正當化。
- 守衛（比照 `runner/domain/policy.py` 的 `ArgumentDigest`／`*_SHA256`）：`policy.py` 以 `INCLUDE_TEMPLATE_IDS`（依類別分組、逐條註記）為白名單，`TEMPLATES_LOCK_SHA256` 固定 lock 檔雜湊，`nuclei_definition_sha256()` 以 release／commit／旗標與**每個模板的 id/sha256/path**（含每檔雜湊，內容或路徑一改就變）的 canonical JSON 產生定義雜湊（比照 `zap_definition_sha256`，供 T18 的報告揭露）。`tests/unit/scanners/nuclei/test_policy.py` 與 `tests/contract/test_fixture_manifest.py` 交叉核對 policy 常數、lock 檔與 `manifest.json` 三者一致（含映像 digest）。
- 產生器 `tools/freeze_nuclei_templates.py`（src/ 之外的 dev／維運工具，不納入 mypy／coverage／import-linter）：驗證鎖定 archive 的 sha256（`80fbabce…`）→以 digest 確認／拉取鎖定映像→乾淨重新解壓→在鎖定映像裡**離線（`--network none`）**跑 `nuclei -tl`→讀頂層 id、算每檔 sha256、與 `INCLUDE` 對帳→寫 lock。`--check` 模式逐位元組重現驗證（`make nuclei-templates-check`、`tests/live/test_nuclei_templates_live.py`）。**全程不連任何目標、不出網**，屬開發動作（比照 `make images`）。

### 23.3 執行設定與禁用

- `FROZEN_FLAGS = -ni -duc -pt http -jsonl -silent`（T18 的 ExecutionPlan 以此組裝，每個 run 另加 `-id`／`-sf`／`-p`／`-o`／`-u` 與凍結的速率/並行）。`-ni` 同時關閉 interactsh 並**排除 OAST 類模板**；`-pt http` 只收 http；code／headless／file／fuzz 在 nuclei 預設就不載入。型別過濾 `TYPE_FILTER`（`-ni -duc -pt http`）是 `FROZEN_FLAGS` 與產生器 `nuclei -tl` 共用的同一份，避免手抄不一致。
- **內容閘門**（`selection.template_violations`）：`-pt http` 擋不住「多協定」模板（nuclei 以第一個協定歸類，實測 `-ept javascript` 也無效），所以產生 lock 時另外讀每個模板全文，排除含 `flow`／`javascript`／`code`／`tcp`／`dns`… 等非 http／多協定頂層鍵、或 `fuzz`／`dast`／`dos`／`oast`／`intrusive` tag 的模板。產生器對任何違規即 fail-closed，`test_selection.py` 以 YAML 片段測閘門邏輯。這就是初版 3 個 JS 模板被攔下的機制。
- `-sf` 的 `domains` 用**完全比對 host:port**，不用未錨定、會子字串命中的 `domains-regex`（`TOOLS.md` §6、S36）；此為 T18 組 secret 檔時落實，`policy.py` 已註記。

### 23.4 人工審查、主動探測與 guard 下的可達性

- 由 Claude 以類別為單位做第一手審查與高風險抽查，紀錄於 `TOOLS.md` §2.1；**最終類別簽核屬使用者**（單人作業，列為效度威脅，比照 §22 T30）；使用者已於 2026-11-04 簽核（§23.6）。
- `ACTIVE_PROBE_TEMPLATE_IDS` 明列會送探測 payload 或 crafted POST 的模板（6 個 generic-vuln 加 `graphql-detect`、`waf-detect`），和 ZAP 的 active scan 同一類、需 grant 明確允許對應 method，只對已核准的 lab 靶機執行；供 T18 區分、日後可組被動子集。
- **guard 下的實際可達性（安全審查量化，列為限制）**：strict-1 下帶 `%` 的 path 探測多半被 `PATH_AMBIGUOUS` 擋下（`xss-uri-reflected` 兩條全擋、`open-redirect-generic` 82/94 擋、`crlf-injection-generic` 6/8 擋）；`http-trace` 的 TRACE、`graphql-detect`／`waf-detect` 的 POST 在只允許 GET 的 grant 下會被 guard 擋。因此「Nuclei 疊 ZAP／fixture 做多來源」在 **T18 的 e2e 已實證 CORS**（nuclei `cors-misconfig` 與 ZAP 10098，§24.5）；SQLi/XSS/CRLF/open-redirect 等帶 `%` 的 path 探測仍多被 guard 擋，屬候選、部分在 T33 放寬編碼後才可達（比照 §22 的「平台阻擋」）。

### 23.5 T17／T18 邊界與殘餘風險

- **不在 T17**：把 `Engine.NUCLEI` 加入 `AVAILABLE_ENGINES`（nuclei 維持回 422，§13.1）、`ENGINE_IMAGES`／`ENGINE_POLICIES`／worker 的註冊、`plan_nuclei_run`、JSONL parser、`/scan-profiles` 揭露 nuclei、`profile_definition_valid` DB 約束放寬（目前綁 `engine='zap'`，`scans/models.py`）。以上全在 T18。
- **T18 DoD（審查提出，記在這裡）**：(1) 凍結速率與並行（`-rl` 不超過 guard 速率、`-c 1`、`-bs 1`、`-retries 0`、`-timeout`），nuclei 預設 150 rps/25 並行，對上 guard 2 req/s 會產生大量 `RATE_LIMITED` 403。(2) **濾掉 guard 的合成拒絕回應**：negative-matcher 模板（如 `http-missing-security-headers`）會把 guard 的 403（無安全 header）誤報成目標缺陷（已重現 10 筆假 finding）；T18 以 `X-Secscan-Guard`（guard 會清掉上游偽造的同名 header）丟棄這些結果，並加 fixture 測試。(3) 載入前加 `-dut`（disable-unsigned-templates；42/42 檔都有 PD 簽章 `# digest:`）並在掛載前逐檔驗證 sha256、只掛這些檔（不掛整棵樹）。(4) 遮罩（SEC-14）涵蓋 `extracted-results`、`request`／`response`／`curl-command`（`email-extractor`、`credit-card-number-detect` 的輸出就是被擷取字串）。
- lock 檔若要隨 wheel 打包（runner 在容器內讀），需在 T18 確認 package-data 設定（目前自 src 樹讀取可用）。
- 殘餘：完整性鏈是「自我證明」的（協調改動 lock＋常數＋manifest 不會被離線測試抓到，真正的獨立驗證是 gated live `--check` 以鎖定 archive 重新推導，加上程式審查）；單人審查；清單對準 lab、不追求 Nuclei 全面覆蓋；預算對 Nuclei 的分配在 M4 後續依量測調整（§16.4）。

### 23.6 使用者的簽核（2026-11-04）
- **模板選擇與排除清單：接受**，條件是補充 42 個模板的適用範圍 → `TOOLS.md` §2.1.1：結論只限這 42 個檢查、對準 lab 的通用與技術棧模板（不含特定產品的 CVE）、只做匿名的 HTTP 掃描；沒有命中不代表沒有弱點；主動探測受 grant 與 guard 限制（例如 strict-1 擋掉帶 % 的 path 探測），被擋下的是「平台阻擋」而不是「沒有弱點」。
- **`-ni` 與證據保存：有條件接受**，條件是補充安全控制與資料管理 → `TOOLS.md` §2.1.2：`-ni`、`-duc`、`-dut` 與 vendored 模板逐檔 sha256 的作用與限制（`open-redirect-generic` 的 payload 字串含 `oast.me`，但 guard 只放行 target origin，即使不加 `-ni` 也連不出去）；證據在哪裡、誰看得到、遮罩到什麼程度（只遮罩憑證形狀的值，email、卡號等偵測目標以原文存在 `evidence` 與 runs volume）、保存期限與加密留在 T23，以及 lab 的資料都是合成的種子資料。
- 單人審查的效度威脅以這次簽核為準，記在這裡與 `TASKS.md` T17。

## 24. T18：Nuclei Adapter、JSONL parser 與引擎整合（2026-11-01）

把 Nuclei 以 ZAP 既有的形狀接進系統（§23.5 的 DoD 全數落實）；既有 ZAP 不回歸。

### 24.1 匿名掃描、直接命令、proxy 走機密檔
- 本輪只做**匿名**掃描（`target_auth=False`）：凍結的 42 個模板多為未認證偵測；目標 secret 的 `-sf` 注入留待後續（需要時再加第二個 CommandTemplate 與 nuclei 的 secret-file）。
- 直接以 `nuclei` 為容器 entrypoint、逐旗標組參數（映像 ENTRYPOINT 即 nuclei，免 shell）。admission 的 `CommandTemplate` 逐旗標比對（literal＋`ArgumentPattern`），順序與 `plan_nuclei_run` 一致。
- 目標流量只能經 egress guard：proxy 以 `-p /scan/secret/proxy-url` 從**檔案**讀（nuclei `-p` 支援 file input），含 token 的 proxy URL 不上命令列（CLAUDE.md §9）。nuclei 的 config/cache 以 `HOME=/tmp` 指向容器的 tmpfs（唯讀 rootfs 下才寫得了）。

### 24.2 模板 vendoring 與完整性鏈（反轉 T17「只提交清單」）
- runner 要掛載模板給 nuclei 跑，必須有實際檔案：將 T17 鎖定 archive（v10.5.0，sha256 已驗）中的 **42 個 PD 簽章模板 vendored 進 repo**（`src/.../nuclei/templates/http/<類別>/<名稱>.yaml`），隨 wheel 打包（uv_build 預設含）。
- 完整性鏈：`plan_nuclei_run` 以 `load_template_files()` 逐檔對 lock 的 sha256 驗證後組成 `ExecutionPlan.inputs`（扁平 `<id>.yaml`，掛進 `/scan/in`）；admission 以每模板 `ContentDigest`（獨立白名單）再驗一次；`plan_hash` 涵蓋每檔內容；契約測試另驗 vendored↔lock↔policy↔manifest 一致。
- CRLF 保全：部分上游模板帶 CRLF、lock 的每檔 sha256 對原始位元組計算 →`.gitattributes` 以 `-text` 關閉行尾正規化、pre-commit 的 trailing-whitespace／end-of-file-fixer 排除此目錄（否則改寫會破壞 sha256）。`-dut` 只跑簽章模板（42/42 有 `# digest:`）。

### 24.3 判定階梯、guard-403 過濾、遮罩
- parser（`nuclei/results.py`）純函式、不丟例外，比照 `zap/results.py`：非零退出（`collect_exit_codes={0}`）→ ENGINE_FAILED；報告讀不到／過大／任一行壞 → OUTPUT_INVALID；空檔＋有 forwarded → 乾淨成功（零告警，與失敗明確可分）；無 forwarded → NO_TARGET_TRAFFIC。
- **guard-403 過濾**：以回應的 `X-Secscan-Guard` header 權威排除 guard 的合成 403（guard 會剝除上游偽造的同名 header）；`DENY_MESSAGE` body 僅在無 telemetry 時 fallback（body 目標可控）。目標真正回的 403 不被誤殺（單元測試釘反例）。budget/wall-clock 逾時由 runner 以 BUDGET_EXHAUSTED/TIME_LIMIT 處理（收集前），worker 傳 `time_limit_reached=False`。
- **遮罩**兩層：runner 以 `redact_outputs=True`／`SecretMasker` 在收集時對整份 JSONL 做位元組級秘密遮罩（target bearer／proxy token，涵蓋 request／response／curl-command）；parser 另以 `redact_text`／`redact_url` 做文字層遮罩（extracted-results、matched-at）。限制：`redact_text` 只認憑證形狀，`email-extractor`／`credit-card-number-detect` 擷取到的 email／卡號本身是偵測目標，目前以原文存入 `evidence`（lab-only 風險；PAN／email 專用遮罩或只存雜湊留待後續）。

### 24.4 可用性、版本、速率、DB
- **環境探測＋靜態版本**：不新增容器能力探測（比照 FAKE）；可用性以映像存在＋guard 就緒判定。`/scan-profiles` 以鎖定的 `NUCLEI_VERSION`（digest 已鎖定、真實可信）、`rule_count=42`、`nuclei_definition_sha256()` 揭露。GET /scanners 的版本來自能力探測，nuclei 沒有容器探測、故為 null（可用性仍正確；版本一致化留待日後加探測）。
- 凍結速率/並行：`-rl` 取 guard 的 req/s、`-c 1`、`-bs 1`、`-retries 0`、`-timeout 15`。
- DB：migration v0012 把 `profile_definition_valid` 放寬為 `engine IN ('zap','nuclei')`；runner 為 nuclei 記 `nuclei_definition_sha256()`（profile-independent）。

### 24.5 真實 e2e 與多來源
- `make test-live-fixture-nuclei`：以真的 nuclei 掃 fixture app 弱點版（insecure）與修補版（secure）。為產生乾淨正負對照，把弱點版的 CORS 最小擴充成**可利用**（反射 Origin＋`Allow-Credentials: true`）：nuclei `cors-misconfig` 在弱點版命中、修補版不命中；同一問題也由 ZAP 10098 偵測 → M4「同一問題多來源」的實證（FX-06）。
- 實跑驗證（2026-11-02）：兩版 succeeded；plan_hash、與 /scan-profiles 一致的定義；`observed ⊆ forwarded`（guard-403 不誤報）；平台阻擋（PATH_AMBIGUOUS、METHOD_NOT_AUTHORIZED）；共享預算未耗盡；容器清理。nuclei 弱點版 `cors-misconfig` 1＋`http-missing-security-headers` 10 筆、修補版 6 筆（無 CORS）。
- 多來源實證（同日重跑 `make test-live-fixture`，確認加 Allow-Credentials 後 ZAP 無回歸）：ZAP 的 `10098 Cross-Domain Misconfiguration` 在弱點版命中 5 筆、修補版 0 筆，和 nuclei `cors-misconfig` 指向同一個 CORS 問題。

### 24.6 T18／T19 邊界
- **不在 T18（T19）**：Observation→Finding、`rule_groups.yaml`、OWASP Top10:2025／API2023 對應、fingerprint、跨工具合併；嚴格 severity／confidence 正規化（T18 只做 raw 透傳＋穩定 label，confidence 以 `unknown` 佔位，因 DB 要求非空）。
- 殘餘：匿名掃描（auth 延後）；fixture 的乾淨 nuclei 對照以 CORS 為主（`cors-misconfig` 加 `http-missing-security-headers`：弱點版 11 筆、修補版 6 筆；其餘模板在此自製小站多半不命中，屬預期——對準 lab 靶機的覆蓋見 `TOOLS.md` §2.1）。
- 其他已知限制：`open-redirect-generic` 的 payload 含 `oast.me` 字串（僅當參數送出、非 interactsh callback，`-ni` 仍有效；多數帶 `%` 的探測被 guard 擋），不改 payload（會破壞 `-dut` 簽章）；JSONL 大小上限沿用 ZAP 的 8 MiB（nuclei 每筆帶完整 request/response，大頁面可能超過而整份失敗，lab 靶機碰不到）；vendored 的 42 個上游模板來自 ProjectDiscovery 的 nuclei-templates（provenance 與版本見 `SOURCES.md` S23；散布前再確認上游授權並視需要附 NOTICE）。

## 25. T19：Observation → Finding、rule groups、對應版本與保守的 fingerprint（2026-11-03）

observation 仍是不可變的單次觀察；T19 在它之上加上 target 層級、跨掃描的 finding。既有原則不變：§2 第 11 列「語意規則群組＋method＋route＋參數＋auth role 都相同才合併；多工具命中不升級」、`ARCHITECTURE.md` §10、`CLAUDE.md` §10、T16 的交接（身分失效的 run 不併入已認證身分的 finding）。

### 25.1 使用者的決定（2026-11-03）
1. **API 範圍**：T19 只做 `GET /scans/{scan_id}/findings`（含這個 scan 的來源摘要）；`GET /findings/{id}` 的完整來源追溯（observation → artifact → run → plan_hash）留給 T20。
2. **severity 聚合**：取各來源正規化之後的**最高值**；來源數本身不加分；來源不一致時 `severity_conflict=true`，並列各來源的原值。
3. **ground truth**：T19 一併更正 T30 案例表的 OWASP 標記（§25.10），不改正負例的語意。
4. **live e2e**：實跑「同一個 scan 同時跑 ZAP＋Nuclei」的 fixture e2e（弱點版、修補版各一）。

### 25.2 模組、分層與連結表
- 新功能模組 `src/secscan/findings/`：`domain/`（純函式：`owasp`、`normalization`、`taxonomy`、`fingerprint`、`linking`、`model`）、`taxonomy/`（`rule_groups.yaml`、`owasp_top10_2025.json`）、`models`、`repository`、`service`、`schemas`、`router`。
- import-linter 的 layers 在 `health | runner | worker` 之下加 `scanners | findings`（findings 以 scans 的觀察與 scan 的授權為基礎，和 scanners 互不依賴）；`findings.domain` 受「domain 不得依賴框架／DB／Docker」約束。
- **連結表，不在 observations 加欄位**（推翻 `ARCHITECTURE.md` §6「observations 加 finding_id、rule_group」）：observations 有 append-only 的 trigger、連結在入庫之後另外計算，而且每個連結要記下當時的 taxonomy 版本。`finding_observations` 以 observation_id 為主鍵：每個觀察最多連結一次。

### 25.3 rule_groups.yaml（人工審查、有版本、執行期釘選）

> 2026-11-04 使用者簽核之後改為 schema 2：跨引擎只經同一次 scan 的佐證、CORS 只標示相關、加上 category 與技術識別，見 §25.14。以下是 v1 的紀錄。

- 以 specs 的嚴格 YAML 解析（拒絕 anchor、alias、tag、重複的 key），欄位逐一檢查，錯誤是 `TaxonomyError`。`RULE_GROUPS_SHA256` 在執行期核對：檔案被改動就 fail closed；`FindingLinker` 建立時載入，所以 worker 啟動就失敗，不是每個 run 才失敗。
- 每個群組：`id`（不含 `:`，不會和 fallback 撞名）、`title`、`kind`、審查後的 `cwe`、`granularity`（`parameter` 預設／`endpoint`：參數本身是群組身分，例如缺的 header 名）、`resource_scoped`、curated 的 `owasp_api_2023`（每筆要有 rationale）、`review`（`reviewed`／`provisional`＋`evidence`）、`members`（`engine`、`rule`、`variant`）。
- **「不可信的映射不跨工具合併」的機制**：成員跨引擎的群組必須 `reviewed` 並寫下 evidence；`provisional` 只能單一引擎、標 `needs_review`。
- **查找只做精確比對**（簡化計畫中的「rule 萬用字元」）：`(engine, rule, variant)`，variant 為 None 或等於 rule（ZAP 的 alertRef 等於 pluginid）時是「沒有 variant」。對不到就是 fallback `engine:rule[:variant]`：永遠單一引擎、`needs_review`，kind 由等級推導（info → informational，其餘 → security），CWE 用工具回報的值（只有 fallback 用；審查過的群組沒有填 cwe 就是沒有，code review 發現）。kind 在 fingerprint 中，所以同一條未審查的規則若工具改了等級（info ↔ 非 info）會成為另一個 finding：接受這個取捨，因為把 informational 的偵測固定成 security 會誤導；要穩定就是把規則審查進群組。萬用字元會讓同一個模板的不同 matcher（例如不同的缺少 header）被合併，不夠保守。
- v1 只收 2026-11-03 之前**真實輸出**出現過的規則（`CLAUDE.md` §1），審查紀錄見 `TOOLS.md` §8：
  - 跨引擎（4 個，evidence 是 T18 fixture 弱點版 GET / 的同一個回應）：permissive CORS（ZAP 10098 ↔ nuclei `cors-misconfig:arbitrary-origin`，CWE-942）、CSP 未設（10038-1 ↔ `content-security-policy`）、X-Content-Type-Options（10021 ↔ `x-content-type-options`）、anti-clickjacking（10020-1 ↔ `x-frame-options`，CWE-1021）；都是 `endpoint` 粒度（ZAP 把 header 名放在參數、nuclei 沒有參數）。
  - 單一引擎：其餘出現過的 ZAP 規則與 nuclei 的 header／資訊類模板。
  - 刻意留給 fallback：動態的 variant（`tech-detect` 的技術名、`fingerprinthub-web-fingerprints` 的指紋名）、需要人工判斷嚴重程度的 `werkzeug-debugger-detect`。計畫中「凍結的 42 個模板都建群組」取消：沒有真實輸出、variant 未知，fallback 才是保守的預設。
- 群組審查後的 CWE 必須是成員工具自己回報的 CWE 之一（契約測試核對 nuclei 的模板分類與 ZAP golden fixture 的 cweid），不為了對應 OWASP 改 CWE。
- **最終簽核屬使用者（單人審查，列為效度威脅，比照 §23.4）**；使用者已於 2026-11-04 簽核並要求修正（§25.14）。

### 25.4 正規化（`NORMALIZATION_VERSION = "1"`）
- severity：ZAP riskcode 0–3 → info／low／medium／high；Nuclei 的值一對一（去空白、不分大小寫）；其他（含 `unknown`）→ info＋`needs_review`。
- confidence：ZAP 0–4 依 ZAP 自己的標籤（false_positive、low、medium、high、confirmed：工具的自評，不是人工 triage）；Nuclei 不回報 → unknown。**finding 不聚合 confidence**，只在各來源保留。

### 25.5 OWASP 對應
- **Top 10:2025（official）**：`tools/freeze_owasp_top10.py`（比照 T17 的產生器）讀手動下載、鎖定 commit（`OWASP/Top10@57db8ec5`，2026-04-06）的 10 個官方分類 markdown，逐檔驗 sha256 → 擷取「List of Mapped CWEs」→ 驗證分類齊全、CWE 不重複（重複或格式改變就失敗、由人決定）→ 寫 `owasp_top10_2025.json`（含來源 commit 與每檔 sha256），sha256 釘在 `OWASP_TOP10_2025_SHA256`；`make owasp-top10-check` 逐位元組重現。實際內容：249 個 CWE、跨分類沒有重複。
- 官方自身的不一致（記錄、以分類頁的清單為準）：Introduction 寫 A05「38 CWEs」、全部「248 CWEs」，分類頁的清單是 A05 37 個、合計 249 個（A05 頁的 Background 也寫 37）。
- 對應方式：finding 的 CWE（群組審查後的，fallback 是工具的）查官方表；查不到就是 none。結果中值得注意的：缺安全 header 的 CWE-693 與 clickjacking 的 CWE-1021 在 **A06:2025 Insecure Design**；ZAP 10098 回報的 CWE-264 是 CWE 的分類節點，不在任何清單。依原則照實標記，不改 CWE 去湊直覺上的 A02。
- **API Security Top 10:2023（curated）**：只來自群組的 `owasp_api_2023`（rationale 依官方 API8:2023 頁：「CORS policy is missing or improperly set」「Security or cache control directives are not sent」「include applicable Security Headers」，`SOURCES.md` S106）；fallback 一律 none。API6、API10 是 DAST 的限制。
- finding 記 `owasp_top10_2025_source`（official／none）、`owasp_api_2023_source`（curated／none）、`mapping_version`（人讀的摘要，例如 `rules-1+owasp2025-57db8ec5ddbc+norm-1+fp-1`）與 `taxonomy_sha256`（三份資料與 fingerprint 版本的雜湊）；每個連結也記當時的 `taxonomy_sha256`。

### 25.6 fingerprint、route 樣板化與身分
- `sha256(canonical JSON)`：`{v, target_id, kind, rule_group, method, route, route_templated, parameter_location, parameter_name, auth: {role, verified}, resource}`。標題、證據、等級、query、工具的 CWE 都不在裡面。`endpoint` 粒度不含參數；`resource_scoped` 的群組加上字面 path（v1 沒有這類群組）。
- `route_templated`（安全審查後加入）：route 是含佔位符的規格樣板時為 true。工具保留大括號的字面 path（例如 `/orders/{id}`）和樣板的文字相同，沒有它就會併入整個樣板層級的 finding；不放整個 route_source，是讓沒有佔位符、與字面 path 完全相同的 operation 仍能和沒有規格的掃描合併。
- route：scan 有規格時，把 (method, path) 以 coverage 的同一套比對（`scans.domain.coverage.most_specific`，由原本的 `_matches` 公開，行為不變）對到凍結、範圍內的 operation；剛好一個最具體的才用樣板（`openapi`），否則字面 path（`literal`）。不 decode、不改大小寫；grant 語法不接受的 path（編碼、空段、大括號）保持字面。operation 先依 (method, 段數, 結尾斜線) 分組（`RouteIndex`；不寬鬆的比對本來就要求三者相同，結果不變），連結時持有 run 的鎖，最多約 2 萬個觀察 × 1,000 個 operation 不必逐一比對。
- 身分：`auth_verified` = anonymous，或 preflight `passed`、guard 記下帶認證的請求被接受過（`accepted > 0`），而且**沒有任何**被拒絕（`rejected`）、退化（`regressed`）或探針被拒絕（`probe_rejected`）的請求、`lost` 是 false；不明一律 false。未驗證的觀察是另一個 finding（仍然可見），不併入已驗證身分的 finding；T22 不能據以標 `not_observed`。
- 比 T16 的 `lost` 嚴格（安全審查發現）：`lost` 是揭露用的門檻（退化 2 個以上、探針被拒絕或從未被接受），中途過期、之後只打新端點的 run 不會觸發它，若只看 `lost`，整個 run 的觀察會被當成已驗證。T16 的真實資料支持這個門檻：健康的已認證 run（VAmPI、Juice Shop、fixture 的 api，共 13 個錄製）都是 `rejected = 0`，token 過期的 run 是 `rejected = 74`、`regressed = 2`。代價：角色本來就會碰到 401／403 的掃描（例如 standard_user 掃到 admin 區、WAF 擋下攻擊請求），觀察都是未驗證的 finding（獨立、不漏報，只是較少合併）；scan 層級的揭露（coverage 的 `AUTHENTICATION_LOST`）仍用 `lost`，所以可能出現「scan 沒有揭露失效、finding 卻是未驗證」——前者是揭露門檻，後者是合併的證明門檻（code review 提醒）。

### 25.7 連結流程（worker）
- `FindingLinker.link(lease)`：一個 transaction、**冪等**（只處理還沒有連結的觀察）。鎖序固定：以 lease 的 fencing `FOR UPDATE` 鎖 run → 依 fingerprint 的順序 `INSERT … ON CONFLICT DO NOTHING` → 依 fingerprint 的順序 `SELECT … FOR UPDATE` 既有的 finding → 更新聚合（只往上）→ 寫連結。不鎖 scans（對帳是 scans → runs）。新增階段只鎖新的列、鎖定階段在新增之後，兩個 run 同時連結不會互等成環；以併發的整合測試驗證（同一個 scan 的 zap 與 nuclei 同時在解析）。只讀連結需要的觀察欄位（不讀 evidence 等長文字）。
- `Worker` 的 `findings` 是必填的參數（只測解析的測試明確傳 None）：新的組裝點不會默默少了連結（安全審查）。
- worker 在解析入庫之後、coverage 之前呼叫；中斷之後重試（已記錄的判定不再解析）只補上沒有連結的觀察。T19 之前的觀察不回填。
- last_seen：`greatest(last_seen_at, clock_timestamp())`，在持有列鎖時取時間，不會倒退。

### 25.8 資料表（migration v0013）
- `findings`：(target_id, fingerprint) 唯一；first／last seen 以複合 FK 引用 `scanner_runs`，**不直接引用 scans**（worker 持有 run 的鎖時檢查 scans 的 FK 要 KEY SHARE，會和對帳的 scans FOR UPDATE → run 形成死鎖，同 observations）。trigger `findings_guard`：新的列一律從 unreviewed、open 開始；身分、對應、triage 與 lifecycle 不可修改（T21 另以 migration 開放 triage）；只有 last seen 與三個聚合可以更新，而且只會往上；不能 DELETE／TRUNCATE。CHECK 涵蓋列舉、`A01–A10:2025`、`API1–10:2023` 的格式與來源一致、CWE 與來源一致、參數位置與名稱一起有值。
- **不另存 `fingerprint_inputs` 的 JSON**（計畫原本有，≤ 4 KiB）：欄位都在表中，可以重算；而 path 是目標可控的文字，長的非 ASCII path 會超過上限、讓連結失敗並拖垮 run（重試耗盡）。
- 實作中發現：CHECK 的文字經 SQLAlchemy 的 `text()`，`'^A(0[1-9]|10):2025$'` 中的 `:2025` 被當成 bind 參數、渲染成 NULL（CHECK 永遠不成立）；以 `\:` 跳脫，model 與 migration 一致。既有的 CHECK 沒有「冒號後接字母或數字」的寫法。
- finding_observations 以 FK 引用 observations：對 observations 單純 TRUNCATE 時 PostgreSQL 先以 0A000 拒絕（trigger 不會執行），既有測試改成 `TRUNCATE … CASCADE` 驗證 trigger 本身（同 artifacts）。

### 25.9 API
- `GET /api/v1/scans/{scan_id}/findings?kind&severity&engine&triage_state&page&limit`：先以 `ScanService.get` 檢查（其他 project 與不存在的一樣 404，SEC-16），列出這個 scan 的觀察連結到的 finding，等級由高到低、再依群組、route、id。`sources[]` 只有這個 scan 的來源（引擎、規則、variant、原值、正規化值、工具的 CWE、觀察數）；engine 篩選的是「這個引擎在這個 scan 有來源」，sources 仍列全部。不輸出 CVE／CVSS（沒有資料來源，不捏造）。
- `normalized_severity` 是 finding 所有掃描的聚合（只會往上）；`severity_conflict`、排序與 `severity` 篩選都用這個 finding 層級的值（triage 的優先順序看的是議題本身）。`scan_severity` 是這個 scan 的來源中的最高值（安全審查：同一個 finding 在別的 scan 可能更高，只看 normalized_severity 會誤解這次掃描的結果）；這個 scan 自己的來源是否一致，看 `sources` 的正規化值（code review 提醒）。

### 25.10 ground truth 更正（研究資料的更正）
- T30 案例表把 2021 的編號當成 2025（「A03:2025 Injection」、「A05:2025 Security Misconfiguration」、「A04:2025」）。更正方式：`Case` 改記案例的 `cwe`，`top10_2025` 由官方表查得，`api_2023` 維持 curated；契約測試核對每個案例的標記等於官方表對該 CWE 的對應（`tests/contract/test_fixture_cases.py`）。正負例、可達性與量測結果都不變。
- 差異：FX-01／02／03／PB-01（CWE-89、79）A03 → **A05**；FX-04（CWE-209）A05 → **A10**；FX-05（CWE-693）A05 → **A06**；FX-06（CWE-942）A05 → **A02**（另加 curated API8:2023）；FX-07（CWE-1004）A05 → **A02**；FX-08（CWE-601）A01 不變；FX-09（CWE-530 Exposure of Backup File）A05 → **無**（官方清單沒有 530，不改用父節點去湊）；FX-10（CWE-639）加 **A01**、API1:2023 不變；FX-11（CWE-915）「A04:2025」→ **A08**、API3:2023 不變；FX-12（CWE-213）維持只有 API3:2023（213 不在官方清單）。contract 案例沒有 CWE 與 OWASP。

### 25.11 驗證
- 離線：`tests/unit/findings/`（taxonomy 的壞檔與跨引擎規則、正規化、OWASP 解析與釘選、fingerprint 的 Hypothesis property test、連結與聚合；`findings.domain` branch 100%）、`tests/contract/test_taxonomy_contract.py`、`tests/integration/test_{finding_linker,findings_schema,findings_api}.py`、worker 的整合測試（ZAP golden 的 11 個觀察都連結到審查過的群組；中斷之後重試補上連結）。
- live：`make test-live-fixture-findings`（2026-11-03，2 passed）：弱點版 34 個觀察都恰好連結一次、29 個 finding，4 個審查過的跨引擎群組在 GET / 各合併成一個 finding、等級取最高值並標衝突；修補版沒有 CORS 的 finding。細節見 `TASKS.md` T19 的交付。

### 25.12 限制與邊界
- T20：去重的反例測試套件（同 CWE 不同參數、同 route 不同身分或物件、不同弱點）與 `GET /findings/{id}` 的來源追溯。T21：triage PATCH、audit、報告。T22：複掃比較（讀 `auth_verified`；不據未驗證的 finding 標 `not_observed`）。
- 限制：query 不在 fingerprint 中（action／type 這類語意 query 會被合併成同一個 route，未處理）；T19 之前的觀察不回填；對應在 finding 建立時寫入、之後不隨 taxonomy 改版而改（新版本只記在新的連結上）；last_seen 依連結的時間而不是 scan 的順序；taxonomy 與 OWASP 對應是單人審查。
- 安全審查提出、留待後續（縱深防禦，目前沒有可利用的路徑）：DB 不檢查連結的觀察與 finding 屬於同一個 target、last seen 的 run 屬於同一個 target（由 linker 依 target 鎖定與查詢保證，整合測試釘住；T20 的來源追溯一併處理）；沒有規格的掃描以字面 path 為 route，敵意的目標可以製造大量不同的 path 或參數，每個都是永久的 finding（每個 run 最多約 2 萬個觀察；上限與保存期限在 T23 決定）。
- code review 提出、記入限制：連結的 transaction 持有鎖的時間隨 run 的大小增長（既有的 finding 逐筆 UPDATE）；P0 只有一個 worker，不會兩個連結同時等待；多個 worker 時，等鎖超過 `DB_LOCK_TIMEOUT_SECONDS` 會是 DB 的錯誤（worker 結束、run 留給對帳重試），屆時改成批次 UPDATE 並把等鎖逾時當成可重試。`findings.route_source` 記的是建立時的值：沒有佔位符的 route 在有或沒有規格的掃描都是同一個 finding，它的 route_source 取決於哪一次先建立（只影響顯示）。

### 25.13 審查（2026-11-03）
- security-reviewer：0 CRITICAL、0 HIGH、1 MEDIUM、6 LOW。已修：MEDIUM（身分判定只看 `lost`，§25.6）；LOW 的大括號 path 與樣板撞名（`route_templated`）、清單的等級語意（`scan_severity`）、連結時讀整個觀察與逐一比對 operation（只讀需要的欄位、`RouteIndex`）、worker 的 `findings` 預設 None（改成必填）、新增時可以直接寫入非初始的 triage（trigger）。記入限制：跨表的 target 一致性、finding 的數量上限。
- code-reviewer：0 CRITICAL、0 HIGH、1 MEDIUM、4 LOW（APPROVE）。已修：MEDIUM（沒有 cwe 的審查群組會吃到工具的 CWE，§25.3）；測試的缺口（併發測試改成確定性的：第一個連結在 commit 之前停住、確認第二個在等鎖再放行；`BATCH_SIZE` 改成 2 的跨批次測試；`RouteIndex` 的 Hypothesis property test）。記入取捨或限制：fallback 的 kind 由等級推導（§25.3）、清單的衝突與排序是 finding 層級（§25.9）、身分判定與 scan 層級揭露的門檻不同（§25.6）、連結持有鎖的時間（§25.12）。

### 25.14 使用者的簽核與修正（2026-11-04；rule groups v2、migration v0014）

| 審查範圍 | 簽核 | 處理 |
|---|---|---|
| CORS 去重 | 建議修改：增加相同根因的判斷條件 | 使用者選「同一次 scan＋證據行為也相同」才合併。ZAP 10098 偵測的是沒有 Origin 時回 `*`，nuclei `cors-misconfig:arbitrary-origin` 是反射任意 Origin 並允許 credentials：行為不同，所以拆成 `zap-cors-wildcard-origin`（misconfiguration、保留 ZAP 的 CWE-264）與 `nuclei-cors-arbitrary-origin-with-credentials`（vulnerability、CWE-942），以 `related` 標示相關，同一次 scan 同一個位置互相列出 `related_finding_ids`，不合併 |
| CSP／XCTO／XFO 去重 | 原則接受：確認相同回應與防護條件 | 使用者選「以 ZAP 為準＋同一次 scan 佐證」。群組的語意是 ZAP 的條件（10020-1 是既沒有 XFO 也沒有 CSP frame-ancestors）；nuclei 的成員（`corroborated_by`）只有在同一次 scan、同一個 method 與 path 有 ZAP 的觀察時才併入，否則留在自己的群組。nuclei 單獨的 XFO（不看 frame-ancestors，防護條件不完整）是 informational／hardening、CWE-693，不標 clickjacking |
| Security／Info | 有條件接受：明確定義分類準則 | 準則見下；security 再分 vulnerability 與 misconfiguration，避免把設定問題當成已驗證的漏洞 |
| OWASP 2025／API8 | 接受：保留原始 CWE、交代未對應項目 | 群組的 CWE 一律是成員工具自己回報的值（ZAP 的 CORS 改回 CWE-264）；API 另輸出 `tool_cwe_ids`（這個 scan 的來源工具回報的原始 CWE）與 `top10_2025_unmapped_reason`（`no_cwe`／`cwe_not_listed`）、`api_2023_unmapped_reason`（`not_curated`）。未對應的清單在 `TOOLS.md` §8.5 |
| 動態技術識別 | 建議補強：與 security finding 分開統計 | 使用者選「審查成技術識別類別」：`nuclei-tech-detect`、`nuclei-fingerprinthub` 的成員是 `*`，finding 以 `群組/技術名` 保留技術名，category 是 technology |

**分類準則**（使用者選「依受測情境的可利用性」並補充兩點）：
- **security**：依規則自己的偵測條件，顯示可被利用的行為或具有安全意義的防護缺失。再分：
  - `vulnerability`：偵測條件本身顯示可被利用的行為（主動探測得到的回應證據），例如注入、XSS、開放轉址、path traversal、CRLF、反射任意 Origin 並允許 credentials。
  - `misconfiguration`：缺少或設定不當的防護、資訊外洩，本身不足以證明可被利用，例如缺 CSP／XCTO／anti-clickjacking、ACAO `*`、版本資訊與內部 IP 外洩、缺 anti-CSRF token。
  - 兩者在人工 triage（T21）之前都只是工具的告警，**不是已驗證的漏洞**；報告與統計不得把 security 的數量說成已驗證的漏洞數。
- **informational**：`technology`（技術識別）、`detection`（檔案或功能存在：robots.txt、security.txt、OpenAPI 文件、OPTIONS、驗證請求）、`hardening`（在受測情境不適用的強化建議，例如 HTTP lab 的 HSTS、COOP／COEP／CORP、Permissions-Policy、Referrer-Policy；或防護條件不完整的檢查，例如 nuclei 單獨的 XFO）。
- **fallback**：kind 暫時依工具的等級，category 一律 `unclassified`、`needs_review`；在人工確認之前和審查過的 finding **分開統計**（API 可以 `?category=unclassified`、`?needs_review=true` 篩選）。
- 工具標 info 不等於低風險：`werkzeug-debugger-detect`（除錯器外露可能允許執行程式碼）審查為 security／misconfiguration、provisional（`needs_review`），等級仍保留工具的原值（不捏造等級）。
- kind 與 category 在 taxonomy 載入時與 DB 的 CHECK 都核對一致。

**佐證的實作**：連結 nuclei 的 run 時，查同一次 scan 中錨點群組成員的觀察（`(群組, method, path)`）；有的話改屬錨點群組，否則照自己的群組。為了讓連結看得到錨點，worker 依 sequence 解析同一個 scan 的 run：前面還有 run 在 collected 或 normalizing（`PARSING_RUN_STATUSES`）時不認領後面的 run（`scans/queue.py`；code review 發現 ZAP 解析失敗重試或多個 worker 時，nuclei 可能先連結）。ZAP 的 run 失敗或沒有觀察時，nuclei 就留在自己的群組（保守，不會誤合併）。ZAP 的 run 沒有佐證成員，連結時不查錨點。跨 scan 不佐證：前一次 scan 的 ZAP 不讓這次的 nuclei 併入。「相同回應」無法直接證明（兩個工具各送各的請求），以「同一次 scan、同一個 method 與 path」作為最接近的條件，並記為限制。

**資料表**：migration v0014 為 findings 加上 `category`（CHECK：值合法、和 kind 一致；既有的列以 ADD COLUMN 的預設值填成 unclassified、不經 UPDATE，再移除預設值）；category 和身分一樣不可修改，所以回填的列一併標成 `needs_review`（只會往上），人工確認之前和 v2 審查過的 finding 分開統計。要乾淨的分類就重建開發 DB（既有的 finding 都是開發與測試的資料）。fingerprint 的公式不變（`FINGERPRINT_VERSION` 仍是 1），群組改名讓 fingerprint 改變，以 `mapping_version`（`rules-2…`）區分。

**影響**：fixture 弱點版的 CORS 從「一個有兩個來源的 finding」變成「兩個相關的 finding」；M4 的「同一問題多來源」改由 header 群組的佐證合併展示，CORS 以相關標示呈現。T19 之前（v1）的 finding 都是開發與測試的資料。

**taxonomy 的驗證**（code review 補強，壞檔讓 worker 起不來）：佐證成員必須是另一個群組的精確成員、只能佐證一個錨點，而且它自己的群組不能也是錨點（合併只有一層）；`*` 不能和精確成員放在同一個群組；技術識別群組不能有 related，也不能被 related 指到（它的 rule_group 帶技術名，相關查詢對不到）。`KIND_CATEGORIES` 目前只有 security 與 informational：M6 加入 contract、robustness 的群組時要先定義它們的 category（現在載入時就會被拒絕）。

**限制**：
- 佐證以「同一次 scan、同一個 method 與 path」近似「相同回應」：兩個工具各送各的請求，回應可能不同（例如依 header 或 cookie 變化的頁面）。
- 同一個問題在不同 scan 可能有不同的身分：這次 scan 沒有跑 ZAP、ZAP 的 run 失敗，或 ZAP 沒有走到那個 URL 時，nuclei 的 header 告警留在 `nuclei-*` 群組；下一次 ZAP 有命中就併入 ZAP 的群組。這是保守的（不會誤合併，複掃也只會標 `not_observed`），但會讓複掃比較出現「一個消失、一個新增」，T22 比較時要對照 related／佐證的群組與覆蓋度（安全審查 L2）。
- nuclei 單獨的 XFO 是 hardening：ZAP 沒有走到的 URL 上真的缺 anti-clickjacking 時也只標 hardening，報告要揭露（安全審查 I1；符合簽核，CSP `frame-ancestors` 可能存在）。
- 技術名來自目標的回應（受目標控制），只接受規則的字元集、最多 64 個字元，否則走 fallback；T21 的報告輸出 title 與 rule_group 時要做安全編碼。

**審查**（簽核分支）：
- security-reviewer：0 CRITICAL、0 HIGH；項目 M1、L1–L4、I1。已修：M1（同一個等級內 security 排在 informational 之前，清單不會被大量的技術識別蓋過）、L1（v0014 回填的列標 `needs_review`）、L3（related 只查本頁的位置）、L4（技術名的字元集與長度）、L2（worker 依 sequence 解析同一個 scan 的 run，剩下的情況記入限制）。I1 記入限制。
- code-reviewer：0 CRITICAL、0 HIGH、1 MEDIUM、3 LOW（APPROVE）。已修：MEDIUM（解析順序，同上，並加上依序認領的整合測試）；LOW 的 taxonomy 驗證（佐證只有一層、`*` 不混精確成員、related 不指向技術識別群組）、效能（related 只查本頁的位置、ZAP 的 run 不查錨點）、測試與遷移（帶資料的 0013 → 0014 升級測試、回填的列標 `needs_review`、`KIND_CATEGORIES` 的 M6 註記）。

## 26. T20：去重的反例、物件鑑別（fingerprint v2）與來源追溯（2026-11-04）

T20 是 M4 的最後一項：DoD 是「同 CWE 但參數不同、同 route 但身分或物件不同、不同的弱點都不會誤合併」與「所有證據都能追溯到來源」。T19 的交接另要求處理跨表的 target 一致性（§25.12）。

### 26.1 使用者的決定（2026-11-04）
1. **物件鑑別**：未審查的規則保留物件（樣板 route 下 fallback 的 resource 是字面 path），審查過的群組照舊合併；`FINGERPRINT_VERSION` 升到 2。
2. **追溯 API**：明細＋觀察分頁。附帶條件：大量 scan 的歷史也要分頁，明細只留彙總、first／last 與有限的近期紀錄；每個觀察都能追到 artifact、run、plan_hash、工具與 parser 的版本、連結當時的 taxonomy_sha256，不受日後版本影響；只給授權範圍內的遮罩證據與 artifact metadata，不給檔案內容與 storage_key；穩定排序、支援 scan_id 與 engine 篩選，資料成長時不重複也不遺漏；驗收涵蓋跨多次 scan、單一 scan 大量觀察與部分 run 失敗。
3. **真實資料**：T30 的錄製升為 golden fixture，並擴充 `make test-live-fixture-findings`；不另外做匿名／認證身分的 live 掃描。
4. **部分失敗**：live 加一個情境（同一個 fixture、小的時間預算跑 ZAP＋Nuclei），先實測確認可重現再定斷言；已取得的資料不遺失、狀態正確不誤判成功、沒有殘留、重試不重複；保存預算、狀態、結果與追溯紀錄作為 M4 的驗收依據。

### 26.2 物件鑑別（fingerprint v2）
- `linking._object_scoped`：resource 是字面 path 的條件是群組 `resource_scoped`，**或** fallback 而且 route 是樣板（`Position.templated`）。fallback 沒有審查過，無法判斷問題在端點還是在物件上；規格的樣板把 `/orders/1001`、`/orders/1002` 變成同一個 route，不能證明是同一個問題（不誤合併優先）。沒有規格時 path 本來就是 route，不重複加入；同一個物件在複掃時仍合併（MERGE-06）。
- 審查過的 34 個群組逐一審查為端點或參數層級（`TOOLS.md` §8.7），`resource_scoped` 都維持 false；真實的 api 錄製沒有 fallback，所以 11 個觀察的分群不變（契約測試）。
- `FINGERPRINT_VERSION = 2`：fingerprint 文件的 `v` 改變，所以**所有** finding 的 fingerprint 都改變（不只 fallback）。v1 的 finding 保留、不改寫（不可修改），新的觀察連結到 v2 的 finding；`mapping_version` 變成 `…+fp-2`、`taxonomy_sha256` 也跟著變，每個連結記得是哪一版語意。既有的 finding 都是開發與測試的資料：要乾淨就重建開發 DB（不由 migration 自動清除）。T22 比較時只比同一個 fingerprint 版本的 finding。
- 刻意的合併與限制：同一個 role label 的不同 auth profile 合併（`CLAUDE.md` §10 以 auth role 為身分，MERGE-05）；以 query 指定物件（`?id=1`）與 action／type 類的語意 query 仍不在身分中（沒有真實輸出支持規則，沿用 §25.12）。

### 26.3 去重的反例套件
- `tests/dedup_support.py`：純函式的不變式，unit、contract、integration、live 共用。每個 finding 的觀察：method 相同；字面 route 時 path 等於 route；有 resource 時 path 等於 resource；參數粒度時位置與名稱相同；auth role 相同；不同的 (engine, rule, variant) 只能是同一個審查群組的成員；跨引擎只限佐證群組，而且佐證的觀察在同一次 scan、同一個 method 與 path 有錨點。不變式以目前的 taxonomy 檢查，只用在以目前版本連結的資料。
- `test_dedup_counterexamples.py`：具名的反例 DEDUP-01–18 與合併的對照組 MERGE-01–06（`SECURITY_AND_TESTING.md` §4.3），加上三個 Hypothesis 性質。在舊的 linking 下 DEDUP-08、18 與同一個 run 的版本失敗（RED），改了之後全部通過。
- `test_dedup_recorded_outputs.py`：golden fixture → 真的 ZAP parser（以 manifest 記下的 grant 重建 scope）→ `plan_links`。web 23 個觀察 → 22 個 finding：POST /login 的 SQLi 是 username、password 兩個；GET /go 的 `next` 上三個不同群組；GET / 五個不同群組；10098 在五個 path 各一個；唯一的合併是 /search 的兩個 X-Content-Type-Options（只有 query 不同）。api 11 → 11，樣板化成 `/api/orders/{id}`、`/api/users/{id}`、`/users/{username}`，GET 與 POST /api/users 各自獨立。
- golden fixture 的審查：原樣複製、不改位元組；`report.json`、`zap.log` 的 sha256 等於 runner manifest；目標只有 lab 主機（報告中其他的 URL 是 ZAP 說明文字的參考連結，以及開放轉址告警中 ZAP 自己的測試 payload `https://8342850138707411404.owasp.org`：它只是參數值，guard 只允許 lab 的 origin）；沒有 Authorization／Bearer／Cookie 的值、JWT、平台 key 或 fixture 的種子 token（`cookie`、`token` 只出現在 ZAP 的說明文字與 anti-CSRF 的參數名清單）；telemetry 只有 method、path、auth 旗標與 status。這兩份錄製只用於去重的回歸，不用來調整規則（holdout 在 T27／T28）。

### 26.4 連結序號與快照（分頁的一致性）
- 計畫原本以「同一個 target 一次只有一個進行中的 scan、run 依序解析」主張 offset 分頁不會重複或遺漏；審查（architect）指出不成立：scan 的 `created_at` 是 transaction 開始的時間、不是 commit 的順序，讀取第一頁時尚未提交的連結之後才出現，若排序落在已讀過的位置就會遺漏；`clock_timestamp()`、UUID、sequence 或 `MAX(id)` 都不保證 commit 的順序，單純改成 cursor 也一樣。
- 採用：**每個 finding 的連結序號＋讀取時的高水位**。migration v0015 加上 `findings.observations_linked` 與 `finding_observations.link_sequence`（`(finding_id, link_sequence)` unique、> 0）。linker 持有 finding 的列鎖（新增或 `FOR UPDATE`）時，每個 finding 每個 transaction 以一次 `observations_linked + k`（新的 finding 直接以 k 建立）保留 k 個序號，連結帶著 (保留之前的值, 之後] 的序號寫入。DB 強制：
  - BEFORE INSERT 的 trigger：序號不能超過這個 transaction 看得到的連結數（別的 transaction 保留、還沒提交的序號看不到，所以也不能用）。
  - deferred 的 constraint trigger：commit 時連結數必須等於這個 finding 的連結筆數；配合 unique 與 > 0，序號恰好是 1..連結數，不留空號（保留了不用、或直接改計數都會讓 commit 失敗）。
  - `findings_guard`：連結數只能增加。
- 為什麼一致：同一個 finding 的配號以列鎖排隊，所以連結依序號的順序提交，rollback 也退回計數。讀取時的 `observations_linked`＝H：序號 <= H 的連結都已提交，之後提交的序號一定大於 H，所以「`link_sequence <= H`」的集合固定；API 以 `as_of` 帶回 H 翻頁。
- **第一版改掉的原因（量測）**：第一版由 BEFORE INSERT 的 trigger 逐列 `UPDATE findings … + 1` 指定序號。審查（code-reviewer、security-reviewer）指出同一列在一個 transaction 中更新上萬次是二次方的成本（舊版本無法 prune，HOT 鏈越來越長）；敵意的目標可以讓上萬個只有 query 不同的觀察落到同一個 finding（parser 的上限是每個 run 2 萬個）。實測（db-test，同一個 run 的 N 個觀察連到一個 finding，`FindingLinker.link` 的時間）：

  | N | 逐列更新（第一版） | 一次保留（採用） |
  |---|---|---|
  | 1,500 | 0.47 秒 | 0.15 秒 |
  | 5,000 | 1.81 秒 | 0.46 秒 |
  | 20,000 | 16.65 秒 | 1.68 秒 |

  第一版在 2 萬個時已接近 30 秒的 lease 與 statement timeout；採用的版本接近線性。量測是一次性的（開發機 Apple M1 Pro、OrbStack 的 db-test），不是效能基準，腳本不提交。
- 鎖序不變：linker 本來就先以 fingerprint 的順序新增（鎖住新列）並 `FOR UPDATE` 既有的 finding，之後才寫連結；trigger 只用不加鎖的 SELECT；不鎖 scans（§25.8）。commit 時每個有變動的 finding 一次 count（用 unique 的索引）。
- 快照固定的是**連結的集合**與由它算出的數量（scan 數、各 run 的觀察數、scan_severity、first／last）；scan 與 run 的狀態、明細頂層的 finding 欄位（`normalized_severity`、`last_seen_*` 等）是讀取時的現值，不凍結。不持有跨 HTTP 請求的 transaction 或 exported snapshot。`page` 上限 10,000：一個快照最多可讀到約一百萬個連結（limit 100），上限與保存期限在 T23 決定。
- 不採用：持久化的快照表（可凍結狀態，但要 TTL、清理與配額，單人的 M4 不需要）；HMAC 的 token（as_of 只是比較值，不是授權憑證：每個請求都重新檢查權限，as_of 大於目前的連結數回 422，而且這個檢查在權限之後）。

### 26.5 跨表的 target 一致性（v0015）
- 連結的 trigger 同時檢查觀察所屬 scan 的 target 等於 finding 的 target；`findings_guard` 改版：連結數只能增加；first／last seen 的 scan 必須屬於 finding 的 target（INSERT 與 last seen 改變時檢查；找不到 scan 時交給 FK）。只用不加鎖的 SELECT，被讀的 `scans.target_id`、`observations.scan_id` 都不可修改（`scans_guard`、append-only）。
- 升級先鎖住兩張表（`SHARE ROW EXCLUSIVE`）再核對既有資料：有跨 target 的連結或 first／last seen 就**失敗**（fail closed，由人處理），不靜默排除；核對以 SQL 的 DO 區塊執行，離線模式（`alembic --sql`）也會產生。回填序號時在同一個 transaction 內暫停兩張表的不可變 trigger。升級前先停 worker；降級只用於開發與測試。
- 既有測試中有兩個 API 測試以不同 target 的 scan 連結同一個 finding（不符合真實流程），改成同一個 target 的依序 scan。

### 26.6 觀察必須引用報告
- 計畫原本要加 `CHECK (report_artifact_id IS NOT NULL) NOT VALID`；未採用：無法證明引用的是正確的報告（kind、path），而且歷史資料可能是 null。改在寫入端強制：`RunRecords.record_results` 有觀察、manifest 卻沒有這個 run 的報告 artifact 時拋 `MissingReportError`，整筆不寫入（同一個 transaction 回滾，worker 之後重試、重試耗盡就失敗）。ZAP 與 Nuclei 的 worker 一向傳入固定的報告路徑，觀察本來就只來自 manifest 列出的報告。
- 更早的觀察若沒有引用報告，追溯 API 回 `artifact: null`（LEFT JOIN，不丟掉這一列、不補造）。

### 26.7 追溯 API（`API_CONTRACT.md` §17.10）
- `GET /findings/{id}`：§17.9 的 finding 欄位，加上 fingerprint、建立時的 taxonomy_sha256、`observations_as_of`、`seen`（快照中的 scan 數、觀察數、first／last 的 scan 與 run）、`engines`（依引擎分組）與 `recent_scans`（最多 5 次）。**回應有上限**：計畫原本的 sources 全部彙總、tool_cwe_ids 與跨 scan 的 related 會隨資料成長，移出明細（scan 層級的 sources 與 related 仍在 `GET /scans/{id}/findings`；related 的語意維持同一次 scan、同一個位置）。
- `GET /findings/{id}/scans`：由舊到新的完整歷史；每個 scan 列出所有 run（含失敗、沒有觀察的引擎），部分失敗在這裡看得到。
- `GET /findings/{id}/observations`：依序號排序；`link`（連結當時的正規化值、needs_review、taxonomy_sha256：append-only，不以目前的 taxonomy 重算——taxonomy_sha256 說明當時的版本，但完整的歷史 taxonomy 內容要由 Git 歷史還原，資料庫只存雜湊）、遮罩後的觀察（同 `GET /scans/{id}/observations`）、artifact 的 metadata（不含 storage_key 與內容）、run（映像、plan_hash、profile 定義、工具與 parser 的版本、時間）。
- 授權：先取 finding，再以它的 target `TargetService.get`（`PROJECT_READ`）檢查；其他 project 與不存在的一樣 404；每個請求都重新檢查。查詢都限定在快照的連結上，每頁的 SQL 數固定（整合測試以 SQLAlchemy 的事件計數）。
- 程式：`findings/domain/provenance.py`（frozen dataclass）、`findings/provenance.py`（查詢）、`findings/provenance_schemas.py`、`FindingService.detail／scans／observations`（repository 回傳 frozen 的 `FindingHead`，service 不讀 ORM model）；`core` 加上 `SnapshotPageMeta`、`SnapshotEnvelope` 與 `ok_snapshot_page`（其他清單的 meta 不變）；`scans.repository.observation_of`、`findings.repository.finding_of` 公開給追溯共用。

### 26.8 部分失敗的 live 情境（M4 的里程碑證據）
- 情境：同一個 fixture app 弱點版、同一個 scan 跑 ZAP＋Nuclei，`budget.max_duration_seconds` 取小值。ZAP 的 plan 是剩下的時間減去保留的 60 秒（`RESERVED_SECONDS`），所以 ZAP 會在自己的時間上限停止；剩下的時間不夠 nuclei 的最小時間窗（60 秒）時，runner 不建立容器、不送流量，nuclei 以 `BUDGET_EXHAUSTED` 結束。
- **狀態的語意**：依 §13.4 的 `aggregate`，任何掃描引擎 `timed_out` 時 scan 是 `timed_out`（不是 `partially_completed`）；`partially_completed` 是「有引擎成功、其他失敗」。這個情境在 API 中呈現為 `timed_out`＋`results_complete=false`：功能上是部分失敗（ZAP 有結果、nuclei 沒有執行），沒有被判成成功。`partially_completed`（ZAP 成功、nuclei 失敗）由整合測試以真的佇列涵蓋；要在 live 中穩定得到它，需要 ZAP 剛好在時間上限之前自然結束、同時剩下的時間又不夠 nuclei，時間窗太窄、不可重現，所以不做。
- **校準**（先量測再定斷言；2026-11-04，預算 240 秒，`ENABLE_LIVE_LAB_TESTS=1 make test-live-fixture-findings LIVE_PYTEST_ARGS="-s -k partial"`，3 次）：

  | 次 | scan | ZAP | ZAP 的觀察 | nuclei | 流量秒數（guard） | 轉送／拒絕 | 殘留 |
  |---|---|---|---|---|---|---|---|
  | 1 | timed_out | timed_out、ENGINE_TIMEOUT、time_limit_reached、exit 2 | 22 | failed、BUDGET_EXHAUSTED、沒有 plan | 194 | 343／10 | 無 |
  | 2 | timed_out | 同上 | 22 | 同上 | 194 | 342／10 | 無 |
  | 3 | timed_out | 同上 | 22 | 同上 | 193 | 345／10 | 無 |

  三次的狀態與錯誤碼相同，所以斷言寫死：scan `timed_out`、`results_complete=false`；ZAP `timed_out`／`ENGINE_TIMEOUT`／`time_limit_reached`；nuclei `failed`／`BUDGET_EXHAUSTED`、沒有 plan_hash、沒有容器、沒有觀察；流量秒數不超過預算。觀察數只要求大於 0（ZAP 的行為不保證每次相同的數量）。
- 已取得的資料不遺失：ZAP 的每個觀察都恰好連結一次，追溯到報告 artifact（sha256 與大小等於 runs volume 的檔案）與 run（plan_hash、映像、版本）；歷史列出 nuclei `failed`、0 個觀察。重試不重複：live 沒辦法強制中斷重試，由整合測試涵蓋（連結之後中斷、重試只補上沒連結的觀察，追溯中每個觀察只出現一次）。
- 錄製：`recordings/fixture-findings/fixture-findings-partial/provenance.json`（預算、scan、引擎狀態與每個 finding 的明細、歷史與觀察頁；gitignore）。

### 26.9 驗證
- 離線：`make test`（全部通過，整體 coverage 99.7%；`findings` 的 domain、`provenance`、`service`、v0015 都是 100%）、`make lint`、`make typecheck`、`make test-contract`、`make owasp-top10-check`、`pre-commit run --all-files`。實際的數字見 `TASKS.md` T20 的交付。
- RED：DEDUP-08、18、同一個 run 的拆分與不變式的性質測試在舊的 linking 下失敗，改了之後通過（以 `git stash` 暫時還原 linking 驗證）。
- live：`make test-live-fixture-findings`（2026-11-04，3 passed、21 分 59 秒，跑完沒有殘留的容器與網路）：弱點版 34 個觀察 → 30 個 finding（和 T19 相同：沒有規格，v2 不改變分群），每個觀察都追到報告 artifact 與 run，POST /login 的 SQLi 是 username、password 兩個 finding；修補版 10 → 10；部分失敗和 §26.8 的校準相同（scan timed_out，ZAP 22 個觀察、196 秒，nuclei BUDGET_EXHAUSTED）。細節見 `TASKS.md` T20。

### 26.10 限制
- query 中的物件（`/doc?id=1` 與 `?id=2`）與 action／type 類的語意 query 不在身分中，fallback 也一樣（沒有真實輸出支持規則）；審查過的 endpoint 粒度群組在樣板 route 下跨物件合併（例如 `zap-private-ip-disclosure` 在不同物件洩漏不同位址時，`TOOLS.md` §8.7）；同一個 role label 的不同 auth profile 合併。T21 的 triage 要注意：標記一個 finding 會涵蓋它所有的物件與觀察，報告要揭露 finding 內不同 path 的數量。
- fingerprint v2：v1 的 finding 保留為 open，同一個問題可能有 v1、v2 兩個 finding；T22 比較時 fingerprint 或 mapping 的版本不同要判成 `inconclusive`，不能判成 `not_observed`。
- 讀取成本：明細與每一頁都依快照重新彙總（count、group by），成本隨連結數線性增加；專案目前沒有 API 的 rate limit。finding 的數量、連結的保存期限與彙總表在 T23 決定。
- `MissingReportError` 走 worker 一般的重試（lease 過期之後重試、重試耗盡就是 `PARSE_ATTEMPTS_EXHAUSTED`）：它是平台不變式的違反（正常流程不會發生），不是工具或驗證的失敗；不另外定義錯誤碼。
- 不另外做匿名／認證身分的 live 掃描（使用者決定）：身分的反例在 unit 與 T19 的整合測試（guard 的真實計數）。

### 26.11 審查（2026-11-04）
- architect（設計階段）：指出計畫的 offset 分頁論證不成立 → 改成序號＋高水位的快照（§26.4）；明細的無上限欄位、nullable 的 artifact／plan_hash、`timed_out` 與 `partially_completed` 的差異都依建議處理。
- security-reviewer：0 CRITICAL、0 HIGH、1 MEDIUM、9 LOW。已修：MEDIUM（逐列更新同一個 finding 的二次方成本 → 每個 finding 一次保留，實測見 §26.4）；L1（直接改計數 → commit 時核對）、L4（SEC-16 的測試加上 as_of、scan_id、engine，確認在權限之後才檢查）、L8（不存在的量測引用 → 補上實測）、L9（升級前鎖表、先停 worker）、L2（storage_key 不是秘密，記入 `API_CONTRACT.md` §17.10 與 T21 的交接）。記入限制：L3、L5、L6、L7（§26.10）。
- code-reviewer：0 CRITICAL、0 HIGH、3 MEDIUM、6 LOW（APPROVE）。已修：M1（N+1 的測試改成比較 1 筆與 100 筆的頁並加上上限，明細與歷史也量）、M2（repository 回傳 frozen 的 `FindingHead`）、M3（同 security 的 MEDIUM）；L1、L2（舊 as_of 的明細、近期 5 次的上限、移除恆真的斷言）、L3（不變式加上 v2 的規則、性質測試涵蓋 fallback 與規格；live 斷言真實的 POST /login 反例）、L4、L5（文件）、L6 的型別收窄。`finding_fields` 以 dict 交給 `model_validate`（執行期才檢查欄位名稱）維持：清單與明細共用，欄位由 schema 的測試釘住。

## 來源

`[Sxx]` 對照見 `docs/SOURCES.md`。

## 27. T22：以覆蓋證據進行保守複掃比較（2026-11-04；完成 2026-11-07）

### 27.1 範圍與待驗證事項

核准的 M5 順序是 T22 → T21 → T31 → T23a–T23d。T21 的生命週期驗證依賴比較證據，T31 的複掃指標也依賴 T22，因此先處理複掃；T23 分成資料保護、API／部署、最終測試與乾淨重建，避免單一驗收項目跨太多界線。T21、T31 與 T23 各項開始前仍須細化並請使用者確認。

T22 先於 T21 實作：比較以同一 target 的不可變 scan 為基礎；`not_observed` 不等於已修補。缺少位置、身分、規則或版本的可比證據時不得推論已修補。逐位置摘要不得保存參數值、憑證或完整請求。

離線以鎖定的 Nuclei v3.11.1 映像（`--network=none`、`--pull=never`）檢查 `nuclei -h`：存在 `-ms`、`-tlog` 和 `-omit-raw`。初始需實測 `-ms` 的模板／位置事件、ZAP 歸屬、passive 完成與固定 target 換版；結果見 §27.5–§27.7，未取得逐規則完整性的證明。規則產生過一次請求不代表該規則對該位置與參數的完整檢測已完成，現行實作採 `inconclusive` 退路（§27.9），不是將初始假設當事實。

### 27.2 初步安全限制（後續定案見 §27.8–§27.9）

- 僅靠參數名稱的字元或長度限制，不能保證名稱中沒有 token 等敏感值；在確定可信來源或不可逆比對方式前，不從實際請求擷取名稱，也不宣稱此部分已完成。
- 現有 operation coverage 容許 summary 比請求明細多一筆，且原本配對邏輯沒有檢查 request 序號唯一。T22 不可直接以該完整性條件證明負面比較；必須另外驗證數量與配對，並對缺失採保守判斷。
- 覆蓋欄位受 2048 bytes 行長限制；實際擷取接線時須依編碼後的 byte budget 截斷並保留不完整狀態，不可假裝完整。

### 27.3 測試中的 ZAP 設定

開發分支先啟用 `injectPluginIdInHeader`，guard 在轉送之前移除該 header 並記錄單一合格數字 ID；任何歸屬都仍只是未驗證的請求訊號。passive 設定的 `maxAlertsPerRule` 和 `maxBodySizeInBytesToScan` 暫以 0 寫明不限。這三項一併納入 ZAP profile definition hash，避免新舊設定共用雜湊。S1／S3 的鎖定映像實測見 §27.5；訊號存在仍不代表規則或被動掃描對位置／參數的完整性。

### 27.4 Nuclei 失敗事件的防誤判準備

鎖定版原始碼的 `WriteFailure` 會寫出 `matcher-status: false`，而且可能帶有 `error`；這種事件不等於成功完成檢測。parser 版本改為 `nuclei-jsonl/2`；初版先要求 false 事件符合原有 finding 格式，S2 後依實際 failure 事件形狀調整為 §27.7 的只讀記憶體結構。非布林狀態與不符各自格式的事件仍拒絕，false 不產生 observation；所有事件都計入數量上限。開發分支已加入 `-ms`，定義雜湊由 T17 的 `504ac80c34da54738903d4937d770cc618d4514f53b2d05cd7ed1579ac061469` 變為 `53eb59977f128f38e8771fa0f686f6c08828a75a138af0fe5a92639c48919fc5`；manifest 保留 T17 原值，另記開發分支的當前值，不變更既有 golden。真實輸出形狀見 §27.7 的 S2 實測；沒有取得完成證據，不以 false 事件判 `not_observed`。

### 27.5 S1／S3 的首次 fixture 實測（2026-11-04）

使用獨立 live 專案、隔離 fixture 弱點版的 web scan；`test_fixture_zap_live.py::TestFixtureVulnerable::test_web_scan_finds_query_injection` 通過（1 passed，3 deselected，1 warning；pytest 404.08 秒，scan 自身約 384 秒）。此次 guard telemetry 有 700 個 request，其中 690 筆帶歸屬、10 筆未歸屬；出現 29 個不同的 ID，全部在該 profile 的 active 白名單內。`zap.log` 顯示被動設定兩個值為 0、`passiveScan-wait` started 並 finished（2 秒）。這些只確認訊號與作業日誌存在，**不證明規則對個別位置與參數已完整執行**，也未單憑 finished 證明每個 response 都完成所有被動規則。

和既有 T30 fixture 弱點版 web 錄製的單次結果相比，兩次各有 23 筆 observation、11 種 source rule；按規則、method 與 path 的計數有 2 個差異項。因此不能據此宣稱行為逐項一致或量測到穩定變異。錄製位於 gitignore 的 `recordings/t22-spike-20261104/`，尚須 S4 在 fixture 端確認內部 header 未送達，以及 S1 對照組、S2、S3 的完成性條件；未確認部分維持 inconclusive。

### 27.6 S4 同 target 換版與 header 去除（2026-11-04）

`test_fixture_rescan_live.py::test_fixture_switch_preserves_the_authorized_target` 在獨立 live 專案通過（1 passed，298.06 秒）。以同一 host、IP、port、target 與 grant，先掃弱點版再換為修補版：guard 分別轉送 228 與 233 次；fixture 的收包紀錄中都沒有 `X-ZAP-Scan-ID`。兩次 run 均因 180 秒總預算下的引擎時間上限而 `timed_out`，因此只證明這次換版後仍有受控流量、header 沒有送到 fixture，**不證明完整規則覆蓋，也不是複掃分類驗收**。測試結束後專用 live 容器與網路已清理。

### 27.7 S2 的 Nuclei matcher-status 實測（2026-11-04）

首次實測等待容器 300 秒後失敗，未取得輸出；離線 admission 測試隨後重現新 plan 因 runner 的固定參數白名單尚未加入 `-ms` 而遭拒。已在 runner **獨立核准序列**精確加入該旗標，測試確認缺旗標、移動位置及額外旗標仍被拒絕；首次 live 的實際終止狀態未被測試記錄，不能斷言其原因。測試改為從 scan event 取得 run ID、以終止狀態結束等待，之後重跑隔離 fixture 弱點版，1 passed（231.52 秒）。

第二次實測引擎回報 succeeded、輸出 919,391 bytes；共 51 筆事件：11 筆 `matcher-status=true`、40 筆 `false`。11 筆 true 有 template-id、matched-at；40 筆 false 都有 template-id 但沒有 matched-at，其中 1 筆有 error。測試以 template-id 和 matched-at 的原始組合數得 42，但 false 的 matched-at 是空值，**不能把這個數字當作 42 個有效位置或完整模板覆蓋**。這次沒有驗證每個模板對每個位置和參數都完成；error 事件也顯示整體 succeeded 不排除個別模板出錯。

parser 保留既有 `parse_report` 的 findings 契約，新增 `parse_report_with_executions`，把 false 事件提供為只存模板 ID、base URL、可選 matched-at 與是否有 error 的記憶體結構，不保存原始 error/request/response；這些 URL 是不可信資料且不寫進日誌。這只是事件訊號，尚未接到持久化或比較；沒有實證的規則完成性、位置與參數關聯時，一律 inconclusive。輸出大小僅代表這一次量測，不能推論其他目標或預算下必定小於上限。

S2 可透過既有隔離入口重現：`ENABLE_LIVE_LAB_TESTS=1 make test-live-runner LIVE_TESTS=tests/live/test_nuclei_matcher_spike_live.py LIVE_PYTEST_ARGS=-s`。沿用 live 的 LAB_ONLY、grant、internal network 與清理檢查；不與其他 live 指令並行。只輸出事件形狀與計數，不列印原始 error、請求或回應。這是訊號量測，不取代三次完整複掃校準。

### 27.8 比較證據的持久化基礎（開發中，2026-11-04）

- v0016 目前新增 run 的規則清單與 hash、連結時的 mapping 版本與 taxonomy hash、`locations_recorded`，以及 `run_locations`／`run_rule_locations`。既有 run 的新欄位保持未知，沒有從目前設定回填過去的執行結果。規則清單與 plan 一起寫入且不可後補；mapping 與位置標記只能寫一次；位置列不可更新、刪除或在標記完成後追加。升降級與 ORM drift 已有整合測試。v0016 也新增比較快照表：以複合外鍵約束兩次 scan 與 finding 屬於同一個 target，快照與明細在建立交易中封存，封存後不可修改或追加；未封存的快照不能提交。先後順序與 terminal 狀態在 service 驗證。比較 API 與事實建構已實作（§27.9–§27.10），完整 live 校準與最後審查仍未完成，**T22 尚未完成**。
- ZAP 凍結依 grant method 過濾的 active ID 與 `pscanrules` add-on 版本；Nuclei 凍結模板 ID，清單按字典序去重，hash 使用無空白的 ASCII JSON。這些只記錄允許的設定，**不是實際執行完成的證明**。
- worker 只有在 guard summary 的 scan 與 run 吻合、轉送數和明細數完全相等、序號與配對合格時，才可在連結 finding 的同一 transaction 保存摘要與 mapping；沒有觀察也保存 mapping。缺 summary、缺明細或不一致時不寫位置、`locations_recorded=false`。零流量但沒有明細檔亦維持未知。交易失敗時位置、mapping 和 finding 連結一併回滾。
- 不保存任何參數名稱或值，`parameters_unknown` 強制為 true；非歸屬請求不一定是 discovery，所以 `discovery_answered` 目前一律 false。初版以 `redact_url` 遮罩 path，但它無法辨識任意敏感值；因此改採 §27.9 的 path digest，不保存明文。仍先拒絕遮罩後會改變的 path，避免遮罩碰撞冒充精確位置。證據不足的來源不能據此判定 `not_observed`。

### 27.9 比較 API 的安全摘要與交易界線（實作中，2026-11-04）

- 調整 §27.8 的位置儲存：`redact_url` 不可能辨識任意 path 秘密，因此新位置表只保存 UTF-8 path 的 SHA-256，不保存原文字串。這是相等性索引，不是加密，也不能阻止對低熵 path 的猜測；一般 API 不輸出這些摘要。比較以既有遮罩 observation 的 path 計算摘要，逐一核對原 scan 觀察過的字面物件，不以同樣板另一物件代替；遮罩後對不上就視為沒有證據。舊 observation 與原始 artifact 的資料保護仍依既定 T23 工作，這次不宣稱一併完成。
- parser 的 observations/artifacts/outcome 維持既有的原子交易，位置摘要、link mapping 與 finding 連結則在下一個 fenced transaction 一起提交。這取代計畫中「和觀察同交易」的要求，避免把工具解析與連結重試綁成大型交易；run 在兩個交易都完成前仍是 normalizing。比較只接受終止 scan，未連結的觀察或缺 mapping 一律視為證據不完整，不把「沒有 finding 連結」當零告警。重試不覆寫既有版本或位置。
- S1–S3 沒有取得規則對位置及參數的完整執行證明，所以實際資料的 `rule_completed` 仍是 false。Nuclei false 事件不持久化 URL，也不升格為模板完成；ZAP header 與 passive job 完成同樣不能支持負面結論。保留三層缺口的布林摘要與來源識別，不記請求、token、參數名稱或值。這是核准的保守退路，不修改掃描範圍或放寬 guard。
- 比較快照使用同一請求交易、唯一 `(baseline, current, algorithm_version)` 與 `ON CONFLICT DO NOTHING`；只有建立者插入明細、寫 audit 並封存。重複請求讀同一快照；兩次 scan 皆先做 object-level 讀取授權，再檢查寫入角色，避免 viewer 透過錯誤差異辨識另一專案資源。封存後父子列不可改寫或追加；明細 trigger 連父列都不可見時也拒絕，不能先放行再依賴 FK。

### 27.10 API、版本身分與真實交易驗證（2026-11-04）

- 已建立 POST 與兩支 GET API（`API_CONTRACT.md` §17.11）；新建 201、重複 200、viewer 可讀但不能建立。兩個 scan 都先做讀取授權；任一無權或不存在回 404，之後才檢查寫入角色。比較不修改 triage/lifecycle，不把 new/not_observed 當成新增／已修補的人工確認。
- 引擎身分納入 engine、映像 tag+digest、工具版本、parser、profile definition、rule_set hash 與排序後 components。明確空 components 是已知無額外元件；缺少、格式錯誤或未 pin 的映像都不能形成可信定義。rule_set 必須排序去重並與 hash 相符。不得以目前映像、profile 或 taxonomy 回填舊 run。
- 同位置的重新識別納入 taxonomy 的 related 與 corroborated_by 成員原群組，雙向標示人工確認而不合併。只有兩個 scan 的 mapping/hash 皆與已載入分類表一致時使用這些關係；沒有舊分類表時，不拿新版關係推論舊 scan。使用位置＋群組索引與每 run 一次建立的回答位置集合，避免 N * M 配對與每 finding 重掃位置；回歸測試以操作次數驗證，不依賴耗時門檻。
- 兩個真實連線的交易測試已通過：唯一鍵競爭者確實等待鎖；先到者 commit 時讀同一份結果，rollback 時後到者接手，最終只有一份快照／明細與一筆 audit。audit 故障時 header 與明細整筆回滾。未封存真實 commit、不可見父列、兩側 scan／finding 複合 FK、UPDATE／DELETE／TRUNCATE／封存後追加都有反例；不是只在單一外層測試交易中模擬 commit。
- `run_locations` 的 INSERT guard 同樣立即拒絕不可見的父 run，不先放行再依賴 FK 等待；完成或已記錄覆蓋後不允許追加。v0016 downgrade 會刪除比較快照、位置摘要與新增 provenance，僅限已備份的開發／測試 DB，不是歷史證據保留方案。
- 已增加零觀察、未連結觀察、來源漏失、認證不健康、同樣板不同物件、規格未知／增減、篩選／分頁、client 偽造證據及輸入／證據超限的測試。100,000 個來源組合與每 finding 16 KiB 是拒絕整筆建立的邊界，不是悄悄截斷後回傳完整比較。
- 完整離線測試首次跑到 6,030 passed、4 failed（新增三支 API 尚未列入端點契約清單）；補齊清單後，該認證測試檔 50 passed。`make lint`、`make typecheck`、`make test-contract`（200 passed、1 skipped）、`make owasp-top10-check` 通過。完整重跑與 live 三次校準／最終驗證仍進行中，這些中途結果不是 T22 完成證明。

### 27.11 比較模組的補強測試（2026-11-04）

- 用真實 queue 的 prepare → record_plan → collect → worker claim → record_results → linker → terminal，分別驗證 ZAP 與 Nuclei 的凍結規則、映像、工具／parser／component 版本可以由比較 reader 原樣建立可比身分。測試的版本字串明確為 `test-*`，不冒充工具 live 量測。
- 補上任一側舊 mapping／taxonomy 不借用目前關係表的反例，以及 Hypothesis 的證據任意退化、可比版本的雙側觀察、單側分類必有理由等性質。
- 獨立 `COVERAGE_FILE=recordings/.coverage-comparisons` 的比較模組檢查：176 passed（53.36 秒）；774 statements 與 156 branches 中各缺 5，合計約 98.92%。核心 domain 的 classification、comparability、evaluation、provenance、reidentification 均為 line/branch 100%。未覆蓋是 reader/service 的不可能正常缺列與 repository 的防禦性分支，不以排除程式碼提高數字。這是比較模組量測，不代替整體或 live 驗收。

- 完整離線重跑已通過：`make test` 6,047 passed、2 skipped、77 deselected，coverage 99.63%，543.53 秒。這次收集早於後補的 9 個 property／完整來源讀回／舊 mapping 測試；它們已另在上述 176 個 focused 測試中通過，最後交付前仍須以同一最終工作樹重跑全部。
- 本輪當時的 `make lint` 與 `make typecheck` 通過（534 source files）；提交前 hooks 已檢查當時全部 tracked/untracked 檔。當時完整程式品質與安全審查、第一輪完整 live 校準尚在執行；後續結果、審查修正與仍未驗證的項目見 §27.12–§27.13。

### 27.12 審查後的認證 header 與 parser 修正（驗證中，2026-11-04）

- 安全審查重現自訂目標認證 header 與 `X-ZAP-Scan-ID` 衝突時，短數字 secret 可能被當成規則 ID 寫入 telemetry；這是合成憑證的離線重現，不表示已查證真實憑證外洩。guard policy 必須拒絕此衝突，包含舊磁碟 policy；新 profile、PATCH 後的版本、新 scan 綁定及 runner 啟動都應拒絕不可執行的設定。
- 初版直接加入 `Credential` 建構子的拒絕清單，相關離線測試 745 passed，但獨立複查發現會連歷史版本查詢、修復 PATCH 與金鑰換版一併阻斷。因此調整為「歷史中繼資料仍可表示、使用前明確驗證」：既有 profile 可讀、可透過合法 header 與新 secret 修復，密文 context 不變，金鑰換版不送出任何目標請求；不允許以原衝突設定建立新版本或開始掃描。這不是放寬出站規則。
- Nuclei 的 `interpret()` 原先只取 findings 而遺漏 false/error 事件，導致 exit 0 可能被誤報完整。修正讀完整解析結果，僅保存有界錯誤數；優先保留無流量／逾時等既有失敗語意，否則為 `failed/ENGINE_REPORTED_ERRORS`，正向 observations 保留，不保存原始 error。parser 升為 `nuclei-jsonl/3`，不能把 `/2` 的成功狀態當成修正後驗收。
- 比較摘要已納入 taxonomy hash：即使零 finding，hash 不同或未知仍標記 mapping 差異與人工確認。連結後、terminal 前遇到 mapping 換版的重試問題另已補整合回歸，但尚未取得實際 DB RED/GREEN，暫不宣稱修復。

### 27.13 第一輪校準與審查後離線結果（尚未完成 T22，2026-11-04）

第一輪完整校準 `calibration-1` 結束，pytest **1 passed，1897.94 秒**；沿用同一 target 的四次 scan，錄製在 `recordings/fixture-rescan/calibration-1/`。此輪使用安全修正前的版本，不能當作 `nuclei-jsonl/3` 或新認證限制的最終驗收：

| 比較 | comparability | persistent | inconclusive | new / not_observed / not_comparable | manual review |
|---|---|---:|---:|---|---|
| 弱點 → 弱點 | comparable | 29 | 2 | 0 / 0 / 0 | false |
| 弱點 → 修補 | comparable | 8 | 24 | 0 / 0 / 0 | false |
| 弱點 → 小預算 | different | 0 | 30 | 0 / 0 / 0 | true |

- 執行輸出確認專屬 live app 容器、DB volume 與 compose 網路完成清理；沒有操作其他專案容器。未啟動第二輪，須以修正後版本重新取得三次有效校準及最後完整驗證。
- 原修補斷言漏掉 CSP/XCTO 等已知修補案例。新增純函式 `tests/live/rescan_assertions.py`：全域安全 header／CORS 依 fixture 的 `_decorate` 實際作用範圍逐 finding 核對；SQLi、XSS、redirect 則以 method、route、參數位置與名稱對應。每個 baseline 已命中案例都必須是 `not_observed` 或 `inconclusive`，缺少比較明細也失敗。所有案例另列 `checked`／`baseline_not_observed`／`no_automatic_mapping`，未對應 finding 亦另列，不能把缺項當驗證通過。新增 33 個單元測試通過。
- 以新版斷言**離線讀取舊錄製**：6 個案例有對應（共 20 個 baseline findings），6 個案例沒有自動對應；另 10 個 finding 未對應。這不是重新 live，也不代表 inconclusive 已證明修補；沒有建立假的新校準紀錄或改寫原錄製。
- Header 初版 RED 為 10 failed、264 passed，涵蓋新設定、舊 policy、數字與非數字合成 secret，以及 runner 綁定。相容性修正另先重現舊中繼資料、修復與金鑰換版的失敗；測試替身一處錯誤已先修正再取得有效 RED。修正後認證／guard／綁定的 focused 檢查 917 passed；新增新 scan 拒絕與舊設定回歸亦通過。保留原有遮罩換行拒絕，不為相容而降低安全檢查。
- 最新不需 DB 的 `tests/unit tests/contract tests/api`：**4,604 passed、2 skipped，57.55 秒**。獨立 coverage 檔只量測此次指定核心，不是全專案 coverage：auth profile domain branch 118/118、comparison domain 97/98、guard 342/344、Nuclei results 79/86，皆高於 90%；四組合計 line 2675/2685、branch 636/646。未更改排除規則。新增 guard 測試的型別收斂之後，`make lint`（5 個 import contracts）、`make typecheck`（540 source files）、`make owasp-top10-check` 均通過。
- 新增 profile 真實 DB 查詢／版本歷史／換金鑰／修復、Nuclei error 持久化與 mapping 換版重試測試，僅確認相關檔 **75 tests collected**，不算測試通過。既有整合 fixture 會讀取 repo `.env`，目前未重新執行，以維持不讀該檔的限制；需要明確確認測試程序可自行載入（不顯示內容），或提供不依賴該檔的測試環境。沒有擷取秘密、改權限或讀取 `.env`。
- mapping 換版後「links 已提交、terminal 前中斷」的重試問題尚未修正；對應 6 個 DB 回歸仍待執行。先前 6,047 個完整測試通過是歷史結果，不能代表這些新增案例與目前工作樹已全綠。T22 保持未完成，不 commit／PR。
- 提交前檢查已對全部 tracked/untracked 工作檔重跑，排除 `.env` 類秘密檔（保留 `.env.example`）：格式、YAML/TOML、檔案大小、合併標記、private key／平台 API key、ruff、mypy、import-linter 均通過；`.env` 禁止提交 hook 因此次沒有匹配檔案而 skipped。沒有 stage、commit 或改動權限。
- 本次 code-reviewer 增量複查未發現確定缺陷。security-reviewer 對先前 HIGH #1 的唯讀複查也已完成：指定的認證用途驗證、歷史相容、runner 綁定及 guard 防護範圍內，沒有未解的 CRITICAL／HIGH。審查者未自行重跑測試、未使用 DB／Docker／live，亦未建置 guard 映像；修正仍須經真實 DB 與新版部署驗證。這些增量結論不取代 T22 最終完整審查。

### 27.14 剩餘修正與驗收（2026-11-05 – 2026-11-07）

- 使用者明確允許既有 make／pytest 測試程式依原機制載入 `.env`，解除 §27.13 的授權歧義；不得主動查看、搜尋、輸出或修改秘密。僅連 `cluster_name=secscan-test` 的 db-test 暫時 DB 與隔離 live Lab，不改測試環境設定、不碰開發／正式 DB 或其他專案資源。日誌只回報安全摘要；無法確認隔離或授權時停止 Live。
- 使用者選擇維持 Nuclei `/3` 的嚴格判定，不新增「成功但不完整」狀態。共用 live 檢查僅接受 Nuclei 的 `failed/ENGINE_REPORTED_ERRORS`、正整數 `engine_errors` 與不完整 scan；仍須符合原有來源、scope、流量及 ground truth 不變式，ZAP failed 不放寬。
- mapping 重試先以六個真實 DB 回歸取得 **4 failed、2 passed** 的 RED；不是環境錯誤。修正後先持有有效 lease 的 run 列鎖，再讀 frozen mapping 與未連結觀察。已凍結且沒有未連結觀察時回傳 0，保留舊 mapping、位置、連結與聚合；仍有未連結觀察且版本／hash 不同時拋 `MappingChangedError`。首次零觀察仍凍結證據，晚期連結失敗仍整筆回滾。
- 六個 linker／comparison DB 測試檔最終 **73 passed（47.77 秒）**；其中 fingerprint、mapping、taxonomy hash 三種換版，各驗證直接完成及新版本重試沿用舊證據。比較均要求人工確認、分類為 inconclusive，沒有 new／not_observed／persistent；不借用目前 taxonomy 重解釋舊 scan。重試測試拆到 `test_finding_linker_retry.py`，避免原測試檔超過上限。
- 認證與 Nuclei 三檔真實 DB 回歸 **50 passed（9.44 秒）**：歷史 profile 讀取／版本／換金鑰／修復、新 scan 拒絕、舊排隊快照在分配容器與交出 secret 前以 PLAN_REJECTED 拒絕，以及 Nuclei matcher error 入庫與不完整狀態。新增歷史佇列測試曾因測試建構誤讀 `Scope.budget` 失敗，改讀 grant 的 budget 後通過；未修改產品的安全判定。
- live 輔助函式 **63 passed**：所有比較（含未對應案例）禁止 new／not_observed，來源的 rule_completed 必須為 false；錄製 root 與檔案皆禁止覆寫，修補核對另存 ground-truth.json。新函式實作前為三個缺模組／缺匯入的 collection errors，不冒稱重現了舊 runtime 缺陷。
- `make lint` 通過（554 個格式檔、5 個 import contracts）；`make typecheck` 通過（547 source files）；`make test-contract` **200 passed、1 skipped**；`make owasp-top10-check` 逐位元組一致。這些日誌及認證／Nuclei DB 日誌的指定敏感樣式掃描沒有命中，不代表可證明任意秘密皆不存在。
- 本次完整 `make test` **6,173 passed、2 skipped、77 deselected（592.79 秒）**，整體 line＋branch coverage **99.6402%**。指定核心 branch：comparisons/domain **97/98（98.98%）**、guard **342/344（99.42%）**、auth_profiles/domain **118/118（100%）**、Nuclei results **79/86（91.86%）**、worker/locations **4/4（100%）**。沒有變更 coverage 排除規則；JSON 留在 gitignore 的 `recordings/t22-completion-20261105/coverage-pre-review.json`。
- 全部 tracked/untracked 工作檔的 pre-commit 通過；秘密設定檔不列入檢查輸入（僅允許 `.env.example`）。全量與 hook 日誌的指定敏感樣式均無命中。
- 完整靜態安全審查已完成，沒有確認的新增 CRITICAL／HIGH／MEDIUM／LOW 缺陷；涵蓋雙側物件授權、快照封存／交易、lease fencing、mapping 換版、三層 coverage、telemetry、parser 與保留 header 憑證邊界。審查者未自行執行 DB／Docker／Live，不將主線測試數或靜態結果當成安全證明。
- 完整 code review 在 API 逾時後從原進度完成，結論 APPROVE，沒有確認的新增 CRITICAL／HIGH／MEDIUM／LOW 缺陷；完整閱讀修改／新增來源與測試，另以無出網入口執行 **569 個離線測試通過（2.14 秒）**。沒有修改 production 或將核准限制當成完成證據；DB／Docker／Live 未由審查者重跑。
- 校準前凍結 311 個產品／部署／fixture 檔案，聚合 SHA-256 為 `23427ec43c8d57959111ba6ee024596a208f282db6c5b73bbc7e4a3f9532bddc`；manifest 在 gitignore 的 `recordings/t22-completion-20261105/live-production-freeze.json`。此時沒有其他 Live／掃描容器，專屬網路與 volume 不存在，8765／55434 可用；既有 db-test 保留。
- 第一輪 `post-fix-1` 的既有 `make test-live-fixture-rescan` 指令在執行前被工具權限檢查以 **Unverifiable Deletion Scope** 拒絕。既有 Live 入口的 cleanup 依兩個專屬網路列出容器後刪除，並拆除 compose volumes；本次未修改該流程、未繞過權限或改派代理。這是執行權限阻塞，不是 Live 測試失敗；修正後有效校準仍為 **0 次**。
- 拒絕後重新核對：`post-fix-1` 的目錄與日誌都不存在，沒有 Live／scan 容器、Live 網路或 Live volume；唯一既有容器仍是 `secscan-db-test-1`。311 個凍結檔案均未改變，因此沒有偽造本輪量測或未記錄的產品變更。
- 修正後三次有效 live 校準、固定斷言後最終執行與 M4 live 回歸仍未完成；在既有指令取得適當執行許可前停止 Live。T22 保持未勾選，尚未 commit／PR。
- 同日重新開始執行剩餘計畫，於 13:28 UTC 完成唯讀前置核對：311 個凍結檔案無缺漏、無變更；只有健康的 `secscan-db-test-1`，沒有 Live／掃描容器、Live 網路，以及 Live 名稱或 compose project label 的 volume。既有 269 個 volume 未讀內容、未清理，不能稱整台 Docker 沒有 volume。IPv4 的 8765／55434 沒有監聽程序；另有非本專案程序監聽 `[::1]:8765`，未停止或修改。
- 使用者設定的 `permissions.allow` 未找到三個限定 Live 指令；專案與專案本機設定檔不存在，亦未能確認 session 層的有效允許規則。依核准計畫停在權限前置，不自行新增規則、修改環境或改用其他執行方法。本次沒有送出 Live 指令，不能稱為新的工具拒絕或測試失敗；六個預定錄製目錄皆未建立。去識別化前置摘要保存在 `recordings/t22-completion-20261105/live-preflight-permissions-summary.json`；後續執行前須重新檢查，不沿用本次環境快照作永久保證。
- 13:3x UTC 重新核對前置條件（同上，皆成立）後，既有 `make test-live-fixture-nuclei` 通過權限並實際執行（錄製在新的 `recordings/fixture-nuclei/post-t22-1`）：**2 passed（446.39 秒）**，production 凍結的 311 檔前後不變。兩個 run 都是 `failed/ENGINE_REPORTED_ERRORS`：弱點版 `engine_errors=1`、轉送 312、觀察 11（`cors-misconfig` 1、`http-missing-security-headers` 10）；修補版 `engine_errors=2`、轉送 314、觀察 6（沒有 `cors-misconfig`）。兩者都沒有用盡預算、沒有超時。這是使用者選擇的嚴格判定下的條件式接受，不是「成功」；CORS 的正例與負例、plan_hash、定義、guard 只看到 target 等不變式都成立。pytest 另有 2 個既有的 class-scoped fixture 棄用警告，與本次修改無關。摘要在 `post-t22-nuclei-1-summary.json`，日誌與錄製的指定敏感樣式掃描沒有命中。
- 執行後檢查發現**殘留**：沒有 Live 容器、網路或 Live 名稱的 volume，但匿名 volume 從 269 個變成 271 個。新增的兩個建立時間（13:34:04Z、13:37:37Z）分別對上弱點版與修補版 fixture 的啟動；guard 映像宣告 `VOLUME /home/mitmproxy/.mitmproxy`，而 `start_fixture` 以 `docker run -d` 啟動、`docker rm -f`（沒有 `-v`）刪除，Docker 因此留下匿名 volume。既有 269 個也全是匿名 volume、建立於 10-28 之後，推測是過去 Live 以同樣方式累積，但未讀內容、無法逐一證明。依使用者條件立即停止後續 Live，**未刪除**任何 volume，交由使用者決定。
- 修正（只改測試輔助，不在 production 凍結清單內，不作廢校準）：`start_fixture` 和 compose 的 guard 一樣以 tmpfs 蓋住該路徑，讓 Docker 不建立匿名 volume，而不是擴大刪除範圍。先以單元測試取得 RED（fixture 容器沒有掛 tmpfs），修正後 Live 輔助的單元測試 **69 passed**、ruff 與 mypy 通過。tmpfs 是否真的阻止匿名 volume，要在下一次 Live 的執行後檢查以 volume 數不變實際驗證。
- 殘留處理（2026-11-06，使用者決定）：先確認兩個 volume 只有匿名標籤、沒有任何容器引用，再以精確名稱 `docker volume rm` 刪除這兩個（`8f435f65…`、`8e4cac7a…`）；匿名 volume 回到 269 個，只剩 `secscan-db-test-1` 在執行。這兩個 volume 沒有用途：fixture 只借用映像的 python，mitmproxy 沒有執行，guard 也以 tmpfs 蓋住該路徑。既有 269 個不處理（可能含其他專案的資料，不用 `volume prune`）。
- 修正後複掃校準 `post-fix-1`（2026-11-06）：**1 passed（1,888.26 秒）**，凍結 311 檔不變、日誌與錄製無敏感樣式、沒有殘留，匿名 volume 前後都是 269 個（tmpfs 修正實測有效）。baseline／control／secure 皆為 `partially_completed`：ZAP succeeded，Nuclei `failed/ENGINE_REPORTED_ERRORS`（engine_errors 1／1／2，條件式接受）；小預算 scan 為 `timed_out`（ZAP `ENGINE_TIMEOUT`、Nuclei `BUDGET_EXHAUSTED`）。比較：unchanged comparable／不需人工（persistent 29、inconclusive 2，理由 rule_incomplete）；patched comparable／不需人工（persistent 8、inconclusive 24，理由 rule_incomplete 24、parameter_unverified 7、engine_incomplete 5）；partial-comparison different／需人工（inconclusive 30；snapshot 理由是引擎定義、fingerprint 與 mapping 版本不一致或未知，逐 finding 理由是 fingerprint 與 mapping 版本不一致）。三組皆 new=0、not_observed=0、not_comparable=0，與修正前 calibration-1 相同。修補核對 12 案：6 checked（20 個 finding）、6 no_automatic_mapping。
- `post-fix-2`（2026-11-06）**無效，屬環境故障，不計次數**：baseline 完成後，control scan 進行中 Mac 於 21:30:44（+08:00）以電池闔蓋睡眠，OrbStack 停止回應；`docker ps`（等待 scan 容器）與 fixture 的 `docker rm -f` 各逾時 120 秒，1 failed。失敗發生在任何比較之前，沒有建立比較快照。02:33 接上電源喚醒後清理完成，沒有殘留、凍結檔案不變、無敏感樣式。證據為 `post-fix-2-env-failure.log` 與 `-summary.json`；確認隔離後以新目錄 `post-fix-2-rerun` 重跑。
- `post-fix-2-rerun`（2026-11-07，接 AC 電源，執行期間沒有睡眠）：**1 passed（1,900.72 秒）**，凍結 311 檔不變、無敏感樣式、沒有殘留，匿名 volume 維持 269 個。四個 scan 的狀態、錯誤碼與 engine_errors 與 `post-fix-1` 相同；unchanged 與 patched 的 comparability、manual_review 與各分類數量完全相同。partial-comparison 仍為 different／需人工、new=0、not_observed=0，inconclusive 為 31（`post-fix-1` 為 30）：小預算 scan 被截斷的位置每次不同，數量不寫死。修補核對同為 6 checked（20 個 finding）、6 no_automatic_mapping。
- `post-fix-3`（2026-11-07）：**1 passed（1,908.71 秒）**，凍結 311 檔不變、無敏感樣式、沒有殘留、匿名 volume 維持 269 個、執行期間沒有睡眠。四個 scan 與 unchanged、patched 兩組比較的結果與前兩輪完全相同；partial-comparison inconclusive 30。修正後的有效校準達 **3 次**（`post-fix-1`、`post-fix-2-rerun`、`post-fix-3`）。
- 固定斷言（只改測試，不作廢校準）：三次都相同的結構寫成 `CALIBRATED_STRUCTURE` 與 `assert_calibrated_structure`（`tests/live/rescan_assertions.py`），在每次比較時檢查——unchanged 與 patched 為 comparable、不需人工、snapshot 沒有理由；partial-comparison 為 different、需人工、snapshot 帶理由；三組 not_comparable 皆為 0；未校準的比較名稱一律失敗。各分類數量（persistent 29／8、inconclusive 2／24／30–31）與 Nuclei 的 engine_errors 只記錄範圍，不寫死。先以單元測試取得 RED（缺少函式），修正後 54 passed；以 calibration-1 與三次有效校準共 12 個實際比較快照離線重放，全數通過。`make lint`、`make typecheck`、pre-commit 通過。
- 固定斷言後的最終執行 `final`（2026-11-07）：**1 passed（1,893.36 秒）**，`assert_calibrated_structure` 在三組比較都成立；凍結 311 檔不變、無敏感樣式、沒有殘留、匿名 volume 維持 269 個、執行期間沒有睡眠。四個 scan 的狀態與三次校準相同；unchanged comparable（persistent 29、inconclusive 2）、patched comparable（persistent 8、inconclusive 24）、partial-comparison different／需人工（inconclusive 30）；三組 new=0、not_observed=0、not_comparable=0。修補核對 6 checked（20 個 finding）、6 no_automatic_mapping。
- 雙引擎 findings 的 M4 回歸（2026-11-07，錄製在新的 `recordings/fixture-findings/post-t22-1`）：**3 passed、3 warnings（1,321.62 秒）**；warnings 是既有的 `PytestRemovedIn10Warning`（class-scoped fixture 定義為 instance method）。弱點版 `partially_completed`：ZAP succeeded（觀察 23）、Nuclei `failed/ENGINE_REPORTED_ERRORS`（engine_errors 1，觀察 11），finding 30（security 22、informational 8）；修補版 `partially_completed`：ZAP 觀察 4、Nuclei engine_errors 2、觀察 6，finding 10；小預算 240 秒：scan `timed_out`、results_complete false，ZAP `ENGINE_TIMEOUT`（觀察 22、time_limit_reached true）、Nuclei `BUDGET_EXHAUSTED`（小預算的數字取自日誌的 `[量測]` 行；該 scan 的錄製依設計只保存 provenance.json）。每個觀察恰好連結一次、預算未用盡。凍結 311 檔不變、無敏感樣式、沒有殘留、匿名 volume 維持 269 個。`test-live-zap`、`test-live-lab` 未在 T22 重跑，留給 T23c 在最終版本執行。
- 增量審查後補上：`assert_calibrated_structure` 失敗時，訊息一併帶出 snapshot 的 reasons 與 counts（Live 結束會拆除 DB，偏離時仍能從日誌分析）；只改訊息、不改判斷，不重跑 Live。
- 交接給 T23c（不在 T22 範圍，未修改）：`tests/live/zap_support.py` 的 `start_site` 與 `tests/live/guard_support.py` 的 `start_receiver` 同樣以 `docker run -d` 跑 guard 映像、沒有 tmpfs，再以 `docker rm -f`（不帶 `-v`）刪除，會和本節的 fixture 一樣留下匿名 volume。`make test-live-zap`、`make record-fixtures`、`make test-live-runner` 會用到；T23c 重跑這些 Live 前應把 tmpfs 常數移到 `tests/live/support.py` 共用並補單元測試，否則會觸發「有殘留就停止」的條件。
- 限制：實際 producer 的 `rule_completed` 一律為 false，所以 Live 的單側 finding 都是 inconclusive；這一版不能計算「自動驗證修補成功率」，not_observed 只在離線 RESCAN 正反例中出現。Nuclei 在本 fixture 每次都有 1–2 個模板 error，依嚴格判定使 scan 成為 partially_completed。

## 28. T21：人工 triage、audit 與 JSON／Markdown 報告（2026-11-08 開始）

細部計畫經兩輪審查：第一版有一次獨立審查（Plan 子代理），使用者 2026-11-07 決定 resolved 採雙軌並附六項條件，2026-11-08 評估第一版後補上四點（§28.1、§28.2、§28.9、§28.10）。

### 28.1 resolved 一律是人工判定；T21 不提供自動修補驗證

- T22 的比較快照是平台事實，封存後不可修改；T21 的 triage 是人工判定。兩者分開保存、分開呈現：人工 resolve 之後，比較快照那一列仍是原本的分類（例如 inconclusive）。
- 程式中沒有任何路徑會自動設定 resolved；DB 要求每次 triage 或 lifecycle 變更都有一筆事件與 actor。not_observed 與 inconclusive 都不會自動變成 resolved。
- 雙軌（使用者 2026-11-07）：PATCH 明確寫出 `basis`，平台只檢查該依據的條件是否成立：
  - `rescan_not_observed`：比較中該列是 not_observed（三層覆蓋都成立）。**現行版本不可用**：algorithm v1 的 producer 一律給 `rule_completed=false`，不會產生 not_observed；送出時以 `not_observed_required` 拒絕。規則仍實作，並以構造的封存快照測試（走正常的 trigger）。
  - `manual_retest`：該列是 inconclusive，平台證據都成立，未完成的只有 `rule_incomplete`／`parameter_unverified`，另附結構化的人工複測證據（`attestation`）。這是目前唯一可用、Live 能驗證的一軌。
- 共同條件：同一個 target、已封存、algorithm 版本受支援、整體 comparability 是 comparable、該列不需要人工確認、finding 已是 confirmed、target 沒有進行中的 scan、比較的 current 之後沒有再觀察到這個 finding（`observed_after_comparison`）。版本不相容、需要人工確認、引擎失敗或逾時一律拒絕。比較標頭的 `manual_review_required` 會彙總其他 finding，不拿來判斷這個 finding。
- 文件、API 說明、報告、PR 與完成回報都不寫成「平台能驗證修復」。

### 28.2 人工複測證據是操作者聲明，不是不可偽造的證據

- request 欄位名稱是 `attestation`（不是 verification）。平台做的是**一致性檢查**：請求摘錄第一行是 finding 的 method 與 route（字面或 OpenAPI 樣板）、`Host` 等於 target、有參數時摘錄出現參數名稱、回應摘錄第一行是 HTTP 狀態列、身分相同、時間不晚於現在且不早於最後一次觀察到它的 scan 結束時間、結果是 `not_reproduced`、大小有上限。
- 這些檢查擋不住偽造：複測不經過平台與 guard，平台不代為重送請求、沒有流量紀錄可比對。因此改以問責：不可修改的事件記下 actor key、request_id、DB 時間、依據、檢查清單與兩段摘錄的 sha256；audit 的 `finding.triage` 記下 `evidence_provenance=operator_supplied`、檢查範圍與雜湊。不做雙人覆核（單人專題），列為限制。
- client 不能填寫 `provenance`、`platform_checks` 等平台欄位（多餘欄位回 422）。

### 28.3 自動重開（R1–R4）與為什麼不鎖 target

- linker 寫連結的同一個 transaction 中，四項都成立才重開：R1 finding 是 resolved；R2 有觀察連結到同一個 fingerprint；R3 這個 run 的 scan `queue_position` 大於 `resolved_scan_position`；R4 run 凍結的 (mapping_version, taxonomy_sha256) 等於 finding 的。failed／timed_out run 的陽性觀察也算有效再現。
- 轉成 resolved 時，DB trigger 以**單一查詢**取得 target 所有 scan 的最大 `queue_position` 並確認沒有進行中的 scan；新的 scan 必須先取得 target 的 FOR NO KEY UPDATE 鎖才寫入、identity 的 cache 是 1，所以查詢看不到的 scan 位置一定比 watermark 大。不以 FOR SHARE 鎖 target：持續的 FOR SHARE 會餓死停用、撤銷這類 FOR UPDATE（§13.5）。
- R4 不成立時不重開（使用者決定），改以衍生的 `resolution_review_required` 標示（resolve 之後又被觀察到但 mapping 不同，或 target 之後有 scan 用了不同的 mapping）；報告不把它算成已修補。
- 事件以複合 FK 引用 scanner_runs(id, scan_id)，不直接引用 scans（linker 持有 run 鎖時對 scans 取 KEY SHARE 會和對帳的 scan → run 形成死鎖，同 §25.8）。

### 28.4 樂觀鎖、悲觀鎖與 lock_findings 的修正

- `expected_version` 必填，和 `triage_version` 不符回 409 `VERSION_CONFLICT`；PATCH 以 FOR NO KEY UPDATE 鎖 finding。
- linker 的 `lock_findings` 由 FOR UPDATE 改成 FOR NO KEY UPDATE：建立比較快照時 FK 檢查會依 UUID 順序對 findings 取 KEY SHARE，FOR UPDATE 與 KEY SHARE 互斥，既有程式就可能死鎖。
- 事件表 append-only（`scan_records_guard`）；事件鏈由 BEFORE INSERT 檢查（sequence 等於 finding 目前的版本、previous 等於上一筆的新值、新值等於 finding 目前的狀態），所以先 UPDATE finding、再 INSERT 事件；deferred constraint trigger 在 commit 時確認每次升版都有事件。

### 28.5 報告

- worker 佇列（`reports`，SKIP LOCKED、lease 30 秒、最多 3 次），內容存 DB（`report_contents`，≤ 8 MiB，超過以整個 finding 為單位截斷並標示）。POST 回 202、`Idempotency-Key` 必填、scan 必須已終止。
- 在一個 REPEATABLE READ READ ONLY transaction 中讀快照；以明確的投影組成白名單欄位，Pydantic `extra="forbid"` 與 golden JSON Schema 檢查。三層遮罩與 canary。Markdown 的不可信字串只放在 code span（換行等換成可見符號）或最上層的 fenced block；JSON 跳脫 `< > &` 與 U+2028／U+2029。
- 完成時以 fenced transaction（鎖住仍持有 lease 的 generating 列）寫內容並轉成 succeeded；deferred 檢查雙向核對內容與狀態、sha256 與大小。
- 只能下載平台產生的報告（以 report id 授權）；契約中的 artifact 下載移除，工具輸出只提供 metadata。

### 28.6 契約修正（端點都還沒實作，不影響既有 client）

- 報告的 POST 由 201 改成 202；移除 `/artifacts/{id}/download`；報告要求 scan 已終止。
- triage 的 request 改用 `basis`、`comparison_id`、`attestation`、`observation_ids`、`expected_version`，取代 `evidence_artifact_ids`。

### 28.7 交接的管理項目

- 全域 audit 查詢（platform_admin，加在 projects 的 router）、全域待核准清單（platform_admin）、停用 auth profile（終止狀態；清除目前密文；新的 scan 回 409；排隊中的 scan 與執行中 scan 之後才準備的 run 在交出 secret 前失敗；已啟動的 run 不受影響）。
- 不做：封存舊版 auth profile、刪除或封存規格（報告引用版本）、刪除報告（T23a）、上傳證據檔案、target 層級的 finding 清單、下載報告的 audit。

### 28.8 限制

- DB 角色仍能 `DISABLE TRIGGER`（DDL／DML 分權在 T23b）；不做 hash chain。
- fixture 上的 Nuclei 每次都是 `ENGINE_REPORTED_ERRORS`：帶 Nuclei 來源的 finding 會有 `engine_incomplete`，兩軌都無法 resolve。
- taxonomy 或 fingerprint 換版之後，T22 一律把舊 finding 判成 inconclusive，所以舊 finding 也無法再以證據 resolve。
- 「人工判定」指以 operator/admin key 送出的 PATCH。平台分不出送出者是人或自動化的 client（Live 中的操作者就是測試本身），問責的對象是 key 與它的持有者；事件與 audit 記下 key、request_id 與 DB 時間。

### 28.9 資料保護現況（T21 完成也不代表完成）

- 人工複測摘錄另存 `finding_triage_excerpts`，事件只存雜湊與長度：T23a 加上加密與到期清除時只改這張表，事件與雜湊不變。摘錄內容只給 operator/admin（人工摘錄只能做樣式遮罩；觀察有 runner 以已知 secret 值精確遮罩）。
- 報告內容與摘錄在 DB 中沒有加密、沒有保留期限（T23a）；runs volume 的原始輸出未加密（T23a）；DDL／DML 分權（T23b）。SEC-14 不標完成。

### 28.10 必要驗收閘門

- G1 併發、G2 交易一致性（故障注入）、G3 DB 層強制、G4 安全反例、G5 審查（code-reviewer、security-reviewer、database-reviewer）、G6 Live、G7 宣稱範圍；coverage 不能替代。G1、G2 的測試在每個階段閘門與最後各連續執行 5 次。

### 28.11 階段 A 的資料庫審查（database-reviewer，opus，2026-11-08）

- 結果：0 CRITICAL、0 HIGH、2 MEDIUM、6 LOW；設計宣稱 1–4 成立。全部採用：
  - M1：`attestation_valid` 在 attestation 缺少 provenance 或不是 object 時，因 NULL 三值邏輯會通過 → 改成 `COALESCE(jsonb_typeof(...) = 'object' AND ... = 'operator_supplied', false)`，並補 `{}`、`null`、`"x"` 的反例。
  - M2：有 resolved finding 時 downgrade 違反 `resolution_watermark` → 重設 lifecycle 的同一個 UPDATE 一併清除 watermark 與版本；補「有資料時 downgrade 成功」的測試。
  - L1：進行中的狀態改成「不在終止清單中」，未知的新狀態視為忙碌。
  - L2：chain trigger 檢查系統事件引用的 scan 屬於 finding 的 target。
  - L3：resolve 事件以 FK `(comparison_id, finding_id)` 引用比較快照中這個 finding 的那一列。
  - L4：reason 遮罩後再檢查長度，超過回 422（原本會在 INSERT 時變成 500）。
  - L5：PATCH 以 FOR SHARE 鎖住呼叫者的 key 並重新確認沒有被撤銷（比照 runner）。
  - L6：upgrade 一開始就取 ACCESS EXCLUSIVE；事件表的三組 FK 加上索引。
- R3 依賴三個沒有寫在 DB、由程式維持的不變量（審查建議明列）：
  - (a) 所有寫入 scans 的路徑都在 INSERT 之前取得 target 的列鎖（identity 在 BEFORE trigger 之前就配出，不能靠 trigger 補鎖）。
  - (b) 不會有把觀察連結到已終止 scan 的工具（backfill、relink）；有的話 R3 永遠不成立、靜默地不重開。
  - (c) PATCH 在證據檢查之前就鎖住 finding；這段期間 linker 不能寫入這個 finding 的連結。把鎖移到證據檢查之後會讓 `observed_after_comparison` 與 trigger 之間出現競態。

### 28.12 階段 B、C 的資料庫審查（database-reviewer，opus，2026-11-08）

- 結果：0 CRITICAL、1 HIGH（審查途中已修正）、2 MEDIUM、8 LOW；佇列 fencing、無死結、配額無競態、attempts ≤ 3、停用之後不交出 secret 等宣稱成立。全部採用：
  - H1：v0019 第一版在共用的 `auth_profiles_guard` 中引用 `OLD.disabled_at`，這個函式也掛在 `auth_profile_versions` 的 TRUNCATE 上（PL/pgSQL 依 trigger 所屬資料表解析欄位），TRUNCATE 變成 42703 → 改成新的 `auth_profiles_update_guard` 只掛在 auth_profiles 的 UPDATE；`auth_profiles_guard` 維持 v0004 的內容（L7 一併處理）。
  - M1：`failed_shape` 在 error_code 是 NULL 時因三值邏輯通過 → 明確要求 `IS NOT NULL`；`result_valid` 註明依賴各狀態的 shape。
  - M2：原本 DB 只核對「內容與狀態一致」，文件卻宣稱繞過 fencing 也提交不了 → 加上 DB 層的 fencing token：`report_contents` 帶著 `attempt` 與 `lease_owner`，insert guard 要求等於父列目前的值、而且 lease 未過期；心跳不能換 owner；deferred 核對也比對 attempt。程式的 `_holds` 一併比對 attempt。
  - L1：`queued_shape` 要求 `attempts < 3`，claim 也只認領 `attempts < MAX_ATTEMPTS`。
  - L2：密文查不到時再查一次是否已停用，錯誤碼分清楚 `AUTH_PROFILE_DISABLED` 與 `AUTH_PROFILE_SUPERSEDED`。
  - L3：「執行中的 scan 不受影響」改成「已啟動的 run 不受影響；同一個 scan 之後準備的 run 在交出 secret 前失敗」。
  - L4：已停用的 profile 不能新增版本；deferred 檢查停用時不能留下任何密文。
  - L5：worker 的 limit 以嘗試的份數計；非連線類的失敗（含這份報告專屬的 DB 錯誤：違反 CHECK、核對失敗、查詢逾時）立即以 fenced transaction 釋放這一次嘗試（退回 queued，用盡時 `REPORT_GENERATION_FAILED`），不白佔 30 秒的配額。
  - L6：讀完快照、渲染之前再心跳一次；長時間的 REPEATABLE READ 會延後 vacuum（每份報告一次，20,000 個 finding 的渲染約 4–6 秒），記為已知代價。
  - L8：`reports.requested_by_key_id`、`auth_profiles.disabled_by_key_id` 加索引；v0019 的 docstring 註明先停 api 與 worker。
- 量測（純函式，合成資料）：20,000 個 finding 的渲染 JSON 3.8 秒、Markdown 6.3 秒（都在 8 MiB 處截斷），遠低於 30 秒的 lease。DB 快照的讀取以每頁 100 個 finding、固定的查詢數分頁，每頁之間心跳。

### 28.13 整體的程式碼審查（G5：code-reviewer，opus，2026-11-08）

- 結果：0 CRITICAL、0 HIGH、5 MEDIUM、5 LOW，結論 APPROVE。全部採用：
  - M1：報告摘要的 `by_lifecycle` 把需要人工確認的 resolved 算進 resolved → 另列 `resolved_review_required` 一桶；依證據性質的兩個計數也不含它們，兩者相加等於 resolved 那一桶（測試斷言這個不變式）。
  - M2：Live 的反例沿用第一個案例的聲明，可能因為 route 或身分不符被拒絕，沒有鑑別力 → 每個反例的聲明都對準該 finding 自己的 method、route、參數與身分；拒絕原因必須包含平台條件算出的每個代碼，而且不含 `request_line_mismatch`、`host_mismatch`、`parameter_missing`、`role_mismatch`；缺少摘錄的反例斷言 `INVALID_REQUEST` 並指出 `response_excerpt`。不符資格的案例也斷言原因代碼。
  - M3：報告的比較快照原本取最舊的 10 份且沒有揭露省略 → 改取最新的 10 份，省略的份數記在 `truncation.comparisons_omitted`，Markdown 印出說明。**`ReportDocumentV1` 因此改變**：逐項比對確認 golden JSON Schema 的差異只有 `TruncationDoc` 新增的這個欄位（properties 與 required），依原本的格式重新產生；這是經審查的刻意變更，不是為了通過測試。
  - M4：worker 的失敗分支與 `WorkerLoop(reports=…)` 沒有測試 → 新增 `tests/integration/test_report_worker.py`：IntegrityError 與 57014 立即釋放、其他 DB 錯誤讓程序結束（報告留在 generating）、lease 已失效不算完成、WorkerLoop 每圈處理一份報告且有產生時不睡。等鎖逾時（55P03）維持「其他 DB 錯誤」：完成時的 `FOR UPDATE` 只會和對帳、心跳這類短 transaction 競爭，逾時代表 DB 層的問題，讓程序結束、由 lease 到期後的對帳處理。ARCHITECTURE 補上失敗處理的描述。
  - M5：超過 50 行的函式拆開（triage service 的 `_cited`／`_checked`／`_event_evidence`，snapshot 的 `_scan_section`／`_spec`，報告 service 的 `_replay`／`_enqueue`）。
  - L1：「人工判定」其實是 key 的問責，平台分不出送出者是人或自動化 client → §28.8、README、API_CONTRACT 寫明。
  - L2：報告快照模型的 docstring 更正。
  - L3：參數檢查原本是整段請求的子字串比對 → query 參數只比對 request-target 中 query 的名稱；位置不明時另外比對 header 名稱與 body；畸形的 header 行不影響 body 的起點。
  - L4：空白的摘錄原本回 `excerpt_too_large` → 新增 `excerpt_empty`。
  - L5：補 `observation_ids` 的正向測試（去重、保留順序、記進事件）與引用其他 finding 觀察的反例；移除沒有用到的 `LockedTriage.observations_linked`。

### 28.14 整體的安全審查（G5：security-reviewer，opus，2026-11-08）

- 結果：0 CRITICAL、0 HIGH、1 MEDIUM、10 LOW。授權與物件層級 404、錯誤訊息不回顯、摘錄的可見性、Markdown／JSON 注入、ReDoS、下載 header、競態與用語都確認成立。處理：
  - M1（採用）：截斷原本以平均大小估計、每輪重新渲染整份報告；不可信內容讓大小分布偏斜時（少數很大的 finding 在前、大量很小的在後），審查估計一次嘗試要渲染約 500 MB、超過 30 秒的 lease，三次後永久失敗，期間 worker 也不處理 run。改成：每個 finding 只投影（遮罩、清理）一次、Markdown 片段只渲染一次，以每個 finding 的位元組數做前綴和一次算出截斷點；固定部分以「省略全部」時的大小估計（截斷說明的位數最多），估計只會偏大，最多再試多放一個；萬一估計失準，以實際大小二分搜尋，絕不送出超過上限的內容。測試：偏斜分布下截斷點等於逐一嘗試的結果、每個 finding 只投影與渲染一次、估計失準時的退路。量測（純函式，合成資料）：400×20KB 加 5,000×1KB 是 JSON 2.2 秒、Markdown 3.2 秒；420×20KB 加 3,000×800B 是 1.8／2.3 秒；均勻 20,000 個 finding 是 4.7／7.6 秒（§28.12 的 3.8／6.3 秒是舊演算法只投影放得下的部分；現在全部投影一次）。都只渲染一趟，遠低於 lease。
  - L1（採用）：停用 auth profile 的理由原樣寫進不可修改的 audit → 比照 triage，先 `redact_text` 遮罩、遮罩後再檢查長度。
  - L2（採用）：`platform_checks` 一律列出全部 8 項 → 只列實際執行的檢查（沒有參數時不列 `parameter_present`）；位置不明的參數在 body 中原本是子字串比對 → 改成表單與 JSON（任一層）的鍵名比對，和 API_CONTRACT 的描述一致。`checks_version` 維持 1：T21 尚未發布，沒有以舊語意寫入的資料。
  - L3（採用）：absolute-form 的 request-target 也必須是 http，而且 authority 等於 target（RFC 9112 §3.2.2），不再只看 `Host`。
  - L4（採用）：Markdown 中 code 以外的 attestation 欄位（時間、雜湊、長度、版本）來自 JSONB → snapshot 逐欄驗證格式（帶時區的 ISO 時間、64 位小寫十六進位、非負整數、檢查名稱的樣式），不符代表資料被改過，這次嘗試失敗，不把它渲染出來。
  - L5（不改程式，寫進文件）：runner 準備完 run、啟動容器之前的短暫時間內停用，該 run 仍會拿到 secret。這和「已啟動的 run 不受影響」一致；在 docker create 之前再檢查一次只能縮小、不能消除這段時間（secret 已寫進該 run 的檔案）。API_CONTRACT §19.5 寫明「回 200 不代表已經沒有 run 持有 secret，要立即停止請取消 scan」。
  - L6（採用）：v0019 的 versions guard 以快照讀父列，繞過應用程式直接新增版本、同時有停用尚未 commit 時，會留下帶密文的已停用 profile → 改成 `SELECT … FOR SHARE`，等停用 commit 後重新讀到已停用而拒絕。新增的競態測試在拿掉 `FOR SHARE` 時失敗、改回來就通過。T21 尚未發布，直接修改 v0019：測試與 Live 每次都從空的資料庫套用 migration；開發 DB 若曾套用舊版的 0019，要先 downgrade 到 0018 再 upgrade。
  - L7（採用）：報告的 `clean()` 先截斷到 4,000 字再遮罩，切開的半截 JWT 不再符合樣式 → 先遮罩、最後才截斷；回歸測試在舊程式下會留下半截 JWT。
  - L8（部分採用）：每個 scan 20 份的上限原本把 failed 也算進去，反覆失敗會讓這個 scan 永久無法產生報告 → failed 不計入。每個 key 的速率限制屬於 T23b（全域 rate limit），T21 不做。
  - L9（採用）：triage-events 的回應加上 `Cache-Control: no-store`；`redact_text` 的 header 規則允許前置空白（縮排或折行的 header 行，這是共用模組的改動，只會多遮罩）；摘錄另外遮罩這個 target 的認證設定各版本用過的自訂 header 名稱（只讀名稱，不讀密文）。
  - L10（採用）：下載的 CSP 加上 `frame-ancestors 'none'`（`default-src` 不涵蓋它）。

### 28.15 Live（G6，2026-11-08）

- 依核准的計畫只執行兩個既有指令。每輪前後確認：只剩 `secscan-db-test-1`、volume 數不變（269）、沒有 live 網路、Makefile 與 Compose 的清理範圍和 main 相同、接著電源；日誌的敏感樣式掃描（平台 key、Bearer、JWT、Fernet 密文、連線字串、密碼、`*KEY*=`）都是 0。
- 第一次 `make test-live-fixture-rescan`（實作完成後、commit 24a04ca，`recordings/fixture-rescan/t21-run-1/`）：通過，31 分 35 秒。
- 第二次 `make test-live-fixture-rescan`（程式碼與安全審查的修正之後、commit e9c2683，`t21-run-2/`）：通過，31 分 31 秒。
- 兩次的結果：

  | 項目 | 第一次 | 第二次 |
  |---|---|---|
  | T22 的比較（unchanged／patched／partial） | new、not_observed 都是 0；unchanged 是 persistent 29、inconclusive 2 | new、not_observed 都是 0；unchanged 是 persistent 30、inconclusive 0 |
  | patched 比較 | persistent 8、inconclusive 24 | persistent 8、inconclusive 24 |
  | 人工複測後 resolve（T30-FX-01 SQLi、T30-FX-02 XSS） | 2 個，平台條件都成立；比較快照仍是 inconclusive | 2 個，同左 |
  | `basis=rescan_not_observed` | 一律 422 `not_observed_required` | 同左 |
  | 反例 | CSP 與 persistent 的 finding 都 422 | 同左；拒絕原因與平台條件算出的完全相同（CSP：`engine_incomplete`、`reasons_not_eligible`；persistent：`inconclusive_required`、`current_observed`、`coverage_missing`、`reasons_not_eligible`），沒有位置或身分不符；缺少摘錄是 `INVALID_REQUEST` |
  | 小預算 scan 之後自動重開 | 2／2，系統事件與 `finding.reopen` | 2／2 |
  | 報告（baseline 與小預算 scan 各 JSON、Markdown） | 4 份都 1 次嘗試完成、未截斷；sha256、header、Pydantic、Markdown 安全檢查與標示都通過 | 同左（CSP 已含 `frame-ancestors`） |

- 第一次在審查修正之前執行，修正之後以第二次為準。Live 中的「操作者」是測試本身：它驗證流程、一致性檢查與標示，不證明人工聲明的真實性。
- `make test-live-fixture-findings` 回歸一次（審查修正之後，linker 與 worker 迴圈都有改；錄到 `recordings/fixture-findings-t21/`，不覆寫 T19／T20 的錄製）：3 passed，22 分鐘；沒有殘留資源。3 個 warning 是 T19 既有 Live 測試的 pytest 棄用提醒（class-scoped fixture 寫成 instance method），與 T21 無關，留給 T23c 整理。
- Gate D 的人工審閱樣本：Live 測試只核對報告、不保存內容，所以樣本改在 db-test 以真實的 PATCH、ReportService、ReportWorker 與渲染產生（觀察是整合測試的合成資料，UUID 換成代號），放在 gitignore 的 `recordings/t21-report-samples/`。使用者審閱之前，Gate D 不標通過。

### 28.16 合併後補查核心模組的 branch coverage（2026-11-08）

- PR #30 合併後才逐一檢查計畫要求的核心模組 branch coverage（≥ 90%），發現 `reports/domain/document.py`、`render.py`、`markdown.py` 分別約 83%、88%、89%：有規格時的 spec 區段、`rescan_not_observed` 沒有 attestation 的 resolution、多個來源的說明、截斷時「再多放一個」成功與最後一個放不下的分支、結構不符的文件都沒有測試。這是 PR #30 的 DoD 缺口，以後續 PR 補上。
- 補測試的過程中發現 Markdown 報告沒有輸出 API 規格（JSON 有，計畫 §3.1 也列出規格），補上「API 規格」一節（`openapi_version` 來自上傳的文件，放在 code 中）。
- `plan_manual` 有一個不可能走到的分支（只為了 mypy 的型別收窄），改寫成等價、每個分支都走得到的形式。
- 結果：`reports/domain/*`、`triage/domain/*`、`findings/domain/triage.py`、`findings/reopen.py`、`reports/queue.py`、`worker/reports.py`、`security/redaction.py` 都是 100%；`findings/triage_records.py` 97%（剩下的分支是 DB CHECK 保證不會發生的防禦檢查）。整體 6471 passed、2 skipped，coverage 99.37%。

### 28.17 Gate D 樣本報告的人工審查與關閉（使用者，2026-11-08）

- 使用者的結論：核心安全語意 PASS（未確認的告警有標示、resolved 標為人工判定、固定說明揭露限制、比較快照與 triage 分離、摘要計數一致、完成狀態一致、覆蓋限制有揭露、摘錄只有雜湊）；有條件通過，Gate D 暫不關閉。處理：
  - **檢查名稱**：`result_not_reproduced` 容易被誤解成平台確認了無法重現 → 改名為 `declared_result_is_not_reproduced`，`checks_version` 升到 2（v1 已合併到 main，但只出現在開發與測試資料）；API_CONTRACT §19.2 逐項定義 `platform_checks`，寫明沒有一項代表平台獨立驗證修補。
  - **嚴重度的來源**：Markdown 的來源行只列正規化後的等級，讀者會以為工具原本就給 High → 每個來源同時列出工具的原始嚴重度、信心與平台正規化的嚴重度，finding 的標題列標明「正規化」。樣本中 SQLi「原始 Medium、正規化 high」部分來自合成資料：整合測試的 `observation()` 預設把 `severity_label` 一律設成 Medium，`raw_severity` 是 3（正規化依 raw 值）；真實的 ZAP 輸出這裡會是 High。
  - **完成度不等於覆蓋**：固定說明在完整完成時加上「`results_complete=true` 只代表掃描流程已完成，不表示測試覆蓋完整」，沒有量測覆蓋時加上「本次未量測測試覆蓋」。
  - **原始 JSON**：審查看到的 `\<id-1>`、`http\://` 是貼到聊天時產生的，檔案中沒有反斜線，`json.loads` 與 `ReportDocumentV1` 都通過。第一版樣本兩個檔案各自替換代號，兩份不同的報告都變成 `<id-1>`，替換也讓內容不再和平台輸出逐位元組相同 → 第二版（`recordings/t21-report-samples-v2/`）經下載端點取得原始位元組、不替換代號（都是合成資料的隨機 id），`manifest.json` 記下每份的 metadata（sha256、大小）與下載 header，四份的 sha256 與大小都和 metadata 相符，報告 id 各不相同；每份都套用 Live 的同一套核對（`check_headers`、`check_document`／`check_markdown`、用語檢查）。
- **三種 scan 狀態的證據組合**：計畫 §6.3 的 Live 報告是 partially_completed 與 timed_out，§6.4 卻要求含 completed。fixture 上的 Nuclei 每次都是 `ENGINE_REPORTED_ERRORS`，Live 不會出現 completed 的 scan，所以 completed 只能由 DB 整合測試涵蓋：

  | scan 狀態 | Live（真實掃描，`make test-live-fixture-rescan` 兩次） | DB 整合（真實 API、worker 與渲染，合成觀察） |
  |---|---|---|
  | partially_completed | baseline 的 JSON 與 Markdown，各兩次 | — |
  | timed_out | 小預算 scan 的 JSON 與 Markdown，各兩次 | 樣本 `timed-out.json`／`.md`；常駐測試（見下方「收尾補強」） |
  | completed | 無（fixture 的 Nuclei 一律失敗） | `test_reports_api`；樣本 `completed.json`／`.md`；常駐測試（見下方「收尾補強」） |

  Live 與樣本都套用同一套核對。使用者已接受這個證據組合，見下方的關閉紀錄。
- **Gate D 關閉紀錄（使用者，2026-11-08）：PASS（接受有文件記錄的替代證據）**
  - **證據**：去重反例（T20，§26）、複掃反例（T22，§27）與報告安全語意驗收（T21，§28.15–§28.17）都有對應的測試證據。
  - **三種狀態**：
    - partially_completed 與 timed_out 由兩次 Live rescan 驗證。
    - completed 因為 fixture 的 Nuclei 引擎限制，改用 DB 整合測試：走真實的 API、worker、渲染與下載流程，並共用報告驗證斷言（`tests/live/report_assertions.py`；常駐測試見「收尾補強」）。
  - **適用範圍**：這個替代方案只適用於 Gate D 的報告正確性與措辭驗收，**不宣稱已完成 completed 的 Live 端到端驗證**。
  - **PR #32**：修正人工複測的檢查名稱、版本與嚴重度呈現；測試結果 6473 passed、2 skipped，coverage 99.37%。
  - **樣本**：報告樣本與下載校驗證據放在 `recordings/t21-report-samples-v2/` 與其中的 `manifest.json`（在 gitignore 中），由執行者保存。
  - **不做的事**：不需要第三次 Live，也不為這個驗收差異修改 fixture 或掃描演算法。
  - **收尾補強**：
    - 關閉前核對時發現，共用斷言原本只由已刪除的樣本產生器套用過一次；`test_reports_api` 用的是另外寫的等價斷言，沒有常駐的回歸保護。
    - 因此新增 `test_completed_and_timed_out_reports_pass_the_live_report_checks`。它重現樣本的同一個流程：completed 是 resolved 的 SQLi，timed_out 是複掃中自動重開的 SQLi。兩者都直接呼叫 `check_headers`、`check_document`、`check_markdown` 與用語檢查。
    - completed 另外斷言 `results_complete=true` 與「完成度不等於覆蓋」的固定說明；`coverage_measured` 是 false 時，斷言「未量測覆蓋」的固定說明。
    - 把傳給 `check_document` 的完成旗標反過來時，completed 與 timed_out 兩個案例都會失敗，所以測試不是空轉。只改測試，不改產品程式。
    - 補強後的結果：新測試連續 3 次通過；`make lint`、`make typecheck` 通過；`make test` 6474 passed、2 skipped，coverage 99.37%，報告與人工複測的核心模組 branch coverage 仍是 100%。
  - **仍未完成**：
    - SEC-14（T23a）、權限與速率限制（T23b）。
    - M5 的其他驗收項目：Gate A–C 尚未正式判定通過，Gate E（T23d）與 T23 的 DoD 尚未完成。
    - Gate D 通過不代表 M5 完成。報告內容與人工複測摘錄尚未加密、尚未設定保留期限，不得宣稱已完成保護。
  - **接下來**：原核准的順序不變，T21 → T31 → T23a–d。

## 29. T31：benchmark harness 與引擎子預算（2026-11-08 開始）

細部計畫第一版經一次獨立審查（Plan 子代理，opus）。使用者 2026-11-08 決定 C 組（ZAP＋Nuclei）的子預算採「凍結：嚴格上限」，並核准離線的實作、測試、文件、分支、PR 與合併。**核准不包含任何 Live**：第 6 節的 Live smoke 需要另外授權；T21 的授權不延伸到 T31。

### 29.1 引擎子預算：嚴格上限（使用者，2026-11-08）

- **為什麼需要**：T12 起每個 run 分到 scan 剩下的全部預算（§16.4），引擎順序固定 ZAP → Nuclei，所以 C 組的 ZAP 可以用掉全部，Nuclei 只拿剩餘；預算寬鬆時 C 實際用掉約 A＋B 的資源，不符合 SECURITY_AND_TESTING §6 的「組合組先分配子預算並凍結分配，總額與單工具組一致」。`ARCHITECTURE.md` §3.4 原本寫「預算預先分配給各引擎」，和 T12 的實作一直不一致，這次一併更正。
- **語意**：建立 scan 時可以選填 `engine_budgets`，每個掃描引擎各一組 `max_requests`、`max_duration_seconds`。每個 run 開始前取「scan 剩下的」與「這個引擎的上限」的較小值（請求數與秒數各自取）。先跑的引擎沒用完的份額**作廢**，不轉給後面的引擎。沒有指定時行為完全不變。
- **建立時的檢查**（不合回 422 `INVALID_REQUEST`，不寫入任何東西，訊息不回顯輸入的值）：
  - 形狀（和引擎的規則一起、在取得任何鎖之前）：只用於兩個以上掃描引擎的 scan；每個引擎恰好列一次。
  - 數值（scan 的總額確定之後）：每個份額是 1 到總額的整數；合計不超過總額；不低於引擎的最小時間窗——ZAP 至少 120 秒、請求數至少 120 秒份（120 × 速率），Nuclei 至少 60 秒。低於最小時間窗註定 `BUDGET_EXHAUSTED`，所以建立時就拒絕。
  - 最小時間窗的常數在 `scans/domain/allocation.py` 另寫一份（`scans` 依分層不能 import `scanners`），單元測試核對和兩個 plan 的常數相同，並以 ZAP 的 `plan_seconds` 驗證邊界。
- **只會讓配額變小**：`min(remaining, cap)` 不可能超過 scan 的總額或 grant；guard 本身不變，仍以 runner 算好的每個 run 的請求數上限與 scan 的速率強制。ZAP、Nuclei 的 plan 也不必改（它們本來就以分到的秒數與請求數計算）。合計不超過總額是公平性的規則，不是安全性的前提。
- **Idempotency**：fingerprint 只在有指定時加入 `engine_budgets`（依引擎排序），沒有指定的請求和 T31 之前**逐位元組相同**（以改動前取得的 golden hex 測試），所以不改 `FINGERPRINT_VERSION`；改版號會讓舊 key 的重送變成 409。同一個 key、不同的子預算回 409；順序不同視為相同。
- **DB（migration v0020）**：`scanner_runs` 新增 `budget_max_requests`、`budget_max_duration_seconds`、`seconds_allotted`。
  - CHECK：上限同時有值或同時是 null、正整數、只屬於掃描引擎（允許清單 zap、nuclei、schemathesis；之後新增的非掃描引擎不會被默默放行）；有上限的 run 寫入請求數時，秒數也必須寫入，兩者都不超過上限——還不認得上限、只寫請求數的舊 runner 會讓整個 prepare 的 transaction 失敗，容器不會建立（fail closed）。
  - trigger：上限不能修改（比照 v0011 的 `scanner_runs_plan_once`）；新增 run 時不能預填配額，請求數寫入之後配額不能再改（唯一的寫入點是開始執行時的那一次）。run 只能在建立 scan 的 transaction 新增、結束的 run 整列凍結，沿用 v0009。
  - downgrade：還有未結束、帶上限的 run 時拒絕（否則舊程式會讓它們分到剩下的全部，子預算悄悄消失）。
  - 升級時三個 CHECK 各掃一次表、持有 ACCESS EXCLUSIVE 到 commit；表很小（每個 scan 最多 4 列），依既有程序先停服務，沒有另外設定 `lock_timeout`（資料庫審查 LOW-5，接受）。
- **揭露**：`engines[].budget` 列出凍結的上限；audit 的 `scan.create` 只在有指定時記下 `engine_budgets`（沒有指定的 scan，audit 的內容和之前相同）。
- **仍然存在、要揭露的偏差**：
  - 份額作廢時 C 的實際用量會少於總額（對 C 不利的保守方向）；manifest 與 `engines[].usage` 揭露實際用量。
  - 引擎順序固定 ZAP → Nuclei（架構決定），隨機化的是 scan 之間的順序；ZAP 的主動掃描可能先改變靶機狀態，列為效度威脅。
  - 被 runner 硬性停止時，清理的秒數算在 `traffic_seconds`，會讓後面的引擎少拿幾秒（例如 ZAP 用了 400 秒、自己的上限 380，Nuclei 只拿到 200 而不是 220），以「實際分到的秒數」揭露。
  - Nuclei 被時間或請求上限停止時不收集輸出（§20.1），結果是 0，不是部分結果；分給 Nuclei 的份額必須夠它跑完。正式數值由 T27 依非 holdout 的校準凍結。
  - 綁定 auth profile 時，preflight 不受上限、從總額扣除它用掉的請求數與秒數：份額合計等於總額時，最後一個引擎可能拿不到自己的上限，甚至低於最小時間窗而 `BUDGET_EXHAUSTED`。建立時的最小時間窗檢查沒有預留 preflight（資料庫審查 LOW-4）。目前多引擎只有 zap＋nuclei，而 nuclei 不能和 auth profile 一起用，所以還不會發生；harness 也只跑匿名的 scan。
- **不改**：guard、T22 的比較（被上限截斷的 run 本來就不完整，比較會是 inconclusive）、T21 的報告（報告現在也不列總預算的上限，記為限制）。

### 29.2 每個 run 的配額與用量進 API

- `engines[].usage`：`requests_allotted`、`duration_allotted_seconds`、`requests_sent`、`requests_denied`、`traffic_duration_seconds`。沒有容器（in-process 的 fake、還沒開始、開始前就結束）或不明時是 null，不以 0 冒充；T31 之前的 run 沒有記下分到的秒數。欄位名稱和 `budget_usage` 一致。
- 這不論子預算怎麼決定都需要：被 runner 停止、沒有收集的 run（例如被上限停止的 Nuclei）沒有 `result.guard_traffic`，原本只能在 DB 看到用量，DoD 的「經 API 保存 guard 計數」做不到。

### 29.3 harness 的設計

- **黑箱**：新的頂層套件 `benchmarks/`（不進 wheel 與映像）只吃平台 API 的 JSON 與本機的實驗檔案；AST 測試禁止它 import `secscan`、`tests`、DB、Web 框架、Docker、網路與子程序的模組，純函式的模組（評估、統計、比對、正規化、排程、規格的 schema）連檔案系統也不碰。和 `cases.py`、平台常數的核對放在測試，不放在 `benchmarks`。
- **實驗規格**（YAML，嚴格 schema）：組別與引擎、子預算、靶場與版本、profile、總預算、重複次數、種子、比較區塊。
  - 靶場只能是 fixture、juice_shop、vampi，位址由 `lab_support` 固定在 live 的 lab 網段；不接受 URL 或 IP，平台的 `LAB_CIDR` 與 grant 再擋一次。
  - 所有組別共用同一份總預算，不超過平台 grant 的上限（2 req/s、5,000 次、1,500 秒）。experiment 的多引擎組別必須凍結份額，而且合計**等於**總額；每格至少重複 3 次。份額依平台相同的規則檢查（常數由測試核對）。組別的引擎必須依平台的執行順序（zap、nuclei）列出。同一個組別與靶場的 scan 數不超過平台的 quota 50。這些都在 `bench-check` 離線檢查，不會等到 stack 啟動之後才在第一個 POST 失敗。
  - 讀 YAML 時拒絕重複的鍵、非字串的鍵、別名、多份文件與過大的檔案（`safe_load` 遇到重複的鍵會靜默以後者覆蓋），也只接受字串、數字、布林、null、清單與 mapping：`!!set` 會靜默去掉重複的鍵、`!!omap` 會保留重複的鍵，merge key、日期與 binary 也用不到（安全審查 L4）。ground truth 與標記檔用同一個讀取函式。
  - T31 只接受 `web_active_lab`：Juice Shop、VAmPI 是否改用 `api_active_lab`（需要上傳規格）由 T27 決定。
- **排程**：單位是一次 scan 或一個比較區塊（baseline 與 current 整塊移動、baseline 在前），以 sha256(種子, 單位) 排序；不用 `random`，可以從 manifest 重現。
- **Live 流程**（`tests/live/test_bench_live.py`）：
  1. 每個（組別, 靶場）一個 project，組別之間的 finding 不會合併；同一個靶場在 session 中用同一個 host（origin 不變），每個 scan 之前重建靶機，讓資料快照相同。
  2. 經 API 建立 scan、輪詢到結束；等待上限是 scan 的總秒數加 900 秒（ZAP 的 JVM、收集、解析與清理不算在流量秒數內），不沿用 `RUN_TIMEOUT` 的 600 秒。
  3. 經 API 收集 scan、這個 scan 的 finding（`GET /scans/{id}/findings` 只看這個 scan 的來源）、觀察數與比較快照；收集與 integration 測試走同一段程式（`benchmarks.collect` 接受一個 fetch 函式）。缺欄位、型別不符、分頁不一致、還沒結束或 fixture 的 scan 一律失敗。
  4. 結構斷言：不是 fake、上限和規格相同、每個容器 run 分到的等於 min（剩下的, 上限）且轉送數不超過分到的、guard 只看到靶機；**不斷言偵測數**。
  5. 不論成功或失敗都寫 manifest 與 SHA256SUMS；失敗時 `complete: false`、只記例外的種類（訊息可能含回應的內容）。
  - 全部在同一個 pytest session 中完成：`test-live-runner` 結束時 `down -v` 會清掉 DB。
  - 不使用其他 live 測試的私有函式，不改既有的 live 測試；`start_juice_shop`、`start_vampi` 只加選填的 `host`。Juice Shop、VAmPI 的路徑在 T31 不執行，第一次 Live 驗證在 T28。
- **失敗與作廢**：不自動重試（重試會讓樣本有偏差）。任何一次執行失敗就停止整個 session；`bench-evaluate` 拒絕評估不完整的 session。
  - 有效的樣本只能以工具或預算的結果結束（允許清單）：`BUDGET_EXHAUSTED`、`ENGINE_TIMEOUT`、`TIME_LIMIT_EXCEEDED`、`ENGINE_FAILED`、`ENGINE_REPORTED_ERRORS`、`OUTPUT_INVALID`、`NO_TARGET_TRAFFIC`、`RESOURCE_LIMIT_EXCEEDED`、`ARTIFACT_REJECTED`。
  - 其他錯誤碼都是平台、授權、設定或環境的問題（例如 `PLAN_REJECTED`、`SCOPE_EXPIRED`、`LEASE_EXPIRED`、`GUARD_UNAVAILABLE`），加上 interrupted、cancelled 的 scan，讓整批作廢，以新的名稱重跑，不計次數，也不挑掉個別樣本。第一版用的是環境錯誤的排除清單，程式碼審查指出 grant 在兩個引擎之間到期、plan 被拒絕這類失敗會被當成 recall 偏低的有效樣本，改成允許清單。
  - harness 的 grant 有效期涵蓋最壞情況的整個 session（每個 scan 都用滿總秒數加 900 秒）再加一天：grant 不會在 session 中到期，ZAP 的 plan 也不會被「grant 快到期」截短。規格的最壞情況超過 29 天（grant 最長 30 天）時，`bench-check` 就拒絕。
- **結果目錄**（`benchmarks/results/<name>/`，已在 gitignore）：O_EXCL 獨占建立、不覆寫，目錄 0700、檔案 0600；寫入前檢查平台 key 的格式、Bearer、JWT 與這次 session 建立的 key 原值；只保存 scan、finding 與比較快照的 JSON，不保存觀察的 evidence。**沒有加密**（T23a 的範圍），manifest 一律揭露。（T23a 更新：結果檔以本機的 bench 金鑰加密、manifest 升到版本 2，見 §30.7。）
- **manifest**（§8）：規格的 sha256、種子、排程與實際順序；每個 scan 的預算、上限、分到的配額、guard 計數與狀態；比較快照；每個檔案的 sha256；`complete`；固定的揭露清單。API 拿得到的身分（`GET /scanners`、`GET /scan-profiles`、每個 run 的 `plan_hash`）照原樣記下；拿不到的由 harness 記下並標明來源：commit 與是否有未提交的修改、guard 與 fixture 執行用的本機映像 ID、fixture 原始碼的雜湊、靶機映像的參照、strict-1（path 規則沒有執行期的版本代號，以 commit 與 guard 映像識別）。
- **指令**：`make bench BENCH_SPEC=… BENCH_NAME=…` 的前置是 `ENABLE_LIVE_LAB_TESTS`、規格與結果目錄名稱（只收英數字、`-`、`_`，已存在就停止）的檢查；都通過之後，recipe 才遞迴執行 `test-live-runner`（以 `make -j` 執行也不會先啟動 stack；安全審查 L2）。建立、測試與清理完全沿用同一個隔離 stack 與範圍（Makefile 測試確認）。使用者給的值以環境變數交給 recipe、由 shell 展開，不以 make 的變數嵌進 shell 的文字（安全審查 L1）；Live 測試從環境變數讀規格的路徑與名稱，規格只讀一次（解析、sha256 與複本來自同一份位元組；安全審查 L3）。`make bench-check` 與 `make bench-evaluate` 是離線的；後者只讀結果目錄，評估以 canonical JSON 寫到 stdout，選填的 `BENCH_TRUTH`、`BENCH_ADJUDICATIONS`、`BENCH_PAIR_LABELS`、`BENCH_INCLUDE_HOLDOUT`。

### 29.4 指標的定義（`benchmarks/evaluate.py` 等，純函式）

- **recall 以案例計**：列入評估的是 security、supported、適用這個 scan 的 auth role、存在於這個版本的案例。holdout 預設排除；`include_holdout` 只接受凍結的 ground truth。被排除的案例依原因列出（holdout、unsupported、platform_blocked、auth_role、not_security_case、not_present_in_variant）。
- **precision 以議題計**（計畫第一版寫「以 finding 計」，依 §7.1「同一真實問題由兩工具命中只算一個 TP」與獨立審查的意見改正）：
  - TP 單位是偵測到的案例，加上裁定為「真的另一個問題」的議題（`issue`）；它們不進 recall 的分母。
  - FP 單位是修補版上對上案例的 finding（負例對照），加上裁定為誤報的議題。
  - 對上 holdout、平台阻擋、不支援或非 security 案例的 finding，以及非 security 的 finding，都不進分子與分母。
  - finding 層級的 precision 另列為次要數字。
- **N/A**：分母為 0；還有未裁定的 finding（precision）；precision 或 recall 為 N/A，或兩者都是 0（F1）。不填 100%。一個 finding 同時對上兩個案例就停止評估（ground truth 有歧義）；平台阻擋的案例被命中列為異常。
- **引擎**：各引擎偵測與獨有的案例數；2 個以上引擎命中的 finding 另算 finding 層級的 precision（§7.1 的探索性分組，不作為合併或升級的規則）。
- **資源與完成度**：guard 計數的請求數與秒數（任何一個開始過的 run 不明，總數就不明）、牆鐘時間（建立到結束）、每個 run 是被請求數（guard 回報用盡，或轉送數達到分到的）還是時間（工具或 runner 的時間上限）截斷；scan 與每個 run 的狀態分開列，不合成單一的「可用」分數。
- **覆蓋**：只有 `coverage_measured` 時才是 observed／eligible，web 的 scan 一律 N/A。
- **去重**（§7.2）：predicted pair 以 finding 層級表示（同一個 finding 有 2 個以上引擎的來源），由人工標記判斷合併是否正確；沒有跨引擎的合併時 precision 是 N/A（`no_cross_engine_merges`），有未標記的合併時也是 N/A；recall 只在標記宣告完整時才算。另報有 2 個以上觀察的 finding 數（包括同一個引擎的合併，例如 T26 錄製中 /search 的兩個 XCTO；不另判對錯）、誤合併、漏合併與列表壓縮比例（1 − finding 數／觀察數，不是 precision 的改善）。逐一 observation pair 的標記與單位的一致性在 T27 視需要再擴充。
- **複掃**（§7.4）：「誤判已修補」＝ ground truth 在 current 的版本仍存在，卻被判 not_observed（必須是 0）；inconclusive 不算驗證修補；修補版上仍 persistent 的案例另外列出；對不上案例的 not_observed 另計。案例的排除規則和偵測相同（holdout 預設排除、不支援、平台阻擋、非 security、auth role），對上被排除的案例只依原因計數、不列出 id（程式碼審查指出第一版會在預設評估中列出 holdout 的案例，違反 §5.2）。
- **跨重複**：每格（組別, 靶場, 版本）列出 n、中位數、最小值與最大值；IQR 只在可用的值有 4 個以上時才算；N/A 另計，不當成 0；每個案例的偵測頻率 x/n。smoke 與未凍結的 ground truth 都在輸出中標明不是正式結果。

### 29.5 ground truth 與人工標記的格式（T27 撰寫）

- T31 只定義格式、載入與檢查，測試用合成的案例；**不在 T31 撰寫正式的比對檔**。每個靶場一份：案例有 kind、支援範圍、holdout、auth role、存在於哪些版本與比對條件（rule group 必填，method、route、可接受的參數位置清單與參數名稱選填）。supported 的 security 案例必須有比對條件；兩個案例不能有相同的條件。
- adjudications：未對上案例的 security finding 的人工裁定（`true_extra`、`false_positive` 必須有 `issue`，`not_security` 不給），同一個 finding 只能裁定一次。pair labels：合併是否正確、漏合併的 pair、是否完整。

### 29.6 限制

- 結果目錄沒有加密（T23a）。（T23a 更新：已加密，見 §30.7。）報告不列總預算的上限與子預算。strict-1 的 path 規則沒有執行期的版本代號。
- harness 本身還沒有 Live 驗證：Live smoke 通過之前 T31 不標完成。Juice Shop、VAmPI 的路徑要到 T28 才第一次執行。
- 只有匿名掃描：Nuclei 不能和 auth profile 一起用（§24.1），主要比較三組都用匿名。

### 29.7 交接

- **T27**：
  - 以非 holdout 的校準凍結總預算與各引擎的份額，Nuclei 的份額要夠它跑完。
  - 依 `cases.py` 的語意撰寫 ground truth 的比對檔並凍結，處理三個已知問題：FX-05 會分成多個 finding（recall 以案例計，不受影響）；`rescan_assertions.py` 中 `body` 的參數鍵永遠對不上（parser 只產生 query／unknown）；`cases.py` 的 FX-08 偵測欄寫 40011，文件與 rule group 是 20019。另外 10020（anti-clickjacking）在 S&T §5.1 同時列為 FX-05 的命中與「超出 12 個案例的告警」，要擇一。
  - holdout 的偵測結果在 T30 的 Live 量測表中已經看過，列為效度威脅。
  - Juice Shop、VAmPI 的案例改成機器可讀；決定它們的 profile。
- **T28**：完整矩陣約 45 次 scan、數小時，需要長時間保持喚醒；guard 的 telemetry 6 小時後刪除；每個 target 24 小時最多 50 個 scan。正式的 recall／precision 與 holdout 跑分排在 T33 之後，或由使用者決定沿用 strict-1、另列平台阻擋（§21.5、§22）。

### 29.8 離線驗證

- 子預算：BUDGET-01 至 10（S&T §4 的新表）。harness：BENCH-01 至 12；BENCH-13 是 Live smoke（需要另外授權）。
- 第一個 commit 時 `make test` 6,576 passed、2 skipped，coverage 99.38%；`benchmarks` 的 branch coverage 100%（`evaluate.py` 等純函式比照核心模組要求 ≥ 90%）。
- 空轉檢查：把配額改成忽略上限有 7 個測試失敗；評估的四個 mutant（忽略未裁定、TP 以 finding 計、分母 0 當 100%、誤判已修補反向）都被測試抓到；確認之後改回，不提交。
- 審查修正之後：`make lint`、`make typecheck` 通過；`make test` 6,905 passed、2 skipped，coverage 99.42%；`benchmarks/` 與 `scans/domain/allocation.py` 的 branch coverage 100%。沒有執行任何 Live。

### 29.9 審查與處理（opus，2026-11-09）

三個審查都沒有 CRITICAL 或 HIGH。

- **程式碼審查（code-reviewer）**：3 個 MEDIUM、3 個 LOW，全部修正。
  - MEDIUM：作廢的判斷改成允許清單，grant 有效期依最壞情況設定（§29.3）；複掃套用和偵測相同的排除規則（§29.4）；規格要求引擎依平台的執行順序，避免合法的規格在 Live 中途斷言失敗。
  - LOW：去重的 N/A 原因與單一引擎的合併（§29.4）；規格離線檢查平台 grant 的預算上限；`ScanService.create` 把寫入、事件與 audit 抽成 `_write`（原本 71 行）。另外 AST 測試的純函式清單補上 rescan、scoring、metrics。
- **安全審查（security-reviewer）**：4 個 LOW，全部修正：make 變數改以環境變數交給 shell（L1）；bench 在檢查都通過之後才遞迴執行 test-live-runner（L2）；規格只讀一次（L3）；嚴格 YAML 的 tag 允許清單（L4）。另依建議，結果檔以 `fchmod` 設定權限。附帶提到既有的 `LIVE_LAB_NET`／`LIVE_PROJECT` 可以從命令列覆寫而改變所有 live 目標的清理範圍：不是這個分支引入，不在 T31 修改，記為 T23b 可考慮的強化。
- **資料庫審查（database-reviewer）**：6 個 LOW。
  - 修正：配額只寫一次的條件收緊，並拒絕 INSERT 預填（LOW-1）；`engine_budget_valid` 改成允許清單（LOW-2）；downgrade 在還有未結束、帶上限的 run 時拒絕（LOW-3）；preflight 共用總額的偏差寫進 §29.1（LOW-4）；補上舊資料列經 repository 讀回、downgrade 拒絕與成功後 trigger 函式都移除的測試（LOW-6 的一部分）。
  - 接受：升級的鎖與掃描成本（LOW-5，依既有程序先停服務）；ORM 與 migration 的 CHECK 文字沒有自動比對（LOW-6 的另一部分：審查已人工逐字核對，專案既有的測試也只比對名稱）。

## 30. T23a：原始證據的加密與保留期限、報告與摘錄的加密、金鑰分組與換版（SEC-14 的一部分，2026-11-09 開始）

細部計畫第一版經一次獨立審查（Plan 子代理，opus）。使用者 2026-11-09 決定：保留期限 7／30／30 天、兩組平台金鑰分開（最小權限）、`benchmarks/results` 也加密、`make env` 由使用者自己執行；並核准離線的實作、測試、文件、分支、PR 與合併。**核准不包含**：任何 Live、由開發代理修改 `.env`（包括經 `make test` 間接觸發 `make env`）、執行 `make bench-key`、修改或清除既有的金鑰，以及修改或刪除 `recordings/`、`runs/spike-t03/work/`、既有的研究資料與開發環境的資料。

**這一節的用語**：原始證據是「run 結束（解析完成、失敗或逾期）之後加密」，**不是全程靜態加密**；執行、收集、等待解析期間是明文（§30.3 的時間表與 §30.9 的剩餘風險）。

### 30.1 範圍

- 做：三組平台金鑰的分配與啟動檢查（§30.2）；runs volume 的加密生命週期、逾期處理與 fail-closed（§30.3）；報告內容與人工複測摘錄的加密（§30.4）；保留期限與清除（§30.5）；換版（§30.6）；`benchmarks/results` 的加密與遷移工具（§30.7）。
- 不做：加密 `observations`（一般 API 的遮罩檢視；Nuclei 擷取的 email 與卡號照 TOOLS §2.1.2 記為限制）；guard telemetry（tmpfs、6 小時）；DDL／DML 分權、compose secrets、掃描容器的 log driver、uid 分離與主機全碟加密的要求（T23b）；最終 Live 重跑（T23c）；乾淨環境重建（T23d）；`recordings/` 與 spike 檔（T34）；原始輸出的下載 API（T21 已移除，不恢復）。

### 30.2 三組金鑰與權限邊界（使用者，2026-11-09；取代 §12.2、§14.12 的對應句子）

| 金鑰 | 設定 | 容器 | 用途 | 不得持有 |
|---|---|---|---|---|
| 目標的 secret（既有） | `SECRET_ENCRYPTION_KEYS` | api（只加密）、runner（解密後注入掃描容器） | auth profile 的 secret | worker |
| 原始證據（新） | `EVIDENCE_ENCRYPTION_KEYS` | runner；runner 容器內的 admin 指令 | runs volume 的原始證據 | api、worker |
| 報告內容（新） | `CONTENT_ENCRYPTION_KEYS` | api、worker；主機上的換版指令與 migration | 報告內容、人工複測摘錄 | runner |
| bench（新，本機） | 金鑰檔（`BENCH_KEY_FILE`，預設 `~/.config/secscan/bench-keys`） | 開發機上的 bench harness 與 `bench-evaluate` | `benchmarks/results` | 平台的任何容器 |

- **格式**：每組 1 到 4 把 Fernet 金鑰（url-safe base64 的 32 bytes），第一把加密、每一把都能解密，規則同 §12.1。`parse_keys` 加上設定名稱的參數，錯誤訊息指出是哪一組的第幾把，不含金鑰。
- **互不共用**：`check_distinct_key_rings` 以解碼後的 bytes 比對（base64 最後一個字元有未使用的位元，不同寫法可能是同一把金鑰），訊息只列出兩組的名稱。每個程序檢查自己持有的幾組；`secscan-admin check-encryption-keys` 在主機上一次檢查三組，只顯示數量、不連資料庫。
- **啟動時缺金鑰就停止**：api 需要 SECRET 與 CONTENT（`app.state.content_cipher`）；worker 需要 CONTENT；runner 需要 EVIDENCE（runner 沒有 SECRET 照舊可以啟動，需要認證的 scan 以 `SECRET_UNAVAILABLE` 失敗）。
- **compose 的分配**：只把各自需要的那幾組傳進容器（部署測試 KEY-02 核對，沒有任何服務用 `env_file`）。主機上的 `.env` 是唯一的設定來源、三組都在裡面，所以主機上的 admin 指令與 migration 由操作者執行；「只給某個程序」指的是容器拿到的金鑰。保留期限也只傳給套用它的程序（runner：`EVIDENCE_RETENTION_DAYS`、`EVIDENCE_PLAINTEXT_MAX_MINUTES`；worker：`REPORT_RETENTION_DAYS`；api：`EXCERPT_RETENTION_DAYS`）。
- **`make env`**：比照既有的寫法，以 `openssl rand -base64 32` 產生、轉成 url-safe、檢查長度 44；冪等，只附加缺少的那一行；任何一個是空值時在寫入之前就停止；不改、不重設、不輪替既有的值；終端只顯示名稱；`umask 077` 與 `chmod 600` 照舊（KEY-05 在暫存目錄執行真的 recipe，不碰真正的 `.env`）。
- **金鑰不外流**：設定一律是 `SecretStr`；repr 只顯示設定名稱與數量；錯誤與 log 不含金鑰、明文或密文（canary 測試）；bench 結果寫入前的秘密檢查加上 Fernet 金鑰的形狀與 bench 金鑰本身。
- **「API 從不解密」的修正**：
  - 保留：API 從不解密**目標的 secret**（`reveal` 仍只在 `runner/service.py`）。
  - 新增：API 只解密 CONTENT 加密的內容，而且只在報告下載（`reports/service.py`）與 triage 事件（`triage/service.py`）。AST 測試（KEY-03）限定 `unseal` 只有這兩個呼叫者、`unseal_stream`／`read_stream_header` 只在 `runner/evidence.py`、`CurrentContentCipher` 只到報告與 triage 的路由、`content_cipher(...)` 只由 api、worker、本機指令與 v0022 建立。換版用 `rotate`，不回傳明文。
- **import-linter**：`cryptography` 只能由 `security.secret_cipher` 與新的 `security.blob_cipher` 使用。

### 30.3 原始證據的生命週期（runs volume）

**加密由 runner 程序內的背景執行緒（keeper，`runner/keeper.py`）負責**。它有自己的 DB session，和主迴圈只共用一個健康狀態：主迴圈監看容器時（最長約 1,500 秒、單一執行緒、期間不做維護）加密照常進行，主迴圈的心跳、對帳與取消不受影響（runner 超過 30 秒沒有心跳就會被當成停擺）。每 10 秒一輪，每輪最多 30 秒、每一步最多 20 個 run。`secscan-admin runner --once` 不啟動執行緒，改成在處理之前與結束之前各同步跑一輪。

| 階段 | 誰 | 檔案狀態 | 上限 |
|---|---|---|---|
| 1. 準備 `in/` | runner | 明文（輸入不含 secret；secret 在 tmpfs 的 secrets volume，容器結束就刪） | 到第 5 階段 |
| 2. 容器執行，寫入 `out/` | 掃描容器 | 明文、沒有遮罩 | run 的時間上限 |
| 3. 收集：就地遮罩、寫 manifest | runner 主迴圈 | 明文（已遮罩已知的 secret） | 數秒 |
| 4. 等待解析、解析 | worker（唯讀） | 明文 | 平常數秒；逾期規則見下 |
| 5. 加密 | keeper | 只剩加密檔 | run 進入終止狀態、容器確認刪除之後的下一輪（約 10–20 秒） |
| 6. 清除 | keeper | 刪除整個目錄 | 加密後 7 天 |

- **待加密的條件**：run 已終止，而且沒有容器或容器已確認刪除（`container_removed_at`；`prepare_launch` 先在 DB 記下容器才呼叫 create，所以有容器的 run 一定有名稱）。之後沒有任何程序會再寫這個目錄。v0021 的 trigger 也只允許這樣的 run 新增紀錄。
- **worker 停擺或異常**（使用者要求明文不能因為 worker 等待或異常而無限期保留）：
  - 起算點是第一次進入 `collected` 的 `run.status` 事件（不用最後一次：每次重試都會再進入 `collected`，用最後一次會讓反覆失敗的解析無限期延長明文；以注入時間落在兩次 `collected` 之間的測試確認）。
  - 超過 `EVIDENCE_PLAINTEXT_MAX_MINUTES`（預設 60，範圍 15–1440）仍是 `collected`，或是 `normalizing` 而 lease 已過期 → keeper 先鎖 scan 再鎖 run（和佇列相同的順序），鎖住之後重新確認條件，轉成 `failed`（新的錯誤碼 `PARSE_DEADLINE_EXCEEDED`），同一個 transaction 重算 scan 的狀態；之後同一輪加密。狀態機加上 `collected → failed`；錯誤碼的 DB CHECK 只檢查格式，不必改 migration。
  - 有效 lease 的解析不受影響。worker 之後以舊 lease 的寫入都會被 lease 的檢查擋下；已經存好的部分結果保留，所以這個錯誤碼的意思是「解析沒有在期限內完成」，不是「沒有結果」。
  - 最壞情況：run 的時間 ＋ 60 分鐘 ＋ keeper 的一輪。例外：lease 一直有效（worker 持續心跳）的解析不受這個期限限制，長度由解析的輸入大小上限決定（安全審查的附註，§30.11）。沒有 collected 事件的舊資料以 run 建立的時間起算。
- **反覆解析失敗**：達到 `MAX_PARSE_ATTEMPTS` 後是 `failed`，隨即加密。**沒有收集的 run**（取消、逾時、中斷、OOM…）直接進入終止狀態，下一輪就把沒有遮罩的殘留加密。**runner 當掉**：重啟之後先對帳（`interrupted`），keeper 再接著加密。**runner 停機，或 Docker 無法確認容器已刪除**：沒有程序能加密，明文一直留到恢復為止（§30.9）。
- **從來沒有目錄的 run**（例如排隊中就取消、啟動之前就失敗）記為 `none`：不算失敗，也不會一直停在 `pending`。
- **probe 的目錄**：capability probe 不送請求、沒有 secret，容器確認刪除之後由主迴圈刪除整個工作目錄（以 dir fd 加 O_NOFOLLOW，不跟隨 symlink）。刪不掉時由 keeper 當成孤兒目錄處理。
- **孤兒目錄**（沒有 `scanner_runs` 紀錄的 UUID 目錄，例如 T23a 之前的 probe）：sealed/ 之外的所有條目超過 1 小時沒有變動才加密；加密檔標頭中已驗證的加密時間超過保留期限才刪除。**絕不在未加密時刪除。**

**fail-closed（使用者要求：加密失敗不能靜默略過，也不能誤報成已受保護）**：
- **runs volume 必須存在而且可寫**（§30.11）：每個操作都先開啟 runs volume 的根目錄（開不了就是錯誤），run 的目錄以根目錄的 dir fd 開啟；keeper 每一輪加密與清除之前先確認可寫。主機上執行、volume 沒有掛上時，找不到 run 的目錄不會被記成 none、到期的也不會被記成 purged。
- **先驗證才刪除**：寫進 `sealed/` 的暫存檔（`.sealing-<隨機>`，O_EXCL）→ fsync → rename → 串流解密，核對原本的路徑、大小與 sha256 → fsync `sealed/`（目錄項目落盤）→ 才刪除明文 → 全部完成之後 fsync run 的目錄。任何一步失敗都保留明文、不寫入 `run_evidence`，API 如實顯示 `pending`；加密之後 sealed/ 之外仍有條目也算失敗。以故障注入（rename、fsync、fchmod、驗證失敗或不符）與「刪除每個明文時它的加密檔已驗證過」的測試確認（EVID-02）。
- **加密失敗或 keeper 停止**：任何一個 run 失敗都繼續處理其他 run，但這一輪就不健康；任何例外都不會讓執行緒結束（非預期的例外只記類別）；失敗的 run 與孤兒退避（20 秒起倍增，最多 10 分鐘），不會每一輪重試、佔滿批次而讓其他 run 等不到加密，還在退避的仍算不健康；正常停止時保留最後一輪的結果（§30.11）。不健康、執行緒停止、停擺（三輪的時間沒有完成一輪）或換版中（拿不到 advisory lock）時，runner 以新的 `CapabilityIssue.EVIDENCE_SEALING_FAILED` 把可用的引擎設成空的，不認領新的 run（比照 guard 停擺的 `require_guard`；執行中的 run 照常完成），`GET /scanners` 與 `/scan-profiles` 顯示原因。一輪沒有任何失敗之後才恢復。`--once` 結束時 keeper 不健康就 exit 1。log 只記 run_id 與錯誤的種類，不記路徑或內容；`retention-status` 列出積壓。**例外（§30.12）**：同一個目錄連續 3 次因為深度或條目數超過上限而加密失敗，就隔離成「需要人工處理」，不再阻擋其他 run 的認領；隔離的目錄保留明文、不會被記成已加密，等待 `retry-evidence`。
- **中斷恢復**：sealed/ 中殘留的 `.sealing-*`、`.rotating-*` 是不完整的密文，直接刪除；run 目錄的 `.masking-*` 是收集時只遮罩了一部分的明文暫存檔（不是證據），也直接刪除。加密到一半的目錄可以重複執行：加密檔的名稱由原本的路徑決定，rename 之後、刪除明文之前中斷時，下一輪重做同一個檔案並取代同一個加密檔，不會多一份。
- **哪些東西會被加密**：一般檔案不論 link 數都加密（hardlink 只刪除 run 目錄中的這一個 link）；symlink 與特殊檔案不跟隨、直接刪除；完成之後刪掉空的子目錄。掃描容器和 runner 是同一個 uid，可以把 `out/` 或檔案改成 000：走訪時先補回擁有者的權限（容器已確認刪除、worker 只能唯讀，期間沒有其他程序改這棵樹；§30.11）。走訪有深度（32）與條目數（20,000）的上限，超過就 fail closed；同一個目錄連續 3 次超過上限就隔離（§30.12）。

**加密檔的格式**（`security/blob_cipher.py`）：
- 一個 run 目錄加密之後只剩 `sealed/`：每個原本的檔案各一個加密檔，檔名是原本相對路徑的 sha256（計畫第一版寫「以序號命名」；改成路徑的 sha256：一樣避免 ENAMETOOLONG，而且讓重做可以取代同一個檔案）。原本的路徑寫在已驗證的標頭中；超過 4,096 bytes 時改記 `overlong-path/<sha256>`。
- 分塊的 Fernet：第一行是格式標記（不加密），第一個 token 是標頭（context `evidence:<run_id>`、原本的路徑、加密時間與隨機的 stream id 的 JSON），之後每 1 MiB 一個 token，明文以**標頭明文的 sha256**、塊的序號與「最後一塊」旗標開頭。竄改、截斷、調換順序、重複、少了最後一塊，或把一塊、整個檔案搬到別的檔案或別的 run，都解不開。記憶體用量有上限（runner 的 `mem_limit` 是 256m）。
- 只用 Fernet 做加密與驗證；Hypothesis 的任意切塊往返、各種竄改，以及持有金鑰者偽造的標頭與塊（驗證不只靠 HMAC）都有測試（SEAL-01），`blob_cipher` 的 branch coverage 100%。

**DB（migration v0021）**：`run_evidence`（主鍵 `scanner_run_id`，以 `(scanner_run_id, scan_id)` 引用 `scanner_runs`）：`status`（none／sealed／purged）、`file_count`、`plaintext_bytes`、`sealed_at`、`purged_at`、`recorded_at`；CHECK 狀態與時間、數量一致；部分索引 `ix_run_evidence_sealed`。trigger：新增只能是 none 或 sealed，而且 run 必須已終止、容器已確認刪除；修改只允許 sealed → purged 一次，其他欄位完全不變；刪除與 TRUNCATE 一律拒絕。既有的資料不回填（升級之後 keeper 分批加密既有的 run 目錄，第一次加密時才開始計算 7 天）。downgrade：已經有 sealed 的紀錄時拒絕。

**API**：`engines[].evidence` 列出 `status`（none／pending／sealed／purged，沒有紀錄是 pending；§30.12 加上 manual_intervention_required）、`sealed_at`、`purged_at`、`hold`（§30.12）；finding 來源追溯的 artifact metadata 的 `encrypted` 改由 `run_evidence` 推導（sealed、purged 是 true），另加 `purged_at`。DB 的 `artifacts.encrypted` 不改，是從來沒有寫入過的舊欄位。

### 30.4 報告內容與人工複測摘錄（DB，CONTENT 金鑰）

- **報告**：worker 渲染、驗證之後以 context `report:<id>` 加密再寫入；`reports.sha256`、`size_bytes` 仍是明文的值。下載時 API 先檢查是否已清除（是的話回 410 `REPORT_EXPIRED`，新錯誤碼），再解密並沿用既有的 sha256 核對；解不開、屬於別的報告或不符一律回 500、不送出內容（CONT-01：把另一份報告的密文搬過來也一樣）。
- **摘錄**：triage PATCH 時 API 先核對 sha256 與長度和事件 attestation 中記下的值相符，再以 context `excerpt:<finding>:<sequence>:<kind>` 加密，期限是建立時間加 `EXCERPT_RETENTION_DAYS`。`GET triage-events` 只為 operator／admin 解密，並再核對一次雜湊與長度；解不開或不符回 500。viewer 仍是事件層級的 null；寫入者看到的每一段加上 `expires_at`、`purged_at`，清除之後 `content` 是 null（tombstone）。
- **DB（migration v0022）**：
  - `reports`：新增 `expires_at`（只在 generating → succeeded 時寫入）與 `content_purged_at`（只能寫一次，必須已到期、其他欄位都不變）；改寫 `reports_guard`。CHECK：succeeded ⇔ 有期限；清除不早於期限。
  - `reports_purge_complete`（deferred constraint trigger，§30.11）：寫入 `content_purged_at` 的 transaction 結束時，內容必須已刪除；清除時間也不能晚於現在（trigger 檢查）。部分索引 `ix_reports_expiry`、`ix_finding_triage_excerpts_expiry` 給到期清除的查詢。
  - `reports_content_check`：重建成只在轉為 succeeded 時觸發（`OLD.status IS DISTINCT FROM 'succeeded'`），只核對這一次嘗試的內容存在；明文的 sha256 改由 app 核對（內容是密文，DB 算不出明文的雜湊）。
  - `report_contents`：改用自己的 `report_contents_guard`（不再用共用的 `scan_records_guard`）：只允許換版時更新 content（其他欄位不變、報告還沒清除），以及報告寫入 `content_purged_at` 之後刪除（同一個 transaction 先寫）。內容的 CHECK 改成 Fernet token 的形狀（`gAAAAA` 開頭）與密文的上限。
  - 摘錄：`sealed_content`（bytea）取代 `content`（TEXT），加上 `expires_at` 與 `purged_at`；改用自己的 `finding_triage_excerpts_guard`：只允許換版（密文換密文）與只能一次的清除（`sealed_content` 變成 NULL、必須已到期）。不能刪除：留下 tombstone，「每個人工複測事件恰好兩筆」的規則不變。新增時的 trigger 保留事件的檢查、要求新的摘錄是密文，拿掉明文雜湊的檢查。
  - **既有資料**（同一個 transaction）：舊報告與舊摘錄的期限一律是升級時間加 30 天；舊的明文在核對 sha256 與大小之後加密（context 和 app 相同，以 API 解得開的測試確認）。只有存在舊資料時才需要 CONTENT 金鑰；缺金鑰或舊內容和 sha256 不符時以清楚的訊息停止，整個升級回滾、資料不變（CONT-02）。
  - **順序**：新增欄位、改寫 trigger 與函式 → 資料的 UPDATE（回填期間暫停 `reports_guard` 與摘錄的 guard，同一個 transaction 內恢復）→ 最後才刪除舊欄位、加上 NOT NULL、CHECK、索引與 `reports_purge_complete`。最後這幾個 ALTER TABLE 在 UPDATE 之後，所以不能有 pending 的 AFTER trigger event：新的 `reports_content_check` 對已經 succeeded 的列不觸發、外鍵欄位沒有改變、`report_contents_parent_check` 只在 INSERT 觸發、`reports_purge_complete` 在 UPDATE 之後才建立（第一版寫「所有 ALTER TABLE 都在 UPDATE 之前」不正確，資料庫審查 L2）。升級之前要停 api、worker 與 runner（0021 建立外鍵時鎖住 `scanner_runs`，`make migrate` 讓兩者在同一個 transaction 中執行；資料庫審查 L1）。
  - **金鑰的來源**：`migrations/env.py` 由設定放進 `config.attributes["content_encryption_keys"]`（呼叫端已經放了就不覆寫），測試以 `alembic_config(content_encryption_keys=…)` 注入；migration 不讀 `os.environ`。
  - **離線模式**（`--sql`）：不在 Python 中加密；產生的 SQL 先以 DO 區塊確認沒有既有的報告內容與摘錄，有就報錯（請改用線上升級）。
  - **downgrade**：先以 ACCESS EXCLUSIVE 鎖住三張資料表再檢查；還有報告內容、摘錄或清除過的報告時拒絕（舊版本只認得明文），否則還原 v0018、v0017 的 trigger、函式、CHECK 與欄位。只用於開發與測試。
  - **例外**：v0022 import `secscan.security`（加密元件），打破「migration 不 import 應用程式的程式」的慣例：在 SQL 中做 Fernet 不可行，而另寫一份加密會讓格式分裂。只 import 加密元件與金鑰的規則，context 的格式在 migration 中另寫一份，以 API 解得開的測試核對兩者一致。
- **API 的其他變更**：報告加上 `expires_at`、`content_purged_at`；每個 scan 的報告配額不計失敗與內容已清除的報告；Idempotency-Key 重送照舊回原本的 metadata（清除之後也是）。

### 30.5 保留期限與清除

| 資料 | 起算 | 預設 | 執行者 | 清除後保留 |
|---|---|---|---|---|
| run 目錄與孤兒目錄 | 加密時間（`run_evidence.sealed_at`，或加密檔標頭中已驗證的時間） | 7 天（`EVIDENCE_RETENTION_DAYS`） | keeper | artifact metadata 與 sha256、觀察、finding、比較快照、`run_evidence` |
| 報告內容 | 完成時寫入的 `expires_at` | 30 天（`REPORT_RETENTION_DAYS`） | worker 的定期步驟 | `reports` 列、sha256、audit |
| 人工複測摘錄 | 建立時寫入的 `expires_at` | 30 天（`EXCERPT_RETENTION_DAYS`） | worker 的定期步驟 | 事件中的雜湊與長度、tombstone |
| guard telemetry | 不變 | 6 小時 | guard | — |
| `benchmarks/results` | 不自動清除（T28 的研究資料） | — | 使用者 | — |

- 一次清除處理到一批不滿為止（最多 20 秒）：v0022 給既有內容同一個期限，到期時會一次積壓；清除時 DB 出錯只記類別、下一個間隔再試，解析與報告照常（資料庫審查 L8）。
- 範圍 1–365 天，可用環境變數調整。只清除內容：metadata、sha256、遮罩過的觀察、finding 與比較快照都保留。
- worker 的迴圈原本沒有計時器：比照 runner 加上 monotonic 的間隔，開始時與之後每 10 分鐘清除一次；到期以 DB 的時鐘判斷（和 trigger 的檢查相同），每批最多 50 份，以 FOR UPDATE SKIP LOCKED 認領。
- **只做邏輯清除**：刪除檔案只是 unlink，不會抹除磁碟上的資料區塊（SSD、APFS、overlay）；DB 的 dead tuple、WAL 與備份也還留著，直到 VACUUM 或備份輪替（比照 §12.3 揭露）。
- **既有資料從升級之後起算**：舊的 run 目錄在第一次加密時才開始計時；舊報告與舊摘錄由 v0022 設成升級時間加 30 天。使用者之後升級開發環境時（`make migrate`、`make up`），既有的報告與摘錄會被加密、run 目錄會分批加密，都不會一升級就刪除。
- `secscan-admin retention-status`：唯讀，列出原始證據（執行中、逾期、待加密、沒有目錄、已加密、待清除、已清除）、報告內容與摘錄（保留中、待清除、已清除）的數量，不含路徑或內容。

### 30.6 換版

- **`rotate-evidence-keys`**（在 runner 容器內執行）：逐檔串流重新加密到 `.rotating-*` 暫存檔、驗證之後才 rename；runs volume 的目錄數量超過上限或列不出來時，不截斷、不換版任何檔案並 exit 1；以 advisory lock 和 keeper 互斥（keeper 每一輪處理檔案時才持有，換版重試到拿到為止；換版期間 runner 不認領新的 run）；可以中斷後續跑；解不開的目錄保留原狀並列出 run_id、exit 1；audit 只記數量。
- **`rotate-content-keys`**（在主機上執行）：報告一份一個 transaction（密文最大約 11 MiB，避開 30 秒的 statement 上限與記憶體上限），摘錄每批 100 段（keyset 分頁）；以 FOR UPDATE 和清除互斥；已清除的略過；解不開的保留原狀並列出 id、exit 1；audit 只記數量。
- **步驟**（比照 §12.3）：新金鑰放在最前面 → 重啟持有它的容器 → 換版 → 移除舊金鑰、重啟 → 再換版一次確認全部解得開；確認之前保留舊金鑰的備份。金鑰由使用者手動編輯，`make env` 從不輪替。`rotate-secret-keys` 不變。
- **`export-evidence`**（break-glass，在 runner 容器內執行）：沒有 `--path` 時列出加密檔的原本路徑、大小與 sha256（列表也會解密驗證每個檔案，所以先寫 audit `evidence.list`；檔名由工具決定，以 ASCII 跳脫輸出）；有 `--path` 時先完整驗證、寫入 audit（記下 run_id、路徑的 sha256 與大小，寫不進去就不匯出），才把明文寫到 stdout，不寫任何檔案。

### 30.7 `benchmarks/results` 的加密（使用者，2026-11-09；更正 §29.3、§29.6）

- **金鑰檔**：預設 `~/.config/secscan/bench-keys`，可用 `BENCH_KEY_FILE` 指定，內容是 1 到 4 把 Fernet 金鑰（一行一把）。必須是一般檔案（不是 symlink）、只有擁有者可讀寫、屬於目前的使用者，而且不在 repo（含結果目錄）之中。`make bench-key` 以 O_EXCL 建立（0600、上層目錄 0700），已經存在就失敗；由使用者執行。`bench-check` 在啟動 stack 之前檢查金鑰檔。金鑰一律不輸出。單元測試只用暫存目錄中的金鑰檔，不讀預設的位置。
- **`benchmarks/sealing.py`** 是 `benchmarks/` 中唯一可以 import `cryptography` 的模組（BENCH-11 的 AST 測試改成依模組允許）；因為 `benchmarks` 不能 import `secscan`，自己包裝 Fernet，以 context `<結果目錄的名稱>/<檔名>` 綁定內容。
- **寫入**：在 `results.write_bytes` 檢查秘密（明文）之後加密，以 O_EXCL 寫成 `<檔名>.sealed`（0600）並 fsync；所有檔案（含規格與 manifest）都經過這一條路，磁碟上沒有明文、也沒有明文的暫存檔。原本的 `seal()`（寫 `SHA256SUMS`）改名為 `write_checksums()`，避免和加密混淆。
- **完整性與可重現性**：明文的 `SHA256SUMS` 列出各加密檔的 sha256，沒有金鑰也能核對；manifest 的版本升到 2，`files` 記下每個檔案明文與密文的 sha256；揭露項目把 `results_not_encrypted` 換成 `results_encrypted_with_local_bench_key` 與 `bench_key_loss_makes_results_unrecoverable`。規格的 sha256、種子與實際順序照舊記在 manifest 中，可重現性不變。
- **讀取**：`bench-evaluate` 先核對 `SHA256SUMS`，再解密、核對明文的 sha256 與 manifest，然後才評估；金鑰錯誤、遺失、檔案被截斷或竄改、改名或搬到別的結果目錄都清楚報錯，不輸出任何部分結果；結果目錄中有明文的檔案時拒絕。
- **既有的明文結果**：`make bench-seal BENCH_SOURCE=… BENCH_NAME=…` 先核對原目錄的 `SHA256SUMS`，寫到 `<名稱>.partial-<隨機值>`（O_EXCL 建立），驗證之後才 rename 成正式的名稱，所以正式名稱存在就代表完整；manifest 升到版本 2 並記下原本 manifest 的 sha256。原目錄不修改也不刪除。驗證失敗時刪掉這次產生的 partial 目錄；程序被中斷時 partial 目錄留著（名稱已標示），不自動刪除。實作時以唯讀方式確認過：目前沒有任何結果目錄（T31 的 Live smoke 還沒執行）。
- **金鑰遺失**：結果無法復原，必須另外備份金鑰檔。`benchmarks/collect.py` 只取指定的欄位，API 新增的欄位不影響它（BENCH-04）。

### 30.8 測試與驗證

- 新的測試表見 SECURITY_AND_TESTING §4：KEY-01 至 05、SEAL-01 至 02、EVID-01 至 07、CONT-01 至 02、RET-01 至 02、ROT-01、BSEAL-01 至 03；修訂 TRIAGE-06、REPORT-04（DB 改成只允許換版與到期清除，雜湊改在 app 中核對）。
- 空轉檢查（故意改壞之後必須有測試失敗，確認之後改回、不提交）：拿掉「先驗證才刪除」、容器確認刪除之前就加密、到期之前就清除、拿掉最後一塊的檢查、逾期改從最後一次 `collected` 起算、加密失敗時引擎仍然可用——六項都被測試抓到。
- 驗證的過程依使用者的要求分兩段：使用者執行 `make env` 之前，只跑不碰 `.env` 的檢查（`make lint`、`make typecheck`、在已經運作的 db-test 上直接執行 pytest），不宣稱完整的 `make test` 已通過；使用者執行之後才跑完整的 `make test`。

### 30.9 SEC-14 的剩餘風險與改善方向（使用者要求寫進 DECISIONS 與 SECURITY_AND_TESTING）

**T23a 完成也不代表 SEC-14 完成**（SEC-14 的 P0 完成條件見 §30.14）：

1. **加密時間點的限制**：run 執行、收集、等待解析期間是明文。
   - 平常是 run 的時間加上數十秒；worker 異常時最多再加 60 分鐘（`EVIDENCE_PLAINTEXT_MAX_MINUTES`）；runner 停機或 Docker 無法確認容器已刪除時，持續到恢復為止。
   - 原因：ZAP 與 Nuclei 只能寫一般檔案，而 runner 必須在容器結束之後讀取並遮罩；worker 再讀取同一份檔案解析。
   - 改善方向：主機的全碟加密（macOS 的 FileVault 涵蓋 OrbStack 的磁碟映像；Linux 用 LUKS），列為 T23b 的部署要求。未來：每個 run 一個 tmpfs 的 `out/` volume，由輔助容器讀出並加密；或讓工具的輸出流經會加密的 sidecar；或讓 worker 直接讀取加密檔（worker 需要證據的金鑰，和目前的最小權限分配衝突，需要另外取捨）。
2. **刪除只是 unlink**：資料區塊沒有抹除（SSD、APFS、overlay）。DB 的 dead tuple、WAL 與備份會保留舊的報告與摘錄，直到 VACUUM 或備份輪替。
3. **權限隔離有限**：所有服務都是 uid 10001，隔離只靠掛載；DB 只有一個角色，可以停用 trigger（v0022 的回填與測試就是這樣做的）；金鑰以 compose 的環境變數傳入，`docker inspect` 看得到。這些都屬於 T23b。
4. **掃描容器的 json-file log**：在容器刪除之前，可能保留 Nuclei 沒有遮罩的 stdout（T23b）。
5. **其他保持現狀的明文**：`observations` 保留遮罩過的證據，包含 Nuclei 擷取的 email 與卡號；guard telemetry 的路徑以明文存在 tmpfs，保留 6 小時；摘錄的雜湊沒有加 salt，留在不可變的事件中（T21 的設計）；報告與摘錄在 API 的記憶體中解密，下載的回應是明文（TLS 由部署負責）。
6. **本機研究資料**：`recordings/` 與 `runs/spike-t03/work/` 中的明文交給 T34（使用者決定之前不修改或刪除）。
7. **超過上限的單一目錄**（安全審查 M1，§30.11；使用者決定方案 B，§30.12）：掃描容器在 `out/` 建立超過深度（32）、條目數（20,000）或路徑總長度（8M 字元）上限的目錄樹時，keeper 連續 3 次失敗（約一分鐘）之後隔離這個目錄、改成需要人工處理，其他 run 恢復認領。剩下的風險：隔離的目錄**保留明文直到有人處理**；機密性隔離（§30.13：隔離的目錄搬到 `held/`，worker 只掛載 `active/`）的 Docker 實際驗證（2026-11-11）與 Live 驗收（2026-11-12）都已通過，但搬到 `held/` 之前（隔離中）worker 仍讀得到；不做全域熔斷（告警在 T35）；計數只在記憶體中（runner 重啟會重新計數，`runner --once` 永遠不會隔離）；超過 `retry-evidence` 絕對上限（深度 64、條目 50,000、路徑總長度 16M 字元）的樹不在系統內處理；孤兒目錄的解除 DB 無法確認已加密。runs volume 的目錄數量超過上限、清除失敗與其他種類的加密失敗（例如磁碟滿）仍然全域 fail closed。完整清單見 §30.12。
8. **runner 指到可寫、但不是 runs volume 的目錄**（例如主機上手動建立的空目錄）時，keeper 仍會把找不到目錄的 run 記成 none。DB 分不出「從來沒有目錄」與「目錄不見了」（容器名稱在建立工作目錄之前就寫入），所以沒有以 DB 判斷（§30.11）。
9. **金鑰在主機上**：`.env` 是唯一的設定來源，三組金鑰都在裡面（600）；bench 的金鑰檔在使用者的家目錄。金鑰遺失之後，尚未清除的證據、報告、摘錄與 bench 結果都無法復原；備份金鑰由使用者負責。

### 30.10 交接

- **T34（新增，獨立於 T23 的 DoD）**：本機研究資料的安全盤點（`recordings/`、`runs/spike-t03/work/`）：逐項列出路徑、大小、類型、是否可能含憑證或敏感資料、被哪些文件引用為證據，提出處理建議（保留、加密或刪除）由使用者決定。盤點必須讀取可能含憑證的檔案，開始之前另外授權；未經決定不修改或刪除。
- **T23b**：主機全碟加密的部署要求、compose secrets、DDL／DML 分權、掃描容器的 log driver、uid 分離、以每個 key 計的速率限制。2026-11-12 拆成 b1–b4，b1 的範圍由使用者決定（§30.14）。
- **T23c**：在最終版本重跑所有 live 套件，包含這次改成等加密完成、以 `export-evidence` 讀取原始輸出的那些。
- **T23d**：乾淨環境的重建，包含 `make env` 產生三組金鑰。
- **T27／T28**：原始證據 7 天後清除；需要人工複核原始輸出時，要在期限內進行（或事先調整 `EVIDENCE_RETENTION_DAYS`）。實驗結果以加密的 `benchmarks/results` 保存，金鑰檔要備份；T31 的 Live smoke 需要使用者先執行 `make bench-key`。

### 30.11 審查與處理（2026-11-09）

三份審查（子代理，opus），範圍是 `git diff main...HEAD`：

| 審查 | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|
| 程式碼 | 0 | 2 | 1 | 4 |
| 安全 | 0 | 1 | 2 | 6（另有一則文件附註） |
| 資料庫（v0021、v0022） | 0 | 0 | 3 | 10 |

兩個 HIGH 被程式碼與安全審查同時找到，合併處理。三份審查都確認加密格式（context 綁定、分塊的順序／截斷／拼接防護、各組金鑰的 token 不互通）、compose 的金鑰分配、路徑處理、trigger 遇到 NULL 的行為、鎖的順序，以及 CHECK 和 ORM 一致，都沒有問題。

**HIGH（都已修正，先寫會失敗的測試）**：

| 問題 | 處理 | 測試 |
|---|---|---|
| 孤兒目錄的加密檔解不開時（金鑰移除、檔案損壞），`sealed_at()` 拋出的例外沒有被攔下，keeper 的執行緒結束：runner 永遠不認領新的 run，正在跑的 run 結束之後也沒人加密，明文一直留到重啟（程式碼 HIGH-1、安全 M2） | vault 的每個操作都以 `guarded()` 把檔案系統與解密的錯誤轉成 `EvidenceError`；`run_pass` 另外攔下所有例外（只記類別、這一輪不健康），執行緒不會結束 | `test_an_unreadable_sealed_header_is_an_evidence_error`、`test_an_unexpected_error_is_a_failure_not_a_dead_thread` |
| runs volume 的根目錄不存在（在主機上執行 `runner --once`、volume 沒有掛上）時，找不到 run 的目錄被當成「從來沒有目錄」：待加密的 run 被永久記成 none、到期的記成 purged，trigger 又禁止更正，真正 volume 中的明文永遠不會加密（程式碼 HIGH-2、安全 H1） | 每個操作先開啟根目錄（開不了就是錯誤），run 的目錄以根目錄的 dir fd 開啟；keeper 每一輪加密與清除之前呼叫 `vault.check()`（根目錄存在而且可寫：沒有掛上 volume 時，runner 容器的 `/runs` 在唯讀的 rootfs 上，寫不進去） | `test_a_missing_runs_volume_is_an_error_not_a_missing_directory`（5 種操作）、`test_check_needs_a_writable_runs_volume`、`test_a_broken_runs_volume_records_nothing`、整合測試 `test_a_missing_runs_volume_records_nothing` |

HIGH 的剩餘部分：runner 指到一個可寫、但不是 runs volume 的目錄時（例如主機上手動建立的空目錄），仍會誤記成 none。安全審查建議只在 DB 能證明「從來沒有建立工作目錄」時才寫 none；但容器名稱在建立工作目錄之前就寫入，`PLAN_REJECTED`、`SECRET_UNAVAILABLE`、取消等常見情況都是「有容器名稱、沒有目錄」，DB 分不出來，所以列為剩餘風險（§30.9 第 8 項）。

**MEDIUM**：

| 問題 | 處理 |
|---|---|
| 常駐的 runner 正常停止（`make down`）時，keeper 的執行緒已結束，`healthy` 是 false：一定印出「無法加密」並以 exit 1 結束（程式碼 M1） | 要求停止之後，`healthy` 回傳最後一輪的結果；只有沒被要求停止、執行緒卻結束了才算不健康 |
| 掃描容器和 runner 是同一個 uid：`chmod 000 /scan/out`、超過深度或條目上限，都讓 keeper 對這個 run 永遠失敗、整個平台停止認領；一直失敗的 run 排在最前面（`sealable` 依結束時間排序），20 個以上時其他 run 得不到加密（安全 M1） | ① 走訪時補回擁有者的權限（目錄 rwx、檔案 r），000 不再能阻擋；② 失敗的 run 與孤兒退避（20 秒起倍增、最多 10 分鐘），`sealable`／`purgeable` 排除還在退避的 run，其他 run 照常加密；③ 還在退避的仍算不健康（不認領），保持 fail closed。**未處理**：超過深度（32）或條目數（20,000）上限的目錄仍會讓整個平台不認領，見下方的待決定事項 |
| 報告下載與到期清除同時發生：API 先讀到「沒有清除」，worker 在下一個 statement 之前 commit 清除，結果回 500，log 寫「sha256 不符」（資料庫 M1） | 「是否已清除」與內容以同一個 statement 讀取（outer join），已清除就回 410；log 分開「沒有內容」「解不開（例如換版之後沒有重啟 api）」「sha256 不符」（也處理程式碼 LOW-1） |
| DB 不保證「已寫入 `content_purged_at`」等於「內容已刪除」：只寫清除時間就 commit，API 回 410 而密文永遠留著（資料庫 M2） | v0022 新增 deferred constraint trigger `reports_purge_complete`：寫入 `content_purged_at` 的 transaction 結束時，這份報告的內容必須已刪除（v0022 還沒合併，直接修改） |
| v0022 寫死的密文上限沒有測試保護，之後一邊改了另一邊沒改，ORM 的 CHECK 會默默和 DB 不同（資料庫 M3） | 單元測試載入 v0022，核對三個常數等於 domain 由 `max_sealed_blob_bytes` 算出的值 |

**LOW**：

| 問題 | 處理 |
|---|---|
| `export-evidence` 對還沒加密的目錄回 traceback（程式碼 LOW-2） | 由 `guarded()` 一併處理；沒有 `sealed/` 時回「這個 run 還沒有加密檔」 |
| keeper 第一輪完成之前，引擎就顯示 `EVIDENCE_SEALING_FAILED`（程式碼 LOW-3） | **不處理**：啟動時 zap、nuclei 的 capability probe 要實際執行容器，比 keeper 的第一輪久，這段期間本來就是 `ENGINE_PROBE_PENDING`；只有 fake 會短暫顯示。不為此新增代碼 |
| `runner/evidence.py` 406 行、`cli/__init__.py` 從 429 行變成 441 行（程式碼 LOW-4） | 加密檔的底層操作拆到 `runner/sealed_files.py`（`evidence.py` 283 行、`sealed_files.py` 172 行）；既有的 `rotate-secret-keys` 搬到 `cli/secret_keys.py`（行為不變），獨立模組的指令由 `cli/modules.py` 註冊與分派，`cli/__init__.py` 變成 380 行 |
| 執行時沒有程序同時持有 EVIDENCE 與 CONTENT，兩者共用金鑰只有手動執行 `check-encryption-keys` 才會發現；共用時 worker 被入侵就能解開原始證據（安全 L1） | 主機上的 `.env` 三組都有：每個 admin 指令之前（`cli/modules.py`）與 `make migrate`（`migrations/keys.py`，只有 env.py import，api 不 import）都檢查三組沒有共用。格式錯誤留給各指令自己說明 |
| `entries()` 超過 20,000 個目錄時靜默截斷，換版漏掉目錄卻回報成功（安全 L2） | 超過上限就失敗；`rotate-evidence-keys` 在換版任何檔案之前就停止、exit 1。沒有用到的 `EvidenceStore.sealed_runs()` 刪除 |
| DB 沒有限制 `expires_at` 的下限，也沒有限制清除時間的上限（安全 L3、資料庫 L5） | 清除時間不能晚於現在：報告、摘錄與 `run_evidence` 的 trigger 都加上 `<= clock_timestamp()`。**期限的下限不加**：期限由 app 以 1–365 天的設定計算；DB 的下限會讓到期清除的測試只能停用 trigger 來製造過期的資料 |
| rename 之後、刪除明文之前沒有 fsync `sealed/`：主機當機時明文與密文可能都不見（安全 L4） | 每個檔案在刪除明文之前先 fsync `sealed/` |
| 列表把工具決定的檔名（控制字元、bidi）原樣印到終端；列表會解密驗證每個檔案，卻沒有 audit（安全 L5） | `ensure_ascii=True`；列表先寫 audit `evidence.list`（run_id 與檔案數） |
| bench 金鑰檔只以 lstat 檢查最後一段路徑，之後的讀取會跟隨 symlink（TOCTOU）；沒有檢查上層目錄；`--results-root` 指到 repo 之外時不在禁止清單（安全 L6） | 以 O_NOFOLLOW 開檔、對 fd 檢查類型、擁有者與權限；上層目錄必須屬於目前的使用者，而且別人不能寫入（建立時也檢查）；實際的結果目錄（與 `bench-seal` 的來源）加進禁止清單 |
| 文件寫「最壞情況：run 的時間 ＋ 60 分鐘」，但 lease 一直有效的解析不受期限限制（安全的附註） | §30.3 補上例外 |
| 升級時 `run_evidence` 的外鍵會鎖住 `scanner_runs` 直到 v0022 完成，runner 的心跳會逾時（資料庫 L1） | 文件與 migration 的說明改成升級之前停 api、worker 與 runner。不改成每個 migration 一個 transaction（影響所有 migration） |
| 文件說「所有 ALTER TABLE 都在 UPDATE 之前」，實際上最後幾個在 UPDATE 之後（資料庫 L2） | 更正說明，寫出為什麼沒有 pending event；新的 `reports_purge_complete` 在 UPDATE 之後才建立。不加 `SET CONSTRAINTS ALL IMMEDIATE`：它會影響同一個 transaction 中之後的 migration |
| downgrade 先檢查、後動作，中間沒有鎖表；v0021 降級會丟掉 purged 的紀錄，再升級之後已清除的 run 會被記成「從來沒有目錄」（資料庫 L3） | 兩個 downgrade 都先以 ACCESS EXCLUSIVE 鎖表；v0021 有 sealed 或 purged 的紀錄時都拒絕 |
| `report_contents_guard` 逐欄比較，之後新增的欄位換版時可以任意修改（資料庫 L4） | 改成 `to_jsonb(NEW) - 'content' = to_jsonb(OLD) - 'content'` |
| keeper 的逾期處理會等 run 的列鎖（worker 還在寫入時最多 5 秒），等不到就讓這一輪不健康（資料庫 L6） | run 的鎖以 SKIP LOCKED 取得，拿不到就留到下一輪，不算失敗 |
| advisory lock：unlock 失敗會蓋掉原本的例外；持有期間沒有確認鎖還在；不相容 PgBouncer 的 transaction pooling（資料庫 L7） | unlock 失敗時讓連線失效（關閉連線就會釋放鎖），不蓋掉原本的例外；說明寫明不支援 transaction pooling。**不處理**持有期間的確認：鎖靜默消失時，因為「先驗證才刪除」，結果只會是誤報失敗、不會遺失明文 |
| 清除每 10 分鐘只處理一批；清除時的 DB 錯誤讓 worker 結束（資料庫 L8） | 見 §30.5 |
| 逾期查詢用不到部分索引；到期清除沒有索引；沒有 collected 事件的 run 永遠不逾期（資料庫 L9） | 查詢加上 `lease_owner IS NOT NULL`；新增 `ix_reports_expiry`、`ix_finding_triage_excerpts_expiry`；沒有 collected 事件時以 run 建立的時間起算 |
| `record()` 先查再新增（資料庫 L10） | 改成 `INSERT … ON CONFLICT DO NOTHING RETURNING` |

**使用者的決定（2026-11-09）**：單一 run 可以讓整個平台停止認領（安全 M1 未處理的部分，§30.9 第 7 項）。可選的方向是 A（維持全域 fail closed，由操作者手動處理那個目錄）與 B（同一個 run 失敗 N 次之後轉成明確的「需要人工處理」狀態，不再阻擋其他 run 的認領）。使用者選擇 **B**，並給了五個實作條件；實作見 §30.12（狀態放在新的 `evidence_holds`，不是 `run_evidence`）。

### 30.12 超過上限的單一目錄改成「需要人工處理」（方案 B；使用者，2026-11-09）

**使用者的條件**（原文）：
1. N = 3 次：同一個 run 因目錄深度超過 32 或條目超過 20,000 而連續加密失敗 3 次，就進入 manual_intervention_required 狀態。
2. Fail-closed：該 run 的未加密證據不得透過正常 API 提供，也不得被當成成功完成。
3. 故障隔離：keeper 跳過被隔離的 run，其他正常 run 繼續認領。
4. 可觀測性：新增 Migration 與 API 欄位，並在 retention-status 顯示待人工處理數量、錯誤代碼及狀態。
5. 人工復原：必須有明確、可稽核的處置與重新嘗試機制，不可自動把異常 run 標成成功或直接刪除未封存證據。

**觸發與計數**（條件 1）：
- 只有三種資源上限會隔離，各有獨立的錯誤代碼（retention-status 分開統計）：`EVIDENCE_TREE_TOO_DEEP`（深度超過 32）、`EVIDENCE_TREE_TOO_MANY_ENTRIES`（條目超過 20,000）與 `EVIDENCE_TREE_PATHS_TOO_LONG`（所有相對路徑的總長度超過 8M 字元；使用者 2026-11-10 加入，見下方「使用者的決定」）。三者共用同一個連續的計數，記下的是最後一次的原因。`runner/fs.py` 第一次超過上限就停止走訪（不繼續累積記憶體）並拋出 `TreeLimitError`（記下是哪一個上限），`sealed_files.guarded()` 轉成帶錯誤代碼的 `EvidenceLimitError`。runs volume 的目錄數量超過上限是整個 volume 的問題，維持一般的 `EvidenceError`（全域 fail closed）。
- 「連續」：keeper 在記憶體中記下每個目錄連續的上限失敗（`runner/backoff.py`）：上限失敗加一、其他種類的失敗歸零、成功就清除。退避的間隔不變（20 秒起倍增），三次失敗大約在 T、T+20 秒、T+60 秒。隔離之前照舊不健康、不認領。
- 計數的步驟：run 的加密，以及孤兒目錄的檢查與加密（不納入的話，一個孤兒目錄仍會讓整個平台停止認領）。**清除不計數**：已加密的目錄在清除時超過上限，代表被改過或環境有問題，維持全域 fail closed。
- 計數只在記憶體中，和退避相同：runner 重啟會重新計數（只會延後隔離，不會提早）；`runner --once` 每次都是新的程序、最多兩輪，所以永遠不會隔離，照舊以 exit 1 結束。
- N = 3 是常數 `HOLD_AFTER_FAILURES`（`scans/domain/evidence.py`），不做成設定。

**隔離之後**（條件 2、3）：
- keeper 在同一個 transaction 中新增 `evidence_holds` 一列，並寫 audit `evidence.hold`（actor 是 null；錯誤代碼、次數、run 或孤兒；run 的 audit 帶 project）。寫入成功之後這個目錄不再算退避中：第 3 次失敗的那一輪仍算失敗，下一輪恢復健康，`EVIDENCE_SEALING_FAILED` 消失，runner 恢復認領。寫入失敗（DB 錯誤或 trigger 拒絕）時算失敗、保留計數，下一次失敗時再寫一次；寫入成功之前維持 fail closed。log 是 ERROR，只有目錄名稱與錯誤代碼。
- keeper 跳過隔離的目錄：`sealable` 在 SQL 中排除隔離的 run（runner 重啟之後也不會再試）；孤兒目錄以分批查詢跳過。keeper 不會自動重試、加密、清除或刪除隔離的目錄；明文保留原狀。
- 隔離的 run 不會有 `run_evidence`，所以不會被記成 none、sealed 或 purged；DB 雙向強制：新增隔離時還沒有 `run_evidence`；新增 `run_evidence` 時（commit 時檢查）沒有還沒解除的隔離；解除時已有 sealed 的 `run_evidence`。API 顯示 `manual_intervention_required`，artifact 的 `encrypted` 照舊由 `run_evidence` 推導（false）。一般 API 本來就不提供原始輸出（T21 已移除下載）；`export-evidence` 只輸出加密檔，隔離的目錄沒有加密檔。

**DB（migration v0023）**：`evidence_holds`（主鍵 `directory`，就是目錄名稱）：`scanner_run_id`、`scan_id`（只有 run 的目錄有，以 `(scanner_run_id, scan_id)` 引用 `scanner_runs`）、`error_code`、`attempts`、`held_at`、`resolved_at`。5 個 CHECK（run 的兩個欄位同時有或同時沒有、`scanner_run_id = directory`、錯誤代碼的清單、次數至少 1、解除不早於隔離）；部分索引 `ix_evidence_holds_active`。trigger `evidence_holds_guard`：新增時還沒解除，run 必須已終止、容器已確認刪除、還沒有 `run_evidence`，孤兒目錄不能是已知的 run；修改只允許 `resolved_at` 寫入一次（其他欄位以 `to_jsonb` 比對不變），run 必須已有 sealed 的 `run_evidence`；`held_at` 與 `resolved_at` 一律由 trigger 以 `clock_timestamp()` 寫入，不採用用戶端的值；刪除與 TRUNCATE 一律拒絕。反方向：`run_evidence` 加上 deferred constraint trigger `run_evidence_hold_check`，commit 時這個 run 還有沒解除的隔離就拒絕（`retry-evidence` 在同一個 transaction 中先寫入 sealed 的紀錄、再解除，commit 時已解除）；新增隔離與新增 `run_evidence` 都先取得以 run 為鍵的交易層級 advisory lock（兩個 int4 的鍵，和 keeper 的 bigint 鍵不重疊），兩者不會同時 commit 而都看不到對方。downgrade 依讀取端的順序鎖住 `scanner_runs`、`run_evidence`、`evidence_holds`，有任何紀錄就拒絕。`run_evidence` 的欄位、CHECK 與 v0021 的 trigger 都不變；v0022 不變。升級時同樣先停 api、worker 與 runner（外鍵鎖住 `scanner_runs`）。

**API 與 retention-status**（條件 4）：
- `engines[].evidence.status` 依序判斷：有還沒解除的隔離是 `manual_intervention_required`（fail closed 的顯示：DB 不允許兩者並存，萬一出現也不顯示成已加密）；否則有 `run_evidence` 用它的狀態；都沒有是 `pending`。新欄位 `engines[].evidence.hold`：從來沒有隔離是 null，否則是 `{error_code, attempts, held_at, resolved_at}`，解除之後保留。
- `retention-status` 新增一段：需要人工處理的 run 與孤兒目錄數量、各錯誤代碼的數量、已人工處理的數量，以及最多 10 筆最早的隔離（目錄名稱、run 或孤兒、錯誤代碼、次數、隔離時間；不含路徑或內容）。「已終止但未加密」不再包含隔離的 run。仍是唯讀、exit 0。
- `GET /scanners` 不變：隔離之後引擎恢復可用。

**人工復原：`secscan-admin retry-evidence`**（條件 5；在 runner 容器內執行）：
- `--directory <目錄名稱> --reason <理由> [--max-depth 32 到 64] [--max-entries 20,000 到 50,000] [--max-path-chars 8M 到 16M 字元]`。目錄名稱必須是標準 UUID；理由必填（單行、最多 200 字），寫進 audit。
- 和 keeper 以同一個 advisory lock 互斥（等鎖的迴圈和 `rotate-evidence-keys` 共用）。流程：沒有還沒解除的隔離就 exit 1、不做任何改變 → 先寫 audit `evidence.retry`（上限與理由），寫不進去就不開始 → 以指定的上限加密（同一條「先驗證才刪除」的路徑）→ 成功時在同一個 transaction 寫入 sealed 的 `run_evidence`（只有 run 的目錄）、`resolved_at` 與 audit `evidence.resolve`，之後照常保留 7 天再清除 → 失敗時（仍然超過上限、其他錯誤、目錄不存在）寫 audit `evidence.retry_failed`，隔離不變、明文保留原狀、exit 1；目錄不存在不會記成 none。加密完成、DB 寫入失敗時提示再執行一次（加密可以重複執行）。
- **上限的上限**：整棵樹會列在記憶體中，而 `docker compose exec` 起的程序和 runner 共用容器的記憶體上限（256m）。只限條目數不夠：每個條目存完整的相對路徑，很長的路徑（例如 64 層、每層 255 字元）會讓 50,000 個條目需要數百 MB（安全審查 M1；計畫中「約多 20 MB」的估計只適用於短路徑）。所以 `TreeLimits` 另外限制所有相對路徑的總長度：keeper 是 8M 字元（ASCII 約 8 MB、最壞每個字元 4 bytes 約 32 MB），`retry-evidence` 最多 16M 字元（最壞約 64 MB），這是絕對的上限。更大的樹不在系統內處理，由操作者另外決定，系統不會刪除它。
- **刻意不提供**：不加密就解除隔離的指令、刪除目錄的指令，以及 API 的復原端點（復原需要 runs volume 與證據金鑰，只有 runner 有；§30.2 的權限邊界）。

**連帶修正：大型加密目錄的清除**：以較高的上限加密的目錄，`sealed/` 可能超過 20,000 個檔案，`remove_tree` 會把它們算進條目上限、清除永遠失敗，又變成全域阻擋。`EvidenceVault.purge` 改成先逐一刪除 `sealed/` 中的條目，再以一般的上限刪除其餘部分。可以這樣做是因為 `sealed/` 只由 runner 寫入而且是平的（掃描容器只掛 `in/` 與 `out/`）；其中有子目錄代表被改過，刪除失敗、fail closed。

**為什麼這樣設計**：
- 另開 `evidence_holds`，不在 `run_evidence` 加狀態：v0021 的 trigger 與「沒有紀錄就是 pending」的語意不變，孤兒目錄（沒有 `scanner_runs`）也能隔離，而且「已加密」與「需要人工處理」不會出現在同一個欄位而被誤讀成成功。
- 退避的計算拆到 `runner/backoff.py`（keeper 維持在 400 行以內）；退避的次方加上上限，長時間的故障不會讓浮點數溢位。
- 分成三個 commit 的計畫改成兩個程式的 commit（功能、審查的修正）加一個文件：新的 CLI 模組依賴 `cli/evidence.py` 的修改，分開提交會讓 pre-commit 的 mypy 在中間的 commit 失敗。

**測試**：EVID-08、EVID-09（SECURITY_AND_TESTING §4）：單元測試 `test_backoff`、`test_keeper_holds`、`test_fs`、`test_evidence_vault`、`test_evidence_hold`；整合測試 `test_evidence_holds`（真的 DB 與檔案，以較小的 `TreeLimits` 製造超過上限）、`test_evidence_retry`（指令、audit、retention-status）、`test_migrations`。`keeper`、`backoff`、`evidence_holds`、`sealed_files`、`fs`、`cli/evidence_holds` 的 branch coverage 都在 94% 以上。空轉檢查（故意改壞之後必須有測試失敗，確認之後改回、不提交）七項都被抓到：`sealable` 不排除隔離、第 2 次就隔離、其他種類的失敗也計入連續次數、隔離之後仍算退避中、trigger 不要求 sealed 的 `run_evidence` 就允許解除、`retry-evidence` 加密失敗也解除、清除不先刪除 `sealed/`。

**審查與處理（2026-11-10）**：三份審查（子代理，opus），範圍是 `git diff 3f6a01d 3eb1e83`：

| 審查 | CRITICAL | HIGH | MEDIUM | LOW |
|---|---|---|---|---|
| 程式碼 | 0 | 0 | 1 | 1 |
| 安全 | 0 | 0 | 2 | 5 |
| 資料庫（v0023） | 0 | 0 | 2 | 6 |

| 問題 | 處理 |
|---|---|
| 隔離已 commit、keeper 卻收到錯誤（回應之前連線中斷）時，退避項目永遠不會清除：這個目錄之後被 SQL 或 `held()` 排除、不再處理，keeper 一直不健康到重啟（程式碼 M1、安全 L2） | 每一輪持有鎖時，先依 DB 清掉退避中、已經隔離的目錄。測試：替身先寫入再拋出錯誤，下一輪恢復健康 |
| 「隔離的 run 不會有 `run_evidence`」只在新增隔離時強制，反方向靠 advisory lock 與 `sealable`；兩邊的 EXISTS 看不到對方還沒 commit 的列（資料庫 M1、安全 L3） | `run_evidence_hold_check`（deferred constraint trigger）與以 run 為鍵的交易鎖（見上方 DB 一段）；顯示改成還沒解除的隔離優先 |
| trigger 的 `to_jsonb` 分支與其他幾個分支沒有測試（資料庫 M2） | 補上：解除時同時改其他欄位、只改 `held_at`、以 none 解除、容器還沒確認刪除、外鍵的 scan 不符、併發（`lock_timeout` 確認會等）、時間由 DB 決定 |
| 記憶體只看條目數，很長的路徑讓 runner 或 `retry-evidence` 超過 256m（安全 M1） | 路徑總長度的上限（上方「上限的上限」）；使用者決定它也是可隔離的上限（上方「使用者的決定」）。**不處理**：改用父節點索引的樹、逐一目錄串流加密、以獨立容器執行 `retry-evidence`（較大的重構，留待之後） |
| 隔離幾乎代表掃描器被攻陷，但隔離之後自動恢復認領、沒有熔斷；超過 `retry-evidence` 上限的樹讓明文永久留下，worker 以唯讀掛載 runs volume 仍讀得到；每次掃描都可能多一個隔離目錄（安全 M2） | 使用者決定（上方）：不做全域熔斷，告警另做（T35）；worker 讀得到隔離中的明文是安全驗收的阻擋條件。操作指引：看到隔離時應當成疑似入侵調查 |
| 隔離那一次的 log 先說「N 秒後重試」又說「不再自動重試」（程式碼 L1） | 到了門檻時只記隔離的結果；孤兒目錄的 log 改稱「目錄」 |
| `resolve` 對 run 的 `HoldNotActiveError` 到不了，會撞上 `run_evidence` 的主鍵而誤報成 DB 錯誤（資料庫 L1） | 先以 `FOR UPDATE` 鎖住還沒解除的隔離；第二次解除得到 `HoldNotActiveError`，有測試 |
| 加密之後 DB 寫入失敗時沒有結果的 audit（安全 L1） | 另外寫 `evidence.retry_failed`（`EVIDENCE_SEALED_NOT_RECORDED`、檔案數與 bytes）；寫不進去時在 stderr 說明。程序被 OOM kill 時仍可能只有 `evidence.retry` |
| 時間由用戶端提供，稽核時間可以回溯（資料庫 L6） | `held_at`、`resolved_at` 由 trigger 以 `clock_timestamp()` 寫入 |
| downgrade 刪除帶外鍵的資料表也要鎖 `scanner_runs`，和讀取端的順序相反（資料庫 L3） | 依讀取端的順序一次鎖住三張表；降級前同樣先停服務 |
| 外鍵沒有索引（資料庫 L4） | **不加**：`scanner_runs` 的刪除與身分欄位的修改都被它自己的 trigger 拒絕，參照端的檢查不會執行；寫在 migration 的說明 |
| CHECK 的錯誤代碼清單不在 autogenerate 的比對範圍（資料庫 L5） | 測試直接比對 `pg_get_constraintdef` 與 `EvidenceHoldCode` |
| `--reason` 中孤立的 surrogate 會讓寫 audit 時拋出未處理的例外（安全 L4） | 開始之前就拒絕無法以 UTF-8 表示的理由 |
| 主鍵是 directory：解除之後的孤兒目錄被人放回超過上限的明文時，第二次隔離會撞主鍵、keeper 一直不健康（資料庫 L2） | **不處理**：只有竄改才會發生，結果是 fail closed；列入剩餘風險 |
| 解除之後的大型孤兒目錄，每一輪都重新驗證全部加密檔的標頭（安全 L5） | **不處理**：既有的行為，只是檔案變多；列入剩餘風險 |
| retention-status 的兩段數量不是同一個快照（資料庫的附註） | 不處理（唯讀的報告，差一兩筆） |

**使用者決定之後的空轉檢查**（三項都被抓到）：路徑總長度不是可隔離的上限、DB 的 CHECK 沒有第三個代碼、`retry-evidence` 不使用指定的路徑上限。

**審查之後的空轉檢查**（十項都被抓到）：`run_evidence` 不檢查隔離、檢查不取得交易鎖、採用用戶端的 `resolved_at`、採用用戶端的 `held_at`、不檢查其他欄位不變、`run_evidence` 優先於隔離、理由不檢查 UTF-8、加密後 DB 失敗不寫結果的 audit、`resolve` 不先鎖住隔離、路徑總長度不限制；另外 keeper 不依 DB 清掉已隔離的退避項目也被抓到。

**使用者的決定（2026-11-10）**：使用者把方案 B 判定為「功能實作基本達標，但尚未通過最終驗收」，並決定審查留下的三個問題：

| 問題 | 決定 | 時程 |
|---|---|---|
| 1. 自動熔斷 | T23a **不加入全域自動熔斷**，維持條件 3 的故障隔離。理由：目錄過深、條目過多不一定代表掃描器被攻陷，也可能是異常輸入或合法但超出預期的輸出；少數異常目錄就讓整個系統停止，反而形成新的 DoS 攻擊面。之後另做：第一次隔離就產生安全告警；例如 15 分鐘內 3 個不同目錄被隔離時升級成高優先級告警，但不自動停機（門檻是初始建議，依實際執行量調整）；「有範圍的熔斷」針對異常的 scanner、worker 或來源停止認領，而不是停止整個 keeper | 後續任務（TASKS 的 T35） |
| 2. 路徑總長度超過上限 | 和深度、條目數一樣是可隔離的資源上限，沿用連續 3 次的規則，不影響其他 run。條件：第一次超過就停止這個目錄的處理、不繼續累積記憶體；連續 3 次才寫入隔離；隔離之前不得被記成 sealed 或 purged；人工重試可以用較高的上限，但有絕對的上限；三種原因各有錯誤代碼 | 開 PR 之前修正（已完成，見上方） |
| 3. 隔離目錄的權限 | 必須讓 worker 讀不到隔離中的明文，而且不能只依賴 chmod（Docker 的 `:ro` 只禁止修改、不禁止讀取；有相關 capability 的程序可以繞過一般的檔案權限）。優先以**掛載範圍**隔離：隔離時把目錄移到只有 keeper 與授權的復原程序能存取、不在 worker 掛載範圍內的位置；要驗證搬移與 DB 狀態轉換的一致性、失敗復原與既有的檔案描述符；隔離也無法撤銷 worker 在隔離之前已經讀到的內容 | **安全驗收的阻擋條件**：可以拆成另一個 PR，但在完成之前不能宣稱風險已消失 |

所以目前的 DB 隔離是**工作流程的隔離，不是檔案的機密性隔離**：worker 以唯讀掛載整個 runs volume，被攻陷的 worker 讀得到隔離中的明文（執行中與等待解析的明文也一樣）。

**機密性隔離的做法（使用者，2026-11-10；另開 PR，細部計畫另外核准）**：
- **做法 A**：runs volume 分成 `active/` 與 `held/`。worker 只以子路徑掛載 `active/`，不得掛載 volume 的根目錄。隔離時在同一個檔案系統內以原子的 rename 移到 `held/`。不採用另一個 volume（跨掛載不能 rename，只能複製，不是原子操作，而且被隔離的樹本來就大）。
- **DB 與檔案系統的一致性**：不能出現「DB 已記成隔離完成、目錄卻仍在 `active/`」的情況。要有隔離的中間狀態、原子 rename、重啟之後的對帳，以及完整的 crash recovery 測試。
- **權限邊界**：檢查 symlink、hard link、已開啟的檔案描述符，以及 runner／keeper 的權限邊界。
- **人工復原**：仍須先完成加密與驗證才能解除隔離。
- **故障隔離**：目錄搬移失敗不得讓其他健康的 run 停止運作。
- **既有資料**：開發 volume 根目錄中既有的 run 目錄，由使用者在升級時手動執行管理員指令搬到 `active/`；**不允許 runner 啟動時自動搬移**。這個指令必須：
  - 可以重複執行，有 dry-run、audit、路徑驗證與中斷復原。
  - 只搬移符合預期的 UUID 目錄，不處理不認得的檔案。
  - 在服務停止、DB migration 完成之後執行。
  - 搬移沒有完成時，必須阻止相關服務以新的目錄結構啟動。
- **PR 的安排**：
  - 目前的 PR（方案 B 與路徑總長度）在使用者執行 `make env`、完整的離線檢查通過之後合併。
  - 機密性隔離另開 PR：active/held、worker 的掛載隔離、DB 與檔案系統的一致性、重啟對帳與 crash recovery。
  - 目前的 PR 合併不代表機密性隔離已經完成：**在新 PR 驗收之前，禁止把沒有這項防護的功能正式部署**。T23a 與 SEC-14 都不得提前標成完成。
  - 不得為了加快合併而降低 fail closed、安全審查或測試的標準。

**剩餘風險**（也寫在 §30.9 第 7 項）：
- **隔離的目錄在完成掛載範圍的隔離之前，worker 仍讀得到**（使用者決定的安全驗收阻擋條件）。§30.13 完成了離線實作，Docker 的實際驗證也已通過（2026-11-11，獨立的測試環境）；Live 通過之前，這一項仍是阻擋條件。
  - **註（2026-11-12）**：上面是當時的敘述，保留作為紀錄。
    - Live 也已通過，這項阻擋條件解除（§30.13 的「Live 驗收」、§30.14）。
    - 隔離完成之前（隔離中），worker 仍讀得到：見 §30.13 的剩餘風險 5、6。
- 隔離的目錄保留明文直到有人處理；看到隔離時應當成疑似入侵調查（安全 M2）。T23a 不做全域熔斷，告警在 T35。
- 計數只在記憶體中：重啟會重新計數，`runner --once` 永遠不會隔離。
- 超過 `retry-evidence` 的絕對上限（深度 64、條目 50,000、路徑總長度 16M 字元）的樹不在系統內處理，明文一直留著。
- 目錄在系統之外被刪除時，隔離紀錄一直留著（刻意不提供不加密就解除的方式）。
- 孤兒目錄的解除 DB 無法確認已加密，由程式保證。
- 一個目錄一生只能隔離一次：解除之後的孤兒目錄被竄改、再次超過上限時，keeper 一直不健康（fail closed）。
- 解除之後的大型孤兒目錄在保留期限內，每一輪都要重新驗證全部加密檔的標頭。
- `retry-evidence` 被 OOM kill 時只留下 `evidence.retry`。
- 所有服務共用同一個 DB 角色，能停用 trigger（T23b）。
- runs volume 的目錄數量超過上限、清除失敗與其他種類的加密失敗（例如磁碟滿）仍然全域 fail closed。

**不做**：自動重試、可調整的 N、API 的復原端點。

### 30.13 隔離目錄的機密性隔離（做法 A；使用者，2026-11-10 決定、2026-11-11 核准計畫）

**範圍**：§30.12 的阻擋條件。隔離的目錄搬到 runs volume 的 `held/`，worker 只以 subpath 唯讀掛載 `active/`；DB 與檔案系統一致、能從當機復原；既有資料由管理員指令搬移。計畫經過兩次審查（第一次六處、第二次四處），使用者核准之後實作。離線實作之後，Docker 的實際驗證在 2026-11-11 以獨立、可拋棄的測試環境完成（見下方「Docker 實際驗證」），發現的 F1–F3 在 2026-11-12 修正。Live 驗收在 2026-11-12 通過（見下方「Live 驗收」）；T23a 依 §30.14 標示完成，SEC-14 仍不標完成。

**layout 與掛載**：

```
runs volume 的根目錄
├── .layout            一般檔案，內容剛好是 {"layout": 2}
├── active/<run_id>/   一般的 run 目錄（原本在根目錄）
└── held/<目錄名稱>/    隔離的目錄（明文，或解除中的加密檔）
```

| 程序 | 掛載 | 權限 |
|---|---|---|
| runner（keeper 與 runner 容器內的管理指令） | 根目錄 | 讀寫 |
| `runs-init`（一次性服務） | 根目錄 | 讀寫 |
| worker | subpath `active` | 唯讀 |
| 掃描容器 | `active/<run>/in`（唯讀）、`active/<run>/out` | 不變 |
| api、guard、socket-proxy | 不掛載 | — |

`active/` 與 `held/` 的權限是 0700（多一層防護：所有服務目前共用 uid 10001）。`vault.check()` 每一輪重新檢查 layout 與兩個區域可以寫入；runner 啟動時也檢查，不通過就不啟動。

**狀態與不變條件**（v0024：`isolated_at`、`releasing_at`、`move_failures`、`last_move_error`、`last_move_failed_at`、`source_ino`）：

| 階段 | 欄位 | 目錄的位置 |
|---|---|---|
| 隔離中（isolating） | `isolated_at` 是 NULL | 搬移完成之前在 `active/`（worker 可能讀得到） |
| 已隔離（isolated） | `isolated_at` 有值 | 只在 `held/` |
| 解除中（releasing） | `releasing_at` 有值 | `held/` 或 `active/`，只有已驗證的加密檔 |
| 已解除（resolved） | `resolved_at` 有值 | `active/`，照常 7 天後清除 |

- I1：已隔離 ⇒ 不在 `active/`。I2：解除中 ⇒ 在 `active/` 時只有已驗證的加密檔。I3：隔離中是唯一允許明文留在 `active/` 的未解除狀態，一律看得見並計時。
- trigger 只允許五種轉換：0 記錄來源 inode（v0024 之前的紀錄）、1 記錄搬移失敗、2 隔離完成（必須有 inode）、3 開始解除、4 解除（必須已開始解除，run 必須有 sealed 的 `run_evidence`）。時間一律由 DB 寫入；9 個 CHECK 是第二道防線（`EXPECTED_CHECK_COUNT` 206 → 215）。既有的資料不回填。

**keeper 的隔離與對帳**（`runner/isolation.py`、`runner/hold_moves.py`）：
- 第 3 次上限失敗：lstat 取得 inode → 新增隔離紀錄（含 `source_ino`）→ 確認沒有有效的解析 lease → 以 dir fd rename 到 `held/`（lstat、inode 比對、目的地必須不存在）→ fsync 兩個區域 → 確認 inode 與裝置 → 寫入 `isolated_at` 與 audit `evidence.isolated`。新增之後同一輪再對帳一次。
- 每一輪在加密之前對帳所有還沒解除的紀錄（表見計畫與 `runner/isolation.py` 的說明）：隔離中的紀錄先處理、分頁到全部完成，已隔離與解除中的紀錄不會擋住它們（審查 M1）。補寫 `isolated_at` 之前一定先確認身分（真的目錄、和 `held/` 在同一個裝置、inode 等於 `source_ino`）並 fsync（第二次審查第 3 點）。違反 I1、I2 就搬回 `held/`、寫 ERROR 與 audit `evidence.reisolated`。對帳絕不自動解除、不記成 none、sealed 或 purged，也不刪除目錄。
- 搬移失敗只讓這個目錄退避（獨立的退避，keeper 維持健康），失敗寫進 DB（四個代碼：`EVIDENCE_HOLD_MOVE_FAILED`、`EVIDENCE_HOLD_CONFLICT`、`EVIDENCE_HOLD_NOT_DIRECTORY`、`EVIDENCE_HOLD_DIRECTORY_MISSING`），retention-status 看得見。
- **緊急門檻**（第二次審查第 4 點）：隔離中超過 `ISOLATION_URGENT_AFTER`（15 分鐘，常數）就升級為緊急狀態：每一輪直接查 DB 找出逾時的隔離中紀錄（不依賴對帳的批次與時間），CRITICAL log、audit `evidence.isolation_overdue`（每個程序對每個目錄一次），retention-status 列為「需要緊急處理」。**這個版本只記錄與升級；主動告警留待 T35 完成**，不宣稱已經具備隔離異常的告警能力。
- `seal`、`purge`、`export-evidence` 在 `active/` 找不到、卻在 `held/` 中的目錄：一律失敗（fail closed）。held/ 的條目超過 20,000 個也全域 fail closed。

**人工復原**（`retry-evidence`）：隔離中 exit 1（`EVIDENCE_HOLD_NOT_ISOLATED`），位置和紀錄不符 exit 1（交給對帳），都不做任何改變。之後：寫 audit → 在 `held/` 加密 → 確認只有加密檔並逐一解密驗證 → 寫 `releasing_at` 與 audit `evidence.release` → 搬回 `active/` → 在 `active/` 再驗證（不通過就搬回 `held/`）→ 寫入 sealed 的 `run_evidence` 與 `resolved_at`。每個中斷點再執行一次就從正確的步驟繼續；明文只會在 `held/`。`rotate-evidence-keys` 也處理 `held/` 中的加密檔。

**既有資料**（`make runs-layout-migrate [DRY_RUN=1]`，由使用者執行）：
- 主機端：以和 `make up` 相同的設定（`APP_COMPOSE`，不覆寫環境變數、不加 `-p`）執行 `config runs-init --format json`，由 `cli/runs_volume.py` 取出 project name 與 `volumes.runs.name`；解析失敗就拒絕，不退回預設名稱（第二次審查第 1 點）。volume 的 compose 標籤必須是這個 project 的 `runs`；api、worker、runner 沒有在執行；沒有任何容器（含已停止的）使用它；任何 docker 指令失敗都視為無法確認。
- 容器內（`compose run --rm --no-deps runner`）：`RUNNER_RUNS_VOLUME` 等於 `--expect-volume`、runs 目錄是掛載點、DB 在 head、拿得到 advisory lock、沒有 lease 有效的 run、沒有容器還沒確認刪除的 run。其中名稱的比對只擋得住「沒有經過 make target 而直接執行、傳入不同名稱」的情況：compose 的 `RUNNER_RUNS_VOLUME` 與 `volumes.runs.name` 是同一個運算式，經 make target 執行時必然相等；掛載點的檢查也不能證明掛上的是哪個 volume。**真正確認 volume 身分的是主機端的 compose 標籤**（安全審查 LOW-4）。
- 搬移：只處理根目錄下標準 UUID 名稱的真實目錄；有還沒解除的隔離紀錄就搬到 `held/`（先記下 inode），其他的經暫存目錄 `.active-migrating` 搬到 `active/`；其他條目不動。有衝突就不完成 layout。可以重跑；dry-run 不寫任何東西。audit：`runs_layout.migrate`、`runs_layout.migrated`（失敗時 `runs_layout.migrate_failed`）。
- **啟動的阻擋**：`runs-init` 是獨立、最小的服務（不使用 `x-app`；沒有環境變數、金鑰與網路，只掛載 runs volume；`restart: "no"`），根目錄是空的就建立結構，否則有 `.layout` 也重新檢查全部條件（第一次審查第 6 點、第二次審查第 2 點）；runner 與 worker 依賴它成功結束。只有搬移指令以 `--no-deps` 略過它。

**open FD 與 hard link**（第一次審查第 2 點；Docker 驗證的 F3 補充）：
- `rename`、`chmod` 與 uid 分離都不會撤銷其他程序已開啟的 FD；只有持有 FD 的程序關閉它或結束才會。Docker 驗證在 worker 內刻意於隔離之前開啟並保留 FD，確認：
  - **檔案 FD**：rename 之後仍讀得到明文；以路徑重新開啟是 ENOENT。
  - **目錄 FD**：可以走訪並讀取整個搬走的目錄，**包含隔離之後才新增的檔案**。目前的設計中，隔離之後只有 `retry-evidence` 寫入這個目錄，寫入的是加密檔；明文仍是隔離之前就在的那些，直到 `retry-evidence` 驗證之後刪除。
  - **`..` 的逃逸被擋下**：經由目錄 FD 走 `..`（例如 `../../.layout`）是 ENOENT。目錄已經搬出 worker 的 subpath 掛載，核心不允許經由它往上走，所以碰不到 `held/` 中的其他目錄與 `.layout`。
  - **經由 `/proc/<pid>/fd` 借用**：同一個容器內、同一個 uid 的其他程序，可以經由 `/proc/<持有者的 pid>/fd/<n>` 開啟同一個目錄並讀取，包含隔離之後新增的檔案。下列條件同時成立才做得到：
    1. 和持有者在同一個 PID namespace，也就是同一個 worker 容器。api、runner 與掃描容器雖然也是 uid 10001，但 PID namespace 不同，看不到 worker 的程序。
    2. 同一個 uid，或有 `CAP_SYS_PTRACE`（所有服務都已 `cap_drop: ALL`）。
    3. 持有者是 dumpable（Python 程序預設是）。
    4. 持有者還沒關閉 FD，也還沒結束。

    uid 分離（T23b）擋不住同一個容器內的這種借用。
  - 重啟 worker 之後，持有者結束，FD 與 `/proc` 的借用都消失；`held/` 仍然看不到。
- **這次的做法**：隔離之前確認沒有有效的解析 lease；worker 只在解析期間開檔，成功與錯誤路徑都關閉（有測試）；runbook：出現新的隔離紀錄或懷疑 worker 異常時，重啟 worker。被攻陷的 worker 在隔離之前開檔並保留 FD，系統無法自動偵測或撤銷。
- **風險分級：LOW（增量）**（2026-11-12 依 Docker 驗證重新確認）：
  - 利用的前提是 worker 在隔離之前就已被攻陷，例如經由解析不可信的工具輸出。
  - 這時 worker 本來就讀得到同一份明文，可以直接複製；FD 只是延長存取的時間。之後新增的內容只有加密檔，也碰不到其他隔離的目錄。
  - 隔離之後才被攻陷的 worker 拿不到 FD。
  - 絕對的影響是一個 run 目錄的原始證據對被攻陷的 worker 外洩，和隔離之前相同。
  - 下列情況要重新評估分級：日後有任何流程在隔離之後把明文寫進 `held/<目錄>`；或解析改成長時間持有 FD。
- **完整的 FD 撤銷**列為 T23b 的獨立項目（和 uid 分離分開），驗收標準寫在 `TASKS.md` 的 T23b。
- **hard link**：跨掛載點的 `link(2)` 會得到 EXDEV；Docker 驗證確認，同一個檔案系統、不同掛載點也是 EXDEV。程式不使用 `os.link`（AST 測試）。

**`held/` 不被覆寫**（第一次審查第 4 點）：目的地的事前檢查是緩解措施，不是原子保證（Linux 的 rename 會取代空目錄；非空的目的地讓 rename 失敗，既有的證據不會被覆寫）。真正的保證是只有持有 advisory lock 的 runner 寫 `held/`（AST 測試確認只有 runner 的模組與 runner 容器內的指令提到 `held`；部署測試確認其他服務都無法掛載根目錄）。`renameat2(RENAME_NOREPLACE)` 列為日後的選項。

**三個決策**：
1. 計畫：有條件核准，兩次審查的修正都已納入。
2. `docker compose config`：只執行受限的語法檢查 `COMPOSE_DISABLE_ENV_FILE=1 docker compose -f compose.yaml --profile app config --no-interpolate --no-env-resolution --quiet`（不讀 `.env`、不替換變數、不輸出內容）；不能證明掛載隔離有效。
3. Docker 的實際驗證：另外授權，是必要的安全驗收（2026-11-11 完成，結果見下方「Docker 實際驗證」）。項目：worker 的 `/runs` 看不到 `held/` 與 `.layout`；隔離之後 worker 讀不到；`/scan/in` 到 `/scan/out` 的 hard link 是 EXDEV；open FD 的三種情境（正常、刻意保留、重啟之後）；`make up` 與 Live 的啟動指令會執行 `runs-init`、舊 layout 時 runner 與 worker 不啟動、`up -d --wait` 能處理成功結束的一次性服務；`runs-init` 的實際容器設定（`docker inspect`）；以非預設的名稱與 project 實際執行搬移指令的檢查（`config --format json` 的格式、compose 的標籤）。

**驗收標準**（第二次審查；全部通過才算機密性隔離驗收完成）：

| # | 項目 | 離線（這個 PR） | 之後（另外授權） |
|---|---|---|---|
| 1 | worker 只掛載 `active/` | 部署測試 | Docker 驗證：通過（2026-11-11，`held/` 非空）；Live：通過（2026-11-12，`held/` 為空） |
| 2 | DB 狀態與檔案位置相符 | 對帳表的每一列、I1–I3 | — |
| 3 | 人工復原之前完成加密與完整性驗證 | `retry-evidence` 的每一步與中斷表 | — |
| 4 | crash recovery 涵蓋 DB、rename 與 fsync 的中斷點 | 七個中斷點、對帳的身分驗證 | — |
| 5 | 搬移工具確認實際 runs volume 的身分 | 假的 `docker` 執行 make target | Docker 驗證：通過（2026-11-11） |
| 6 | `runs-init` 沒有繼承金鑰、環境設定與掛載 | 合併之後的設定逐項測試；以真的 compose 解析（F1 之後） | Docker 驗證：通過（2026-11-11） |
| 7 | 搬移失敗保留明文並揭露，其他 run 不受影響 | 單元與整合測試 | — |
| 8 | 超過 15 分鐘升級為緊急事件 | 只到升級（主動告警是 T35） | T35 |
| 9 | Docker 實際驗證掛載、hard link 與 FD | — | Docker 驗證：通過（2026-11-11；FD 的結果見剩餘風險 1） |
| 10 | Live 通過之前不把 T23a、SEC-14 標成完成 | 文件與 TASKS 維持未完成 | Live：通過（2026-11-12）；T23a 依 §30.14 標示完成，SEC-14 仍未完成 |

**Docker 實際驗證**（2026-11-11；使用者授權，限定在獨立、可拋棄的測試環境）：
- **隔離的做法**：
  - 獨立的 compose project `secscan-t23av`。`compose.yaml` 固定了 volume 與外部網路的名稱，只加 `-p` 會接到開發用的資源，所以測試 env 把 5 個具名 volume、2 個外部網路、映像 tag 與 port 都改成測試名稱；秘密都是新產生的測試值。
  - compose 以清空的環境、指定的 env 檔執行。建立或刪除任何資源之前，先以 `config --format json` 確認每個名稱都是測試資源，也確認秘密都來自測試的 env 檔。
  - migration 在測試容器內執行，只連測試 DB；`make runs-layout-migrate` 以 `-o env` 執行，不改 `.env`。
  - 結束時 `down -v`，並刪除測試網路與映像。前後的 Docker 快照逐行相同，`.env` 沒有改變。

| # | 項目 | 結果 | 證據 |
|---|---|---|---|
| 1 | worker 只掛載 `active/` | PASS | <ul><li>掛載是 `subpath=active`、唯讀；`/runs/..` 是容器自己的 `/`，看不到 `held/` 與 `.layout`。</li><li>以 keeper 的真實流程隔離深度 35 的目錄：第 3 次失敗之後搬到 `held/`，`isolated_at` 有值，inode 前後相同；之後 worker 在整個檔案系統都找不到它。</li><li>把根目錄掛給 worker 時，worker 以 exit 1 拒絕啟動。</li></ul> |
| 2 | hard link 跨掛載點 | PASS | 掃描容器形狀的 `in/` 連到 `out/` 是 EXDEV（兩邊都可寫也是）；同一個掛載點的對照組成功；worker 從 `/runs` 連到 `/tmp` 是 EXDEV |
| 3 | 搬移前後的 open FD | PASS（和剩餘風險 1 相符） | 見上方「open FD 與 hard link」 |
| 4 | `runs-init` 的實際容器 | PASS | 環境變數只有映像預設的 7 個；`NetworkMode` 是 none；只掛載 runs volume；唯讀 rootfs、`CapDrop` 是 ALL、重啟政策是 no、uid 10001。有 `.layout` 但根目錄仍有 UUID 目錄時 exit 1 |
| 5 | `config --format json`、volume 的標籤與名稱解析 | PASS；發現 F1 | 自訂名稱的 volume 也有兩個 compose 標籤。搬移指令以真的 Docker 執行：api 還在執行、已停止的容器仍使用 volume、project 改名，三種情況都拒絕；`DRY_RUN=1` 不改變任何東西；實際搬移完成並寫 audit；重跑不做任何事 |
| 6 | `up -d --wait` 與啟動順序 | PASS；措辭 F2 | 舊 layout：回傳 1，runs-init exit 1，runner 與 worker 從未啟動。新 layout：回傳 0，順序是 runs-init 結束 → worker → runner |
| 加測 | `retry-evidence`、retention-status | PASS | 在 `held/` 加密、搬回 `active/`，DB 依序寫入解除中與已解除；之後 worker 只看得到加密檔 |

- **發現與處理**（2026-11-12，使用者核准方案 (a)）：
  - **F1（LOW）**：`config runs-init --format json` 的輸出含有 `DB_PASSWORD`。compose 即使只查詢一個服務，也會輸出全部頂層的 `x-*`，而且是替換變數之後的值；`DB_PASSWORD` 原本在 `x-app-env`。make target 只把輸出放在 shell 變數、以 pipe 交給本機的解析程式，不會印出或寫進 log，實際的暴露很小，但「輸出不含金鑰」的說法不正確。
    - 處理：`DB_PASSWORD` 移到 api、runner、worker 各自的 `environment`，`x-app-env` 只留不含秘密的連線設定；三個服務的 DB 連線設定不變。
    - 回歸測試 `tests/unit/test_compose_secrets.py`：
      - 靜態檢查：頂層的區段都不引用秘密，每個服務只在 `environment` 中引用自己需要的秘密。
      - 以真的 `docker compose`、暫存的 project directory 與虛構的秘密解析：`config runs-init` 的輸出不含任何秘密，每個服務只拿到自己的秘密。這個測試不讀 `.env`，也不連 daemon。
      - 在修正之前的 compose 上，這個測試有 3 項失敗。
  - **F2（措辭）**：subpath `active` 不存在時，worker 容器可能成功建立，但無法啟動（直接 `docker start` 是 exit 128），不是「無法建立」。保護的效果相同，平常由 `runs-init` 先擋下；已修正 compose.yaml 的註解。
  - **F3（剩餘風險 1 的補充）**：目錄 FD 看得到之後新增的檔案；同 uid 的程序可以經由 `/proc/<pid>/fd` 借用。已寫進上方「open FD 與 hard link」與剩餘風險 1，T23b 加上 FD 撤銷的驗收標準。
- **觀察**（既有的設計，不是這次的修改）：
  - 舊 layout 時 `up -d --wait` 回傳 1，但 db、api、guard、socket-proxy 已經啟動並留著；搬移指令會要求先 `make down`，和 README 的升級順序一致。
  - 超過上限的目錄在隔離之前，keeper 不健康，runner 約 1 分鐘不認領新的 run（PR #35 的設計）。
  - 驗證期間 Mac 用電池進入睡眠，Docker 停止回應約 20 分鐘；接上電源之後恢復。沒有重啟 OrbStack，不影響結果。

**Live 驗收**（2026-11-12；使用者授權，只限 T23a 驗收所需的操作）：
- **前提**：
  - **版本**：main `c5988fe`（PR #36 的 merge commit）。
  - **環境**：Makefile 的 Live 專案 `secscan-live`，有自己的 volume、網路與 DB。migration 只在 Live 自己全新的 DB 上執行，沒有碰開發環境。
  - **電源**：開始時是電池，接上 AC 之後才啟動 Live。
  - **證據**：放在 gitignore 的 `recordings/t23a-live/`，摘要與每個檔案的 sha256 在 `SUMMARY.md`。

| 項目 | 結果 |
|---|---|
| `make test`（使用者，同一個 commit） | 7,586 passed、2 skipped、78 deselected，coverage 98.74% |
| `make lint`、`make typecheck` | 都 exit 0 |
| `make test-live-fixture-findings` | 3 passed（23 分 19 秒） |
| `make test-live-fixture-rescan` | 1 passed（31 分 45 秒）。unchanged 與 patched 的 new、not_observed 都是 0；小預算的比較是 different，需要人工檢視 |
| 測試內建的證據斷言 | <ul><li>每個 scan：worker 的 `/runs` 沒有 `held`、`.layout`、`active`；API 只有 `sealed` 或 `none`；run 目錄只剩密文，沒有 target 的明文。</li><li>只有 findings：以 runner 容器內的 `export-evidence` 解密，sha256 與大小等於 API 的 artifact。</li></ul> |
| worker 的獨立檢查（每項 Live 3 次） | <ul><li>掛載是 subpath `active`、唯讀：`HostConfig.Mounts` 與 mountinfo 都確認。</li><li>`/runs/held`、`/held`、`/runs/../held`、`/runs/.layout` 都是 ENOENT；在整個檔案系統都找不到 `held` 與 `.layout`。</li><li>worker 的 `/runs` 和 runner 的 `/runs/active` 相同。</li><li>對照組：runner 看得到 `.layout`、`active`、`held`。</li></ul> |
| 清除 | <ul><li>沒有 Live 的殘留；`.env` 是 600、401 bytes，沒有改變。</li><li>映像 ID 改變，只是因為 containerd 映像存放區每次 build 都產生新的 attestation manifest；config digest 不變。</li></ul> |

**11/12 Live 的限制**：
- 這兩項 Live 不會產生隔離，`held/` 都是空的。**11/12 的 Live 沒有驗證非空 `held/` 的存取隔離。**
- 也不能在驗收的 Live 中放入資料：runner 會把沒有 DB 紀錄的目錄記成 ERROR `EVIDENCE_HELD_UNKNOWN`，干擾驗收結果。

**互補的證據**（使用者 2026-11-12 同意以兩次驗證互補，條件見 §30.14）：

| | 2026-11-11 Docker 驗證 | 2026-11-12 Live |
|---|---|---|
| 版本 | `c974cce`：build 前後的 `git status` 都沒有追蹤中的修改；`.dockerignore` 只放入 `pyproject.toml`、`uv.lock`、`src/`、`deploy/guard/` | `c5988fe` |
| 環境 | 獨立的 project `secscan-t23av`；測試的 volume、網路、映像 tag 與秘密；以 repo 的 `compose.yaml` 加上測試 env 檔執行 | project `secscan-live`（Makefile 的 Live 隔離） |
| `held/` | 非空：keeper 以真實流程隔離的目錄 | 空 |
| 範圍 | 掛載、隔離之後 worker 讀不到、hard link、open FD、`runs-init`、`up --wait`、搬移指令 | 真實掃描（ZAP、Nuclei）的端到端、加密與證據斷言、worker 的掛載與負向存取 |
| 限制 | <ul><li>隔離的是 runner 在 `active/` 建立的孤兒目錄（深度 35，內容是 canary），不是真實掃描的證據。</li><li>隔離之前開啟的 FD 仍讀得到（剩餘風險 1）。</li></ul> | `held/` 中沒有隔離的資料 |

**11/11 非空 `held/` 的紀錄**：原始的指令與輸出保存在 `recordings/t23a-live/20261111-held-negative-access.txt`，從當天工作階段的紀錄擷取，沒有修改；runner 的 log 在 `20261111-t23av/`。
1. runner 在 `active/` 建立深度 35 的孤兒目錄，內容是 canary。
2. keeper 連續 3 次 `EVIDENCE_TREE_TOO_DEEP`。
3. 14:11:55Z，`evidence_holds` 寫入 `held_at`、`isolated_at` 與 `source_ino` 850708；audit 是 `evidence.hold`、`evidence.isolated`。
4. runner 看到 `/runs/held/<目錄>`：inode 是 850708，讀得到 canary。
5. worker：
   - `ls /runs` 只剩另外兩個目錄；
   - `ls /runs/<目錄>` 是 ENOENT；
   - `find / -xdev -name <目錄>` 沒有結果。
6. retention-status 顯示「已隔離 1」。

**版本等價**（`git diff c974cce c5988fe`）：
- 有修改的部分：
  - `compose.yaml`：`DB_PASSWORD` 從 `x-app-env` 移到 api、runner、worker 各自的 `environment`（F1），加上註解（F2）。掛載、uid、唯讀、capability 與網路都不變。
  - `src/`：只有 `cli/runs_volume.py` 的 docstring。
  - 測試與文件。
- 沒有修改：Dockerfile、`deploy/`、Makefile、`pyproject.toml`、`uv.lock`、migrations。
- 11/11 解析之後的 worker 設定，和 11/12 Live 實際的 worker 相同：
  - subpath `active` 唯讀、`guard_telemetry` 唯讀；
  - uid 10001、唯讀 rootfs、`cap_drop ALL`；
  - 只接 `control_net`。

**開發環境**（2026-11-12 唯讀檢查）：
- **做法**：把 volume 唯讀掛進一次性容器（沒有網路、`cap_drop ALL`），在 tmpfs 的複本上以 single-user 模式查詢。原本的 volume 沒有寫入，也沒有建立新的 volume。
- **結果**：
  - DB 的 `alembic_version` 是 `0024`（head）；
  - runs volume 的 `.layout` 是 layout 2，`active/` 與 `held/` 都是空的。
- **沒有可靠的 migration 執行紀錄**，所以不記載執行過 `make migrate`。

**剩餘風險**：
1. open FD（LOW，增量；細節見上方「open FD 與 hard link」）：
   - 被攻陷的 worker 在隔離之前保留的檔案 FD 或目錄 FD 無法自動撤銷；rename 之後仍讀得到明文。
   - 目錄 FD 也看得到隔離之後新增的檔案（目前只有加密檔）。
   - 同一個 worker 容器內、同 uid 的程序可以經由 `/proc/<pid>/fd` 借用這些 FD。
   - `..` 的逃逸被核心擋下。
   - 目前只能重啟 worker（T23b-b3：完整的 FD 撤銷，不可省略，§30.14）。
2. 所有服務共用 uid 10001（T23b-b3：uid 分離，不可省略，§30.14）。
3. 主機與 Docker 的管理者讀得到 volume。
4. `held/` 中的目錄保留明文，直到有人執行 `retry-evidence`（worker 讀不到）。
5. 隔離之前的空檔：連續 3 次失敗約 1 分鐘，這段時間目錄在 `active/`；隔離中正常在同一輪（新增之後再對帳一次）或下一輪（約 10 秒）完成，這一輪的時間預算用完時留到下一輪。
6. 搬移持續失敗時明文一直留在 `active/`、worker 讀得到；看得見（API、retention-status、audit），15 分鐘後升級為緊急狀態，但主動告警留待 T35，在那之前要有人執行 retention-status 或查看 log 才會發現，也不會自動阻擋其他 run。處置程序與接受標準（提議）見 §30.14 的「PR #37 審查意見的處理」。
7. hard link 的檢查依賴掛載的邊界。
8. `held/` 不被覆寫的保證依賴「只有一個可信的寫入者」：事前檢查與 rename 之間不是原子的，空的目的地會被 rename 取代（裡面沒有資料）。
9. 主機的容器檢查與搬移之間不是原子的；volume 的身分只依賴主機端的 compose 標籤（容器內的名稱比對在 make target 下必然成立），有 Docker 權限的人可以改寫標籤。日後可以在容器內比對 `/proc/self/mountinfo`（需要 Docker 驗證確認格式）。
10. Docker 驗證的範圍有兩項沒有涵蓋：
    - **`make up` 本身沒有直接執行**：它會先執行改寫 `.env` 的 `make env`，而且指向開發 project。改在測試 project 上執行相同的 compose 指令，確認 `runs-init` 在實際啟動指令下的行為。
    - **runner 實際產生的掃描容器設定沒有在 Docker 上執行**：這次沒有執行掃描（Live 另外授權）。hard link 改用相同掛載形狀的容器驗證。
    - 2026-11-12 的 Live 以 runner 實際產生的掃描容器跑完真實的掃描，加密與證據的斷言都通過；但 hard link 的 EXDEV 只在 11/11 以相同掛載形狀的容器驗證過。`make up` 本身仍然沒有由開發代理執行。

11. 降級：v0024 的 downgrade 在有隔離紀錄或 layout 搬移的 audit 時拒絕；但 `runs-init` 建立的新 volume 不寫 DB、偵測不到。降級之前要先把 `active/` 的目錄搬回根目錄、刪除 `.layout`，否則舊程式會把找不到的目錄記成「沒有目錄」（資料庫審查 M1）。
12. **搬移的前提會和啟動的阻擋互相卡住**（資料庫審查 M2）：runner 異常結束（OOM、Mac 睡眠讓 OrbStack 停止回應、kill -9）時，可能留下容器還沒確認刪除的 run；搬移指令依核准的前提拒絕，而新版的 runner 在舊的 layout 上不會啟動、無法對帳。使用者 2026-11-11 決定**維持原本的前提**，不放寬；無法安全對帳時不刪除紀錄、不略過檢查，明確報錯並提供人工修復的程序（README 與下方）。驗證（`tests/integration/test_runs_layout_recovery.py`）：
   - 對帳的程式（`ContainerReconciler`）新版與舊版相同，只依 DB 的容器名稱與 Docker 的 label 判斷，和 runs volume 的 layout 無關：label 相符才刪除、刪除之後才結算；404 才算不存在；同名但 label 不符的容器不動；Docker 不可用時不結算。所以新版的 runner 在 layout 搬移之後能安全對帳舊版留下的 run，但搬移之前不會啟動。
   - OOM／kill -9（lease 還有效）、lease 過期、容器還在、容器已刪除、Docker 不可用：搬移都正確地拒絕或在對帳之後完成。
   - 原本寫的脫困方式（切回舊版執行 `make up`）在 `make migrate` 之後**不可行**：舊版的 runner 只接受 0023 的 schema。修正後的程序要先降回 0023（這時一定沒有 v0024 的資料，降級會成功；被拒絕就停止）。
   - `make up`／`make down` 的實際執行需要 Docker，屬於另外授權的驗證（決策 3）；離線只以假的 `docker` 驗證 make target 的檢查。
   - 日後的選項（需要使用者決定）：新版提供只做容器對帳的指令（以 socket-proxy 存取 Docker、不碰 runs volume、不認領 run），就不必切回舊版與降級。



**審查與處理**（2026-11-11，opus，審查未 commit 的 diff；三份都沒有 CRITICAL 或 HIGH）：

| 意見 | 處理 |
|---|---|
| 程式碼 M1、安全 MEDIUM-1：對帳只取最舊的 500 筆，已隔離的紀錄累積之後，新的隔離中紀錄排不到、也不會升級（共用 DB 角色時，被攻陷的 worker 可以插入假紀錄放大這個問題） | 隔離中的紀錄先處理、分頁到全部完成；緊急升級改成每一輪直接查 DB。加上「超過一頁的已隔離紀錄不會擋住隔離中的紀錄」的測試 |
| 程式碼 M2：換版先處理完 `active/` 才列出 `held/`，`held/` 列不出來時回報「沒有換版任何檔案」卻已換了一部分 | 兩個區域都先列出，才開始換版；加測試 |
| 資料庫 M1：已經搬到新的 layout、沒有隔離紀錄時，降級擋不住 | 降級也檢查 `runs_layout.*` 的 audit；`runs-init` 建立的 volume 偵測不到，寫進剩餘風險 11 |
| 資料庫 M2：搬移的前提和啟動的阻擋互相卡住 | 使用者決定維持前提；lease 與未確認刪除的容器分開回報，訊息指向 README 的人工修復程序（先降回 0023、以舊版對帳）；OOM、kill -9、lease 過期、容器已刪除與 Docker 不可用的測試；寫進剩餘風險 12 |
| 安全 LOW-1：worker 沒有在執行時確認自己只看得到 `active/` | worker 啟動時以 lstat 確認看不到 `held/` 與 `.layout`，否則不啟動；加測試 |
| 安全 LOW-2：「只有加密檔」不檢查 `sealed/` 中點開頭的條目 | `require_sealed_only`：`sealed/` 只能有 64 個十六進位字元名稱的一般檔案；`retry-evidence` 搬回前後都用它 |
| 程式碼 L3、安全 LOW-3：`HoldMoves.move` 沒有用到目的地參數 | 來源與目的地相同時拒絕，方向由兩個參數決定；加測試 |
| 安全 LOW-4：容器內的 volume 比對是同義反覆 | 修正文件的說法（真正的身分檢查是主機端的標籤）；mountinfo 的比對列為日後的選項 |
| 程式碼 L1：搬移收尾時一筆身分不符就整個中止；UUID 名稱、但不是目錄的條目會造成無法完成的迴圈 | 身分不符的紀錄不寫入、繼續其他的（交給 keeper 的對帳）；這類條目在計畫階段就列為阻擋、不做任何改變；加測試 |
| 程式碼 L2：重新隔離的 audit 寫入失敗之後不會補寫 | 留到下一輪再寫；加測試 |
| 程式碼 L4：held/ 寫入者的靜態檢查沒涵蓋 `for … in Area` | 檢查加上區域的走訪，白名單加上 vault、換版與 worker 的自我檢查（只讀） |
| 資料庫 L1：統計查詢用不到部分索引 | 還沒解除的條件移到 WHERE |
| 資料庫 L2：測試缺口 | 補上：搬移失敗的時間由 DB 決定、no-op 更新被拒絕、降級之後的函式和 0023 完全相同 |
| 資料庫 L3：共用的 DB 角色可以停用 trigger | 既有的限制，已列在 T23b |

**修正之後的空轉檢查**：18 項重新執行，全部被抓到。

**runner 異常結束之後的人工修復**（OOM、kill -9、Mac 睡眠讓 OrbStack 停止回應之後，`make runs-layout-migrate` 回報「容器還沒確認刪除」時）：搬移指令不刪紀錄、不略過檢查，必須先讓 runner 對帳（Docker 確認容器已刪除，或刪除這個 run 的容器，才結算）。新版的 runner 在舊的 layout 上不會啟動，而舊版的 runner 只接受 0023 的 schema，所以：
1. `make down`。
2. `uv run alembic downgrade 0023`：只有沒有 v0024 的隔離資料、也沒有執行過 layout 搬移時才會成功（搬移指令在寫入任何東西之前就拒絕，所以這時會成功）；被拒絕就停止，改為人工確認，不要強制降級。
3. 切回升級之前的版本（例如 `git switch --detach 61a5cd3`），先確認沒有排隊中的 scan（舊版的 runner 會認領它們），再 `make up`；runner 啟動時就對帳，log 出現「容器已確認不存在：已結算」。Docker 不可用時不會結算，先修復 Docker。
4. `make down`，切回新的版本，`make migrate`，再執行 `make runs-layout-migrate DRY_RUN=1`：它會再檢查一次；仍有未確認的容器就重複第 1 到 4 步。
5. `make runs-layout-migrate`，`make up`。

### 30.14 T23a 的驗收結論與之後的決定（使用者，2026-11-12）

**T23a 標示完成的依據**（由文件 PR 提議，使用者審查合併之後生效）：

使用者要求正式結案之前要符合三點：
1. 兩項既定的 Live 完整通過。
2. worker 的 `active/` 掛載要實際驗證。
3. 對 `held/` 中實際存在的隔離資料，另外要有負向存取的證據。

1、2 由 2026-11-12 的 Live 驗收滿足（§30.13 的「Live 驗收」）。

3 的處理：使用者同意以 2026-11-11 的 Docker 驗證與 2026-11-12 的 Live 互補，條件有四項：
- 兩次的版本、掛載與權限設定可證明等價；
- 11/11 的 `held/` 確實有 keeper 以真實流程隔離的資料，而且 worker 的負向存取有明確的結果紀錄；
- 文件區分兩次驗證的日期、版本、環境、範圍與限制；
- 不宣稱 11/12 的 Live 驗證了非空 `held/` 的存取隔離。

四項都已在 §30.13 確認並記錄：版本等價、11/11 的紀錄、兩次驗證的對照表、11/12 Live 的限制。

離線的部分：使用者在同一個 commit 執行的完整 `make test`，以及 2026-11-12 的 `make lint`、`make typecheck`。

**T23a 完成不代表**：
- SEC-14 完成；
- 不是全程靜態加密（§30.9）；
- §30.13 的剩餘風險都還在：open FD、共用 uid、隔離之前的空檔等。

**SEC-14 的 P0 完成條件**（使用者，2026-11-12）：
- **前提**：T23a、T23b 的 b1–b3、T23c 都完成。
- **洩漏路徑**：除了程式的修改與 Live canary 通過，還要驗證機密不會經由下列路徑洩漏：
  - 一般 API；
  - 日誌；
  - 報告；
  - 未授權的證據存取路徑。
- **剩餘風險**：所有剩餘風險都要明確記錄、界定適用範圍，並經使用者確認接受。
- **範圍**：Schemathesis 的安全驗收延到 M6。SEC-14 的 P0 通過，不代表全部範圍都已完成。

**T23b-b1 的範圍**（使用者，2026-11-12）：只做 DDL／DML 分權。服務級的 DB 角色是 b3 之後的另一個子項目。要求如下：

1. **驗證權限確實被撤銷**：
   - `secscan_app` 不能執行 `ALTER TABLE`、`DROP TABLE`、`ALTER TRIGGER` 或其他未授權的結構操作。
   - 也要檢查能不能經由物件擁有權、繼承的角色或特殊函式繞過。
2. **migration 使用獨立的憑證**：`secscan_owner` 不長期提供給 api、worker、runner。
3. **分權之後重新測試 T23a 的安全不變條件**：`active/`／`held/` 隔離所依賴的 trigger 與 DB 約束仍然正常運作。
4. **記錄剩餘風險**：三個服務仍共用 `secscan_app`。一個服務被入侵時，仍可能存取其他服務能存取的資料；DDL／DML 分權不是完整的服務級隔離。

PostgreSQL 的物件擁有者有特殊權限，不能只靠 `REVOKE` 就認定隔離完成。目前 `secscan_app` 擁有資料庫與所有物件（所以能停用 trigger），細部計畫要處理擁有權的移轉。

**PR #37 審查意見的處理**（使用者，2026-11-12）：

1. **過期的敘述**：
   - 下列地方「Live 通過之前／完成之前 T23a 不標完成」的敘述保留作為當時的紀錄，加註已由 2026-11-12 的驗收結果取代：
     - TASKS 的 T23a；
     - §30.12 的剩餘風險；
     - ARCHITECTURE。
   - 仍然有效的部分照舊：不宣稱風險已消失、SEC-14 不標完成。
2. **本機證據的核對**（合併之前，2026-11-12）：
   - 原始紀錄在 gitignore 的 `recordings/`，不提交：其中有掃描的錄製與服務的 log。所以 GitHub 上看不到。

   | 對象 | 方式 | 結果 |
   |---|---|---|
   | SUMMARY.md 列出的 12 個檔案 | `shasum -a 256 -c` | 全部 OK |
   | 全部證據：<ul><li>SUMMARY.md 本身；</li><li>之後加入、SUMMARY.md 沒有列出的檔案（`docker-before-rescan.txt`、11/11 的摘錄與四個檔案）；</li><li>兩個錄製目錄。</li></ul> | 新建完整的清單 `recordings/t23a-live/MANIFEST.sha256`（36 個檔案），再以 `shasum -c` 核對 | <ul><li>全部 OK；</li><li>清單本身的 sha256 是 `afdd409c6a4fc72fcb277efd3209eb9afc049d690d2dda164cb3467a1ea8aa47`。</li></ul> |
   | 11/11 的四個檔案（`20261111-t23av/`） | 和 scratchpad 的原檔比對 | 逐位元組相同 |
   | 11/11 的摘錄（`20261111-held-negative-access.txt`） | 以同一個擷取程式，從工作階段的 transcript 重新擷取 | 23 筆，逐位元組相同 |

   - **重新核對**：`cd recordings && shasum -a 256 -c t23a-live/MANIFEST.sha256`。
   - **限制**：
     - sha256 只證明檔案在建立清單之後沒有改變，不證明內容是真實的輸出；後者依賴紀錄本身（指令、時間、結束碼）。
     - scratchpad（`/private/tmp`）與 transcript 之後可能被清除；需要的內容已保存在 `recordings/t23a-live/`。
3. **隔離之前的風險要繼續追蹤**（不要求 T23a 重做）：
   - **T23b-b3 不可省略**：
     - 兩項都是 SEC-14 P0 的必要條件，不能以接受剩餘風險取代：
       - 完整的 FD 撤銷：§30.13 的剩餘風險 1，隔離之前開啟的 FD 仍讀得到明文；
       - uid 分離：剩餘風險 2。
     - FD 撤銷的驗收標準見 TASKS。
   - **搬移持續失敗**（§30.13 的剩餘風險 6：明文一直留在 `active/`，worker 讀得到）：
     - **已有，有測試**（§30.13 驗收表的第 7、8 項）：
       - 搬移失敗時保留明文並揭露：API 的 `hold.stage`、retention-status、DB 的失敗代碼；其他 run 不受影響。
       - 隔離中超過 15 分鐘就升級：CRITICAL log、audit `evidence.isolation_overdue`，retention-status 列為「需要緊急處理」。
     - **還沒有**：
       - 主動告警（T35）；
       - 書面的人工處置程序：`retry-evidence` 在隔離中一律拒絕（exit 1），目前沒有任何處置的步驟；
       - 接受標準。
     - **處置程序**（提議；T23c 寫進 README，以 Docker 驗證之後才算數）：
       1. 看到隔離中的目錄，就當成疑似入侵調查（§30.12 的安全 M2）。
       2. 停止 worker。
          - 能讀 `active/` 的程序中，不可信的只有 worker：runner 是唯一可信的寫入者，`runs-init` 只在啟動時執行，掃描容器只掛載自己那個 run 的目錄。
          - 停止之後，worker 讀不到明文，原本持有的 FD 也隨程序結束。
          - 代價是解析與報告暫停。
       3. 依 DB 的失敗代碼調查原因：`EVIDENCE_HOLD_MOVE_FAILED`、`EVIDENCE_HOLD_CONFLICT`、`EVIDENCE_HOLD_NOT_DIRECTORY`、`EVIDENCE_HOLD_DIRECTORY_MISSING`。不使用任何不加密就解除或刪除目錄的方式（系統刻意不提供）。
       4. 確認隔離完成之後，才重新啟動 worker：`isolated_at` 有值，retention-status 不再列出。
     - **接受標準**（提議；SEC-14 的 P0 驗收時，由使用者確認是否接受）：
       1. **看得見**：每個隔離中的目錄都出現在 API、retention-status 與 audit，超過 15 分鐘一定升級。已有測試。
       2. **處置可行**：上面的程序寫進 README，並在 Docker 上以故障注入驗證：
          - 停止 worker 之後，它的程序與 FD 都已結束；
          - 其他 run 不受影響；
          - 原因排除之後，keeper 完成隔離；
          - 沒有任何步驟會不加密就解除或刪除目錄。
       3. **發現的時限**（由使用者二選一）：
          - (a) SEC-14 的 P0 之前完成 T35 的主動告警；
          - (b) 接受「發現依賴人工執行 retention-status」，並明訂檢查的時機，例如每次 Live 或部署的前後。
       4. **適用範圍**：只適用於 lab、單一操作者的環境。提議正式部署之前一定要有主動告警（T35）。

**順序**：T23a 的文件 PR 合併之後，才撰寫 T23b-b1 的細部計畫；核准之前不實作。

## 31. T23b-b1：DDL／DML 分權（2026-11-12 計畫核准、實作）

### 31.1 決定的來源

- **2026-11-12**（§30.14）：b1 只做 DDL／DML 分權，有四項要求：
  1. 撤銷驗證，含繞過的途徑；
  2. migration 使用獨立的憑證；
  3. 分權之後重測 T23a；
  4. 記錄剩餘風險。
- **細部計畫第一輪**（使用者）：
  - 只能新增的表只給 SELECT、INSERT；
  - 其他表依實際業務需求授權，不為了方便開放 CRUD；
  - 保留既有的 trigger；
  - 不能經由擁有權、繼承或其他機制繞過；
  - 考慮未來的 table、sequence 與 function；
  - 正向與負向測試。
- **第二輪審查**（M1–M3）：
  - M1：default privileges 改用全域的 `FOR ROLE`；
  - M2：REASSIGN OWNED 的範圍要列舉、fail closed；
  - M3：advisory lock 的並行分析。
- **核准時的選擇**（2026-11-12）：
  - 報告鎖採方案 A（advisory lock，L1–L8 通過之後接受雜湊碰撞的額外等待）；
  - G3 保留全部四項 Live；
  - G5（開發 DB 的移轉）由使用者自己執行。

### 31.2 角色與權限

**兩個角色**，都是 NOSUPERUSER、NOCREATEDB、NOCREATEROLE、NOREPLICATION、NOBYPASSRLS，沒有成員關係：

| 角色 | 擁有 | 誰使用 |
|---|---|---|
| `secscan_owner`（`DB_OWNER_USER`） | 資料庫與所有物件 | 只有 migration（主機上的 `make migrate`、Live 的 recipe） |
| `secscan_app`（`DB_USER`） | 不擁有任何物件 | api、worker、runner 與主機的 admin CLI |

**資料表的權限**：依執行期的實際用法；預期值在 `tests/db_privileges.py`，migration v0025 另有一份快照。

| 類別 | 資料表 | 權限 |
|---|---|---|
| 只能新增（trigger 拒絕 UPDATE、DELETE） | `audit_events`、`api_specs`、`api_spec_operations`、`artifacts`、`observations`、`scan_events`、`scan_operations`、`run_coverage`、`run_locations`、`finding_observations`、`finding_triage_events`、`scan_comparison_findings` | SELECT、INSERT |
| 只新增、從不讀取 | `run_rule_locations` | INSERT |
| 有狀態轉換 | `api_keys`、`auth_profiles`、`auth_profile_versions`、`evidence_holds`、`finding_triage_excerpts`、`findings`、`reports`、`run_evidence`、`scan_comparisons`、`scanner_runs`、`scans`、`scope_grants`、`targets` | SELECT、INSERT、UPDATE（執行期的修改與列鎖；`FOR UPDATE／SHARE` 需要 UPDATE） |
| 需要刪除 | `report_contents`（換版、到期刪除）、`runner_instances`（心跳的 upsert、刪除過期的實例） | 另加 DELETE |
| 執行期不修改 | `projects` | SELECT、INSERT（報告建立的排隊改用 advisory lock，§31.6） |
| 版本檢查 | `alembic_version` | SELECT |

- **一律不授予**：
  - TRUNCATE、REFERENCES、TRIGGER、MAINTAIN；
  - GRANT OPTION、欄位層級的權限。
- **既有的 trigger 與 CHECK 全部保留**：
  - 只能新增的表有兩層：權限與 trigger；
  - 其他表的轉換規則仍由 trigger 決定。
- **資料表以外**：
  - 資料庫只有 CONNECT：initdb 建立資料庫時就授予，所以 migration 之前 readiness 也能回報「schema 不是目前版本」；v0025 再確認一次；
  - schema `public` 只有 USAGE。`public` 由 `pg_database_owner` 擁有；PUBLIC 保留 PG 15 起預設的 USAGE；
  - sequence 沒有權限：identity 取號不檢查；
  - 函式沒有 EXECUTE：trigger 觸發時不檢查。
- **函式的 default privileges**：
  - 既有的函式與 procedure（`ALL ROUTINES`）：撤銷 PUBLIC 的 EXECUTE。
  - 之後建立的函式：以**全域**的 `ALTER DEFAULT PRIVILEGES FOR ROLE <owner> REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` 處理。PostgreSQL 18 文件明確說明，per-schema 的寫法撤銷不了全域或內建的預設，所以不使用。
- **readiness**（`core/db.py` 的 `probe_database`）：應用程式角色讀不到 `alembic_version` 時，回 SCHEMA_OUTDATED，不是 UNAVAILABLE。這是 v0025 還沒套用的情況。

### 31.3 實作的檔案

| 對象 | 內容 |
|---|---|
| `migrations/versions/v0025_app_role_privileges.py` | <ul><li>檢查：未分類的表、應用程式角色。</li><li>先撤銷，再依矩陣授權。</li><li>函式的 default ACL。</li><li>downgrade 還原內建預設；資料庫的 CONNECT 保留。</li></ul> |
| `migrations/credentials.py` | `MigrationCredentials`：`DB_OWNER_USER`、`DB_OWNER_PASSWORD`。 |
| `migrations/roles.py` | 每次 migration 之前的角色檢查（§31.4）。 |
| `migrations/env.py` | <ul><li>以 owner 連線，不退回應用程式角色的帳密。</li><li>連線失敗時不轉印驅動程式的訊息。</li></ul> |
| `cli/db_roles.py`、`cli/db_roles_catalog.py`、`cli/db_roles_scope.py`、`cli/scram.py` | `secscan-admin migrate-db-roles`（§31.5）。 |
| `reports/service.py` | `lock_project_reports`（§31.6）。 |
| `deploy/postgres/initdb/10-roles.sql`（原 `10-app-role.sql`） | 建立兩個角色；資料庫由 owner 擁有。 |
| `compose.yaml` | `DB_OWNER_*` 只交給 `db`。 |
| `Makefile` | <ul><li>`LOCAL_SECRET_KEYS` 加上 `DB_OWNER_PASSWORD`；</li><li>新的 `db-roles-migrate`、`test-live-db-roles`。</li></ul> |

### 31.4 migration 的守門（`migrations/roles.py`）

每次 migration 之前，在同一個 transaction 中檢查。不符合就停止，資料不變：

1. 目前的角色（owner）：
   - 不是 superuser，而且擁有目前的資料庫；
   - 沒有 CREATEDB、CREATEROLE、REPLICATION、BYPASSRLS；
   - 沒有成員關係。
2. 應用程式角色的條件：
   - 存在，而且不是目前的角色；
   - 沒有任何高風險屬性；
   - 沒有任何成員關係，所以不能經由繼承取得 owner 或預先定義角色的權限。
3. 應用程式角色在目前的資料庫與共用物件中不擁有任何物件。
4. 應用程式角色含經由 PUBLIC，都沒有：
   - 資料庫的 CREATE、TEMPORARY；
   - `public` 的 CREATE。
5. 角色與資料庫層級的設定（`pg_db_role_setting`）：
   - 範圍：應用程式角色、目前的角色、目前的資料庫，以及 `ALTER ROLE ALL`；
   - 只允許 `timezone`；
   - 目前連線的 `session_replication_role` 也必須是 `origin`；
   - 應用程式角色含經由 PUBLIC，都不能以 `GRANT SET ON PARAMETER` 設定 `session_replication_role` 或 `lo_compat_privileges`。
   - 理由：例如 superuser 設定的 `session_replication_role = replica`，會讓應用程式的連線不觸發任何 trigger。
6. `pg_default_acl` 只能有 v0025 的那一列：owner 的全域函式條目，ACL 只有 owner 自己。

**例外**：傳入連線、沒有 `app_role` 時不做這些檢查。這只用於測試，例如建立舊的狀態，或升到 v0025 之前的版本。v0025 本身沒有應用程式角色的名稱就停止。

### 31.5 既有資料庫的移轉（`make db-roles-migrate [DRY_RUN=1]`）

**做法**：
- 只用於 T23b-b1 之前建立的開發 DB；新建的 DB 由 initdb 直接建立兩個角色。
- 在主機上以 superuser（`DB_ADMIN_PASSWORD`）執行：
  - 主機只接受 loopback；
  - `cluster_name` 必須是 `secscan-dev`。
- 以 `pg_shdepend` 列舉應用程式角色與 owner 在**所有資料庫**中的依賴，分類器（純函式）只允許下列範圍：
  - 應用程式角色擁有：目標資料庫本身，以及 `public` 中的表、sequence 與 trigger 函式（S0）；
  - owner 擁有：同上，加上 v0025 的全域函式 default ACL；
  - S2 時應用程式角色的授權：目標資料庫的 CONNECT、`public` 的 USAGE、`public` 中資料表的權限。
- **其他一律拒絕**，例如：
  - 其他資料庫或 tablespace；
  - schema、large object、不是 trigger 的函式、view；
  - 其他資料庫中的依賴；
  - policy、init privileges；
  - 目標資料庫中第三個角色的物件。bootstrap superuser 擁有的物件不記在 `pg_shdepend`，所以另外以每個有擁有者欄位的 catalog 列舉，條件是 oid ≥ 16384；
  - 涉及應用程式角色的 default privileges；
  - 成員關係；
  - 角色或資料庫層級的設定；
  - 應用程式角色或 owner 的連線。
- **owner 已存在時**：
  - 屬性、成員關係、擁有的物件都要相符；
  - `.env` 的密碼要和它的 SCRAM-SHA-256 verifier 相符：在任何改變之前，由 superuser 讀出 verifier、在本機核對。

**執行**：在同一個 transaction 中依序：
1. 工具專用的 advisory lock；設定 `lock_timeout`，關閉 `log_statement`、`log_min_error_statement` 與 `log_min_duration_statement`；
2. 重新列舉與分類；
3. 讀取應用程式角色實際擁有的物件，必須等於分類的那一組。理由：READ COMMITTED 下兩者是不同的語句，空檔中新增的物件沒有經過分類，不移轉；
4. 沒有 owner 時 `CREATE ROLE`：
   - 密碼以本機產生的 SCRAM-SHA-256 verifier 傳送，明文不到伺服器，也就不會進伺服器的任何日誌；
5. `REASSIGN OWNED`：同時移轉目標資料庫本身；
6. 事後檢查：
   - 應用程式角色不擁有任何物件；
   - owner 擁有原本兩者的聯集；
   - 所有資料庫中其他角色的擁有權依賴前後相同；
   - 目標資料庫中第三個角色的物件前後相同；
   - 在同一個 transaction 中重新分類，必須是 S1，而且沒有任何拒絕的項目；
7. 同一個 transaction 中寫 audit `db_roles.migrated`：只記狀態與數量；
8. commit，之後以 owner 另外登入一次。

- superuser 與 owner 的連線都要求 `require_auth=scram-sha-256`（libpq 16 起）。理由：port 被別的服務占用時，對方不能要求明文密碼。`make migrate` 的 owner 連線也一樣。
- **失敗時的說明**：
  - 連不上：說明要確認的設定；
  - 等鎖逾時（55P03）：另一個移轉正在執行，或還有連線持有鎖，沒有任何改變；
  - commit 本身失敗：結果不確定，請以 `DRY_RUN=1` 確認是 S0 還是 S1。

**fail closed**：
- 任何一步失敗都 rollback，沒有中間狀態；再執行一次就完成。
- S1、S2 不寫入任何東西。
- CREATE ROLE 以 psycopg 直接執行，例外不含語句。
- 終端與錯誤都不含密碼。

**和計畫不同的地方**：

| 計畫 | 實作 | 理由 |
|---|---|---|
| 「owner 已存在時，在任何改變之前確認能以 `.env` 的密碼登入」 | 改為核對 SCRAM verifier | S0 時 owner 連不進任何資料庫：initdb 撤銷了 PUBLIC 的 CONNECT，資料庫又由應用程式角色擁有 |
| 「沿用 `audit_local`」 | 改以同一個連線的 session 寫 audit | 才能和移轉同一個 transaction |

### 31.6 報告建立的 project 鎖

**修改**：原本以 `FOR NO KEY UPDATE` 鎖住 projects 的列，那需要 projects 的 UPDATE。改成交易層級的 `pg_advisory_xact_lock(28005, hashtext(project_id::text))`。

**位置與語意**：
- 取得的位置、鎖的順序不變；
- 同一個 project 互斥；
- commit 或 rollback 時自動釋放；
- 等鎖逾時是 55P03，可以重試。

**分析**：沒有其他程式或 trigger 依賴 projects 的列鎖；FK 檢查用的 `FOR KEY SHARE` 本來就不和它衝突。

**碰撞**：n 個 project 至少一組碰撞的機率約 n²／2³³（1,000 個時約 1.2×10⁻⁴）。碰撞只讓兩個 project 的報告建立互相排隊。

**沒有採用的替代方案**：
- 保留列鎖，加上拒絕所有 UPDATE 的 trigger；
- 另外建立鎖表。

**測試**：L1–L8（`tests/integration/test_report_lock.py`）。

### 31.7 測試與假設的結論

ROLE-01 至 08 的內容見 `SECURITY_AND_TESTING.md` §4.3。既有的整合測試照下列原則調整：
- **不改斷言的意義，只換連線的角色**；
- **需要 DDL 的故障注入**：改用 owner；
- **驗證 trigger 那一層、但應用程式角色已經沒有該權限的語句**：改用 owner；
- **整個檔案改用 owner**：只驗證 schema 的 6 個檔案。它們的 fixture 以同一個 session 建立資料；
- **其他測試都維持應用程式角色**：api、worker、runner 與 CLI 的功能回歸，就在新的權限下執行。

| 假設 | 結論 | 測試 |
|---|---|---|
| A1 trigger 觸發時不檢查函式的 EXECUTE | 成立：違規得到 23000，不是 42501 | ROLE-04 |
| A2 identity 取號不檢查 sequence 的權限 | 成立 | ROLE-04 |
| A3 default ACL 還原成內建預設時，那一列被刪除 | 成立 | ROLE-05 |
| A4 advisory lock 的等待 | 成立：<ul><li>`wait_event_type = 'Lock'`；</li><li>`lock_timeout` 得到 55P03；</li><li>int8 與兩個 int4 的鍵是不同的空間。</li></ul> | L1、L3、L5、L6 |
| A5 移轉之後應用程式角色不擁有任何物件 | 成立，含 identity sequence | ROLE-06 |
| A6 `public` 由 `pg_database_owner` 擁有 | 成立 | ROLE-02 |
| A7 沒有 grant option 的 GRANT 只發出警告 | 成立，ACL 不變 | ROLE-03 |
| A8 應用程式角色可以修改自己 | 部分成立：<ul><li>可以 `ALTER ROLE` 自己的參數，例如 `default_transaction_read_only`；</li><li>`DROP OWNED BY` 自己可以執行，但**撤銷不了** owner 授予的權限：實測，和計畫的假設不同；</li><li>擁有權、trigger 與約束都不變。</li></ul>列為剩餘風險 2 | ROLE-03 |

### 31.8 回復（只用於開發；不提供指令）

1. 以 owner 執行 `alembic downgrade 0024`：撤銷逐表權限，還原函式的 PUBLIC EXECUTE 與 default ACL。
2. 以 superuser 執行 `REASSIGN OWNED BY secscan_owner TO secscan_app`。
3. 切回 T23b-b1 之前的程式。

### 31.9 剩餘風險

1. **共用角色**：三個服務與主機的 admin CLI 共用 `secscan_app`，任何一個被入侵，就有全部服務的 DML 權限。DDL／DML 分權不是服務級的隔離，服務級的角色是 b3 之後的子項目。
   - **runner 被入侵時，分權沒有限制力**（安全審查 M1）：socket-proxy 不檢查 create 的 body（§14.1）。runner 可以：
     - 建立 privileged、`PidMode: host` 的容器，讀 db 的 postmaster 的 `/proc/<pid>/environ`，裡面有 `POSTGRES_PASSWORD` 與 `SECSCAN_OWNER_DB_PASSWORD`；
     - 以本機的 postgres 映像掛載 `db_data`，直接讀寫資料檔。

     改善留給 b2：例如以 `*_FILE`，讓 db 初始化之後不把密碼留在容器的環境；以及 b3 之後的部署強化。
   - 其他例子：
   - api 被入侵，可以依 trigger 允許的轉換寫入 `evidence_holds` 的隔離完成，但目錄並沒有搬走。能發現它的是 keeper 的對帳（§30.13），不是 DB 權限；
   - worker 被入侵，可以改 `scanner_runs`、`findings`；
   - 每個服務都讀得到全部的密文欄位，解不解得開取決於金鑰（§30.2）。
2. **只會造成服務中斷的操作**（A8）：
   - 應用程式角色可以：
     - `ALTER ROLE` 自己的密碼與可由使用者設定的參數，例如 `default_transaction_read_only`：之後的連線都不能寫入；
     - 對同一個角色的連線 `pg_terminate_backend`；
     - 占用 keeper 或報告的 advisory lock；
     - `LOCK TABLE`；
     - 建立自己擁有的 large object（`lo_create`），或設定自己的 default privileges（`ALTER DEFAULT PRIVILEGES FOR ROLE secscan_app …`）。之後 migration 的守門會拒絕執行，`make migrate` 就被擋住；owner 不是 superuser，清除不了（資料庫審查 M2）。
   - **復原**：
     - 密碼與參數、large object 與 default privileges：**只有 superuser** 能處理，owner 是 NOCREATEROLE。例如：
       - `ALTER ROLE secscan_app RESET ALL`；
       - 重設密碼；
       - `SELECT lo_unlink(oid) FROM pg_largeobject_metadata WHERE lomowner = 'secscan_app'::regrole`；
       - `ALTER DEFAULT PRIVILEGES FOR ROLE secscan_app` 撤銷。
     - 權限：owner 執行 `alembic downgrade 0024 && alembic upgrade head`。
   - `DROP OWNED BY` 自己撤銷不了 owner 授予的權限（ROLE-03 實測）。
   - **可以減少的部分**（沒有在 b1 實作，請使用者決定）：由 superuser 在 initdb 與 migrate-db-roles 中撤銷 `pg_catalog.lo_creat`、`lo_create`、`lo_from_bytea` 對 PUBLIC 的 EXECUTE（程式沒有用到 large object）。
     - 這是新的一類變更，要修改 pg_catalog 的 ACL，也需要新的測試與移轉支援；
     - default privileges 的部分擋不了。
3. **superuser 的設定可以繞過 trigger**（例如 `session_replication_role`）：
   - b1 只能偵測：migration 的守門、移轉指令、ROLE-02；
   - 擋不住 superuser 之後再設定。
4. **密碼的存放**：
   - owner、superuser 與應用程式角色的密碼都在主機的 `.env`；
   - db 容器的 environment 也有 owner 的密碼，`docker inspect` 看得到；
   - 改善留給 b2。
5. **owner 本來就有完整的 DDL 權限**：取得 owner 的帳密就能停用 trigger；`pg_hba` 也沒有限制 owner 的連線來源。
6. **UPDATE 是表層級的**：能改成什麼由 trigger 決定；trigger 的錯誤，權限補不了。
7. **報告鎖的雜湊碰撞**：只會讓兩個 project 的報告建立互相排隊。
8. **large object**：一般角色預設就能建立 large object。它不涉及資料表的權限；ROLE-02 確認應用程式角色不擁有任何 large object。但被入侵的應用程式角色可以建立 large object，擋住之後的 migration（見第 2 點）。
9. **開發 DB 的狀態**：你執行移轉（G5）之前，它仍是分權之前的狀態。
   - 移轉之後、`make migrate` 之前，應用程式角色連不上：REASSIGN OWNED 也移轉資料庫的 ACL。
   - 所以這段期間，readiness 與 runner、worker 的啟動檢查都會回報「無法連線」。

### 31.10 關卡

| 關卡 | 內容 | 執行者 |
|---|---|---|
| G1 | 離線實作、測試與審查，開 PR、不合併 | 我（Claude） |
| G2 | `make env` 與完整的 `make test` | 使用者 |
| G3 | 四項 Live，另外授權 | — |
| G4 | 合併 | 使用者（2026-11-13 改由使用者要求 Claude 最終核對後合併，§31.14） |
| G5 | 開發 DB 的移轉 | 使用者（2026-11-13 改由使用者授權 Claude 依 7 項條件執行，§31.14） |

- b1 在 G1 到 G5 都完成之後才標完成。
- **SEC-14 仍不標完成。**

### 31.11 審查與處理（G1，2026-11-13）

三項審查都以 opus 進行（唯讀）：資料庫、安全、程式碼。都沒有 CRITICAL。

| 來源 | 項目 | 處理 |
|---|---|---|
| 安全 M1 | runner 經由 socket-proxy 讀得到 owner 與 superuser 的密碼，§31.9 漏寫 | 寫進 §31.9 第 1 點；改善留給 b2 |
| 安全 L1、資料庫 L2 | CREATE ROLE 的明文密碼可能經由 `log_min_duration_statement`、`pg_stat_statements` 等進入日誌 | 改以本機產生的 SCRAM verifier 傳送，並關閉 `log_min_duration_statement` |
| 安全 L2、資料庫 M3 | 分類與移轉之間的 TOCTOU：空檔中新增的物件未經分類就被移轉 | <ul><li>`Dependency` 帶 `(dbid, classid, objid, objsubid)`，實際擁有的物件必須等於分類的那一組；</li><li>REASSIGN 之後重新分類，必須是 S1；</li><li>測試：分類之後才新增物件就拒絕。</li></ul> |
| 安全 L3、程式碼 M2 | commit 失敗被說成「沒有做任何改變」；等鎖逾時被說成「連不上」 | 連線與 transaction 分開；commit 失敗回報結果不確定；55P03 另外說明。三者都有測試 |
| 安全 L4 | 連線沒有要求 SCRAM | b1 新增的 owner、superuser 連線加上 `require_auth=scram-sha-256`；應用程式的連線留給 b2 |
| 安全 L5、資料庫 M2 | 復原方式寫錯：owner 改不了應用程式角色自己的設定，也清不掉它的 large object；被入侵的應用程式角色可以擋住 migration | 更正 §31.9 第 2、8 點。撤銷 `lo_create` 等的做法列為提議、沒有實作 |
| 安全 L6 | 守門沒有檢查 owner 自己的屬性與成員關係；`DB_OWNER_USER` 沒有命名規則 | 守門加上檢查；`DB_OWNER_USER`、`DB_USER`、v0025 都不接受 `pg_` 開頭；有測試 |
| 資料庫 M1 | 沒有檢查 `GRANT SET ON PARAMETER session_replication_role`（含 PUBLIC），可以讓 trigger 不觸發 | 守門與移轉都以 `has_parameter_privilege` 檢查 `session_replication_role`、`lo_compat_privileges`；ROLE-02、05、06 有測試 |
| 資料庫 L1 | 守門沒有把 PUBLIC 的權限算進去 | 改用 `has_database_privilege`、`has_schema_privilege`；`pg_default_acl` 只允許預期的那一列 |
| 資料庫 L3 | <ul><li>`ALL FUNCTIONS` 不含 procedure；</li><li>表名沒有 schema；</li><li>角色名稱可以 `pg_` 開頭；</li><li>readiness 依賴 AND 的求值順序</li></ul> | <ul><li>改成 `ALL ROUTINES`；</li><li>GRANT 加上 `public.`；</li><li>不接受 `pg_` 開頭；</li><li>readiness 改成 `coalesce(has_table_privilege(to_regclass(…)), false)`</li></ul> |
| 資料庫 L4 | 測試缺口 | ROLE-02 加上應用程式角色所有授權依賴的盤點；ROLE-05、06 加上 `ALTER ROLE ALL`、parameter ACL |
| 程式碼 HIGH | A8 的測試與文件矛盾 | 審查看到的是修正之前的版本：已改成實測結果，即撤銷不了權限，和文件一致 |
| 程式碼 M3 | cluster 範圍的快照與 `pg_locks` 不依賴自己的範圍 | 快照只取這個測試自己的角色與資料庫；`pg_locks` 以資料庫過濾 |
| 程式碼 M4 | 文件高估了以應用程式角色執行的測試範圍 | 更正 S&T 與 TASKS 的敘述，和 `tests/integration/conftest.py` 一致 |
| 程式碼 LOW | <ul><li>fixture 中途失敗留下角色；</li><li>碰撞搜尋失敗時的訊息；</li><li>例外的型別；</li><li>變數遮蔽；</li><li>過期的文件</li></ul> | 都已修正。`owner_alembic_config` 以命名推出應用程式角色，維持現狀並寫明約定 |

空轉檢查 16 項：計畫列出的都被測試抓到。L4 第一次沒抓到「session 層級的鎖」：NullPool 的連線在 commit 之後就關閉。改成在連線還開著時檢查之後，抓到了。

### 31.12 G2 的結果（使用者，2026-11-13）

- **`make env`**：補上 `DB_OWNER_PASSWORD`；`.env` 是 600、468 bytes，和計畫相同。
- **第一次的 `make test`**：7,882 passed、1 failed，失敗的是 `test_evidence_retry.py::test_retention_status_shows_unfinished_isolation_as_urgent`。
  - **原因**（推論，依程式碼與量測；失敗的當下沒有量到時鐘差）：
    - `retention-status` 判斷「需要緊急處理」時，比較的是 trigger 以 DB 容器時鐘寫入的 `held_at`，和主機的 `datetime.now(UTC)`（`cli/evidence.py` 的 `_isolation_status`、`_isolating_line`）。
    - 測試把門檻設成 0 分鐘。DB 容器的時鐘比主機快、而且快過兩次取時間的間隔時，緊急的數量就是 0。
    - 事後量到 DB 比主機快 0.2 到 9 ms。
  - **和 b1 無關**：
    - 這個測試與程式屬於 T23a，這個 PR 沒有修改；
    - 分權之前的基準與三次完整執行都通過；
    - 單獨重跑 12 次都通過；
    - 那段期間沒有睡眠紀錄。
- **第二次的 `make test`**：7,883 passed、2 skipped，coverage 98.75%。
  - 2 個 skipped 是既有的、依環境略過的測試：
    - `test_workspace.py:397`：檔案系統不接受非 UTF-8 的檔名；
    - `test_taxonomy_contract.py:89`：需要 gitignore 的錄製。
- **提議**（待使用者決定，b1 的範圍之外）：`retention-status` 改以 DB 的時鐘判斷經過的時間。
  - 到期清除已經以 DB 的時鐘判斷（`worker/retention.py`），這裡用主機的時鐘並不一致；
  - 改了之後，這個測試就不受主機與容器的時鐘差影響。

### 31.13 G3 的結果（Live，使用者 2026-11-13 授權）

**執行條件**：
- 每一項都以 `caffeinate -is` 執行，AC 電源；
- 可拋棄的 `secscan-live` stack；
- `.env` 執行前後都是 600、468 bytes；
- 沒有使用開發用的 db。

**證據**：在 gitignore 的 `recordings/t23b-b1-live/`。
- 內容：SUMMARY、各項的 log 與結束碼、Docker 前後的快照，以及兩個錄製目錄。
- 清單：`MANIFEST.sha256`，37 個檔案，本身的 sha256 是 `300d05d50e912791d33caeceec636690175d066c42924ab466b2b016c73fb75f`。

| 指令 | 結果 |
|---|---|
| `make test-live-db-roles`（attempt 1） | 10 passed、1 failed：測試的設計不對（見下） |
| `make test-live-db-roles` | 14 passed |
| `make test-live-runner` | 42 passed |
| `make test-live-fixture-findings` | 3 passed |
| `make test-live-fixture-rescan` | 1 passed |

**attempt 1 的失敗**：
- 原本的寫法：要求在同一次 `pg_stat_activity` 快照中同時看到三個服務的連線。
- 為什麼看不到：runner 與 worker 使用 NullPool，每 2 秒輪詢時才連線幾毫秒。
- 修正之後：
  - 在每個服務的容器內，以那個程序自己的環境設定連線，確認 `current_user`、`session_user` 都是應用程式角色。只輸出角色名稱，密碼不離開容器。
  - api 的連線池中的連線，以 `pg_stat_activity` 確認也是應用程式角色。

**和 T23a 驗收的對照**：
- findings 的 `[量測]` 行逐行相同；
- rescan 只差執行秒數，以及一個 ZAP 告警回報的路由（`/greet` 與 `/go`）。T22 的 `rescan-final.log` 也是 `/greet`，所以是 ZAP 本身的變動。
- 分權沒有改變掃描結果。

**殘留**：
- 容器與網路和執行前相同。
- 另有 12 個空的匿名 volume，都建立於 `make test-live-runner` 期間：
  - **原因**：guard 映像宣告了 `VOLUME /home/mitmproxy/.mitmproxy`。Live 的接收端以 `docker run -d` 啟動，以沒有 `-v` 的 `docker rm -f` 刪除，Makefile 的清除也一樣。
  - 這是 T11 起既有的行為，和 b1 無關。
  - 沒有刪除，由使用者決定。
  - **提議**：`docker rm -f -v`。不在 b1 的範圍內，可以和 §31.12 的時鐘修正一起處理。
  - **處理**（§31.14）：2026-11-13 依使用者的決定定向清除；修正在 PR #39。

### 31.14 G4、G5 的結果與殘留的處理（使用者，2026-11-13）

**使用者的決定**：
- 不重跑四項 Live；不為了既有的匿名 volume 擴大 PR #38 的範圍。
- 依序執行：
  1. 定向清除 12 個匿名 volume；
  2. PR #38 最終核對並合併；
  3. G5 的移轉與升級後的驗證；
  4. 從 main 另開小 PR，處理時鐘誤差與匿名 volume。
- §31.10 原本由使用者執行的 G4、G5，改由使用者要求 Claude 執行。

**G5 的執行條件**（使用者看過第一次 dry-run 之後提出）：
1. 正式移轉之前，確認有可還原的備份，也沒有非預期的連線；
2. 再次確認移轉的範圍和 dry-run 相同；
3. 依序執行，任何一步失敗就停止，不跳過檢查、不強制修改 DB；
4. 接上 AC 之後才以 `caffeinate` 執行 `make up`；
5. 驗證健康狀態、schema 0025、擁有權、逐表權限、default ACL 與三個服務的實際連線角色；
6. 不刪除或重建開發 DB 的 volume、不重設金鑰、不修改 G5 範圍以外的資源；
7. 保留紀錄。

**證據**：在 gitignore 的 `recordings/t23b-b1-g5/`。
- 內容：SUMMARY、各步驟的 log 與結束碼、備份、驗證腳本。
- 清單：`MANIFEST.sha256`，29 個檔案，本身的 sha256 是 `92bf3b0e8a6be485e44808bc5cdc429d6a84206e0011db1ad9e1d253bcb1f66c`。

| 步驟 | 結果 |
|---|---|
| 清除 12 個匿名 volume | <ul><li>先確認每一個都是 G3 前後清單的差集、建立於 `test-live-runner` 期間、只有匿名標籤、沒有容器引用、內容為空；</li><li>以完整 ID 逐一 `docker volume rm`（沒有 prune）；</li><li>之後的清單和 G3 執行前相同（275 個）。</li></ul> |
| G4：PR #38 | <ul><li>本機 HEAD 等於 PR head，base 是目前的 main；</li><li>`make lint`、`make typecheck` exit 0；</li><li>G2 之後的 commit 只改 Live 測試與文件；沒有設定 CI。</li></ul>合併：`4287eea` |
| 連線 | 除了查詢自己之外沒有 client 連線（app stack 沒有在執行） |
| 備份 | <ul><li>`pg_dump -Fc` 與 `pg_dumpall --globals-only --no-role-passwords`；</li><li>`pg_restore --list` 與 `pg_restore -f -` 完整解碼，exit 0；</li><li>30 張表的列數和 DB 相同。開發 DB 只有 3 列：`alembic_version` 1、`runner_instances` 2。</li></ul>**沒有**實際還原到任何資料庫（條件 6） |
| dry-run ×2 | 兩次都是 S0、exit 0，逐行相同：<ul><li>70 個物件：table 30、sequence 2、trigger function 37、資料庫 1；</li><li>沒有任何拒絕。</li></ul> |
| `make db-roles-migrate` | <ul><li>exit 0；</li><li>transaction 內重新分類的清單和 dry-run 相同；</li><li>已移轉 70 個物件；</li><li>`secscan_owner` 可以登入。</li></ul> |
| `make migrate` | exit 0：`0025 (head)` |
| `make up` | <ul><li>接上 AC，以 `caffeinate -is` 執行；</li><li>exit 0，所有服務 healthy；</li><li>db 容器沒有重建，`secscan_db_data` 仍是 2026-11-12 建立的那一個；</li><li>`.env` 前後都是 600、468 bytes。</li></ul> |
| 升級後的驗證 | **24/24 通過**，見下方 |
| 服務 | <ul><li>api、runner、worker、guard 的日誌沒有權限錯誤；</li><li>這次啟動的 runner 與 worker 都有新的心跳（INSERT 之後 UPDATE）。</li></ul> |

**24 項驗證**：
- **健康狀態**：live 與 ready。
- **schema**：版本是 0025，等於 head。
- **擁有權**：
  - DB 由 owner 擁有；`public` 由 `pg_database_owner` 擁有；
  - `public` 中的 relation、函式與型別都由 owner 擁有；
  - app 在所有資料庫都不擁有任何物件；
  - 兩個角色的屬性正確；
  - 沒有成員關係，也沒有角色或資料庫層級的設定。
- **權限**：
  - 30 張表的權限等於 `tests/db_privileges.py` 的矩陣；
  - 沒有 GRANT OPTION；
  - PUBLIC 沒有表的權限，也沒有欄位權限；
  - app 在 DB 只有 CONNECT，在 public 只有 USAGE；
  - 37 個函式都有明確的 ACL，app 沒有 EXECUTE，也沒有 SECURITY DEFINER。
- **default ACL**：只有 owner 的全域函式條目一列。
- **服務的連線**：
  - 三個服務在各自的容器內，`current_user` 與 `session_user` 都是 `secscan_app`；
  - 環境變數中沒有 owner 的帳密；
  - 所有的 client 連線都是 `secscan_app`。

**執行中的兩個錯誤**（都在驗證的查詢本身，唯讀，沒有任何改變）：
1. 腳本的 `text || "char"` 運算子有歧義，加上 `::text` 後重跑；
2. 第一次的心跳檢查把 G5 之前的 2 列舊紀錄也算了進去，同一個紀錄中已更正。

**殘留**：
- 開發用的 app stack 維持啟動。
- `runner_instances` 中 2026-11-12 的 2 列舊紀錄：
  - 由 runner 與 worker 迴圈的 `prune()` 在 7 天沒有心跳之後刪除（`STALE_AFTER`）；
  - 沒有手動刪除。

**§31.12、§31.13 的兩項提議**：在 PR #39 處理（從 main 另開；2026-11-14 合併，merge commit `d427498`）。
- `retention-status` 改以 DB 的 `clock_timestamp()` 判斷經過時間，並加上主機時鐘快或慢一小時的回歸測試；
- Live 的接收端以 tmpfs 蓋住 guard 映像的 VOLUME，沿用 `lab_support` 既有的作法；
- Makefile 的清除改成 `docker rm -f -v`。

**結論**：
- b1 的 G1 到 G5 都完成，**b1 標示完成**；
- T23b 的 b2 到 b4 尚未開始；
- **SEC-14 仍不標完成**（§30.14 的 P0 條件）：
  - 還需要 T23b 的 b2、b3 與 T23c 完成；
  - 還要驗證機密不會經由洩漏路徑外流；
  - 剩餘風險要經使用者確認接受。
