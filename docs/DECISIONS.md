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
- DB 連線尚未設定 `statement_timeout`、`idle_in_transaction_session_timeout` 與 `sslmode`。只在單機 loopback 使用時影響不大；T09（工作佇列的鎖）與 M2（離開單機）前補上。

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
  - gate 的時間與鎖等待（T09）：呼叫端在取得 `FOR SHARE` 之後再取 `now`，並設定 `lock_timeout`（§7 已記錄尚未設定 `statement_timeout`），避免建立 scan 的 transaction 拖長時卡住撤銷。
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
| 綁定 | 加密的內容是 `{"context": "auth_profile:<profile id>", "v": 1, "value": <secret>}`；解密時 context 不符就拒絕 | Fernet 沒有 associated data。能寫 DB 的人把 A 的密文搬到 B，B 會解不開。只綁 profile、不綁版本：新版本沿用 secret 時直接複製密文，API 不必解密 |
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
- **不寫入 log**：
  - 請求中的 `secret` 是 `SecretStr`（API 文件標成 writeOnly），domain 物件的 repr 不含它。
  - 驗證錯誤不回顯任何輸入，沿用 T04 的 422 處理與 §10.2 的原則。
  - engine 已設定 `hide_parameters`，SQL 參數不出現在例外與日誌中（`ARCHITECTURE.md` §6.2）。
  - 測試以 canary 檢查回應、DEBUG 等級的所有 log、audit、DB 中的明文與例外訊息。

### 12.3 換版

**加密金鑰**：
- `secscan-admin rotate-secret-keys`：
  - 在一個 transaction 內以 `FOR UPDATE` 鎖住所有密文。
  - 以 MultiFernet.rotate 改用第一個金鑰重新加密（保留原本的時間戳記 [S69]），並確認 context 仍然相符。
  - 任何一份解不開就全部回滾、exit 1，訊息只列出 profile id；成功時寫一筆全域 audit。
- 流程（Fernet 文件的做法：新金鑰放最前面、rotate 既有的 token、再移除舊金鑰 [S69]）：
  1. 新金鑰放在第一個，重啟 API：新的 secret 改用新金鑰加密，舊的仍解得開。
  2. 執行 `rotate-secret-keys`。
  3. 移除舊金鑰，重啟 API。
  4. 再執行一次 `rotate-secret-keys`，確認全部解得開。

**profile 的版本**：
- `PATCH` 產生新版本，version 是每個 profile 各自的流水號；舊的 scan 快照不受影響（`API_CONTRACT.md` §2）。
- **建立新版本時清除上一版的密文**（使用者的決定）：secret 只存在於目前的版本，換掉就消失；token 頻繁更換時，舊 token 不會累積。
  - DB 以部分唯一索引保證每個 profile 最多一份密文 [S74]。
  - 舊版本只留定義（type、header 名稱、preflight），回應中是 `secret_configured: false`。
- trigger：版本列只允許兩種 UPDATE，而且其他欄位都不能改：
  - 清除：密文變成 NULL，同時記下 `secret_erased_at`。清除之後不能恢復。
  - 重新加密：密文換成另一份非 NULL 的密文（金鑰換版）。
  - INSERT 必須帶密文；DELETE 與 TRUNCATE 一律拒絕。profile 本身的列完全不可變。
- **鎖的順序**：PATCH 先以 `FOR UPDATE` 鎖住 profile（版本號依 commit 的先後遞增），再鎖目前的版本列，才讀它的密文。金鑰換版還沒 commit 時，PATCH 會等它，複製到的就是新金鑰加密的密文；換版只鎖版本列，所以不會互相等待而死結。

取捨：
- 排隊中、綁定舊版本的 scan：版本被取代後密文已清除，runner 啟動前就會失敗（fail closed），不自動改用新版本（T09、M2）。
- 能寫 DB 的人仍能清除密文（trigger 允許這個轉換）：結果是 scan 失敗，不會洩密。和其他 trigger 一樣只防程式錯誤造成的誤改（§7）。

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
| 代理與路由 | `Proxy-*`（含 guard 用的 Proxy-Authorization）、Forwarded、Via、Max-Forwards、`X-Forwarded-*`、X-Real-IP | 會干擾 guard 或上游判斷請求的來源 |
| 改寫 method 或 path | X-HTTP-Method-Override、X-HTTP-Method、X-Method-Override [S75]、X-Original-URL、X-Rewrite-URL [S76] | 有些框架照這些 header 改 method 或路由，會繞過 grant 的 method 與 path 範圍 |
| 其他 | Cookie、Set-Cookie；`X-Secscan-*` | Cookie 用 cookie 類型；`X-Secscan-*` 保留給平台 |

取捨：拒絕清單不保證完整。主要的防線是嚴格的字元集；實際送出的 header 由 M2 的 guard 檢查。

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
  - JSON Pointer 依 RFC 6901 解析，含陣列索引；指不到就不符合。
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

- security 加入 `cryptography`（MultiFernet）；仍不得依賴 Web 框架、DB 與 Docker。
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

## 來源

`[Sxx]` 對照見 `docs/SOURCES.md`。
