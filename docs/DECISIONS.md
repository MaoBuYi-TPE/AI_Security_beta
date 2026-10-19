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
- **遮罩的已知缺口**：HAR 那種 name/value 成對的格式、URL 中的帳密與 query 參數、`password=…` 之類的文字還不處理（`security/redaction.py` 的說明）。T08（認證設定）與 M3（證據遮罩）需要時再擴充，並補對應的測試。

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
| `LAB_CIDR` | 設定 `LAB_CIDR`，預設 `10.89.7.0/24`，也就是 `compose.lab.yaml` 的 lab_net（有測試比對兩者一致）。必須是 RFC 1918 私有網段內、前綴 /16–/30 的 IPv4 網段 | CLAUDE.md §6：不一律開放 RFC 1918。太寬的設定（例如 `10.0.0.0/8`）可能涵蓋校園網路；/31、/32 沒有一般意義的網段與廣播位址，規則會變得難懂 |
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
  - IPv6、尾端的點、`localhost` 與 `*.localhost`
  - 數字形式模糊的 host：前導 0、十六進位、整數、不足 4 段，以及最後一段是數字、卻不是合法 IPv4 的名稱
  - 不合法的 port：0、超過 65535、前導 0
- **理由**：同一個字串，不同的 URL parser 可能解出不同的 host（SEC-05）。以 Python 3.12 實測與 WHATWG URL 規格（瀏覽器與部分工具採用）對照：
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
| path 的語法 | 以 `/` 開頭、只用 ASCII 的 URI path 字元；不可有 `%`、`\`、`?`、`#`、空白與控制字元，也不可有空段落（`//`）或 `.`、`..` 段落；每個最長 512 字元 | SEC-08：percent-encoding 與點段落讓同一條 path 有多種寫法，無法可靠比對時 fail closed。比對規則由 T07 與 M2 實作，T06 只定語法 |
| `allowed_methods` | GET、HEAD、OPTIONS、POST、PUT、PATCH、DELETE 的子集，大小寫必須完全一致；TRACE、CONNECT 一律拒絕 | HTTP method 區分大小寫（RFC 9110）。狀態改變的 method 必須明確列出（CLAUDE.md §7） |
| 重複值 | 任何清單有重複（正規化之後）都拒絕，不默默去重 | 不默默修正輸入，與分頁參數的原則相同 |
| 預算 | `requests_per_second`、`max_requests`、`max_duration_seconds` 三個正整數，上限是 M0–M2 的保守起始值 2、5,000、1,500；沒指定時用上限 | 沿用 `ARCHITECTURE.md` §3.4。上限放在 domain，DB 只檢查大於 0；M3 量測後要提高時，在這裡記錄理由，不需要 migration |
| 期限 | `valid_until` 必填；`valid_from` 預設為申請時間。必須 `valid_from < valid_until`、`valid_until` 晚於現在，期間最長 30 天 | 授權不能沒有期限。30 天代表一學期的 lab 大約每月重新核准一次 |
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
- **併發**：核准與撤銷以 `SELECT … FOR UPDATE` 鎖住 grant，並以 DB 的最新值判斷（`populate_existing`，同 §9 撤銷 key 的做法）。同時核准與撤銷時，結果和其中一個先執行的結果相同。
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
- operator 的緊急停止是停用 target：已核准的 grant 就不能再用來建立新的 scan（§10.6）。撤銷 grant 留給 admin（`API_CONTRACT.md` §2）。
- admin 可以核准自己提出的申請。目前只有一位管理員，CLI 本來就能再建立 admin key，以 key 區分並不會帶來真正的職責分離；audit 會記下申請者與核准者。

### 10.6 掃描 gate

- `ScopeGrantService.require_usable()` 是「這個 grant 現在能不能用來掃描」的唯一判斷。T09 建立 scan 時在同一個 transaction 呼叫；runner 啟動前（M2）再判斷一次。
- 通過條件：grant 屬於該 target、狀態是 approved、`valid_from <= 現在 < valid_until`、target 未停用、所有 IP 都在當下的 `LAB_CIDR` 內。
- 以 `FOR SHARE` 依序鎖住 target 與 grant：撤銷 grant 或停用 target 一旦 commit，之後就不可能再建立使用它的 scan；反過來，正在建立 scan 時，撤銷會等它 commit。撤銷之後停止執行中的 scan，由 T09、T13 處理。
- 鎖的順序固定為 target 先、grant 後；只有 gate 同時鎖兩者，所以不會互相等待而死結。

### 10.7 模組與分層（更新 §9.4）

```text
main | cli → migrations → health | grants → targets → projects → api_keys → audit → security → core
```

| 模組 | 為什麼在這一層 |
|---|---|
| grants | 申請 grant 要鎖住 target 取得版本號，並由 target 得知所屬的 project |
| targets | 建立與列出 target 前要確認 project 存在：admin 指定不存在的 project 時回 404 |

### 10.8 不在 T06 範圍

- path 與 method 的比對規則，以及 OpenAPI operation 是否在 grant 範圍內：T07、T11。
- `POST /scans` 呼叫 gate；撤銷 grant 或停用 target 之後，停止執行中的 scan：T09、T13。
- guard 的 DNS/IP 綁定與 redirect 檢查，以及與 mitmproxy 的 URL 解析比對：T11。
- seed path、依量測調整預算上限：M3。
- 全域的待核准清單：目前要從 project → target → grant 逐層查詢，和全域 audit 查詢一起留給 T21。
- 請求大小上限：T07（§9.5）。

何時重新檢討：
- 要掃描 lab 以外的目標：先完成 §6 的條件，再設計 `LAB_ONLY=false` 時的規則（例如書面授權的核對方式）。
- 30 天的期限或預算上限妨礙實驗：依量測調整，並在這裡記錄。
- 有多位管理員：考慮禁止核准自己的申請。

## 來源

`[Sxx]` 對照見 `docs/SOURCES.md`。
