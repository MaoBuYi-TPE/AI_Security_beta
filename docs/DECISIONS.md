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

## 來源

`[Sxx]` 對照見 `docs/SOURCES.md`。
