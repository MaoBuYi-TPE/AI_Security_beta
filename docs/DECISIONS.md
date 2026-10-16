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

## 來源

`[Sxx]` 對照見 `docs/SOURCES.md`。
