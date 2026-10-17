# 需求摘要與範圍凍結（T01）

- 凍結日期：2026-10-17
- 狀態：**已凍結**。題目已經指導教授確認；範圍、研究問題與排除項目由本人確認後凍結。
- 用途：用一頁說明本專題要解決什麼、做到哪裡、要回答哪些問題。細節見 `PROJECT_PLAN.md`，設計理由見 `DECISIONS.md`。
- 變更規則：
  - 凍結後要調整題目、P0/P1 範圍或研究問題，先在 `DECISIONS.md` 新增一節寫下理由，再同步修改本文件、`PROJECT_PLAN.md` 與 `TASKS.md`。
  - 依 `PROJECT_PLAN.md` §10 的降階順序調整（先砍 CI 範例、再砍 SARIF、最後 M6 改為補強），屬於預先同意的變更，只需在 `TASKS.md` 記錄。

## 1. 題目

**Web 與 API 多引擎動態安全檢測暨結果整合後端系統之設計與實作**

1 人開發、只做後端，期間 2026/10/16 – 2027/06/30。

## 2. 要解決的問題

小型開發團隊需要在上線前檢查 Web 與 API，卻沒有專職資安人力。手動分別使用 ZAP、Nuclei 等工具時，授權範圍、認證設定、輸出格式與失敗判讀都分散在各個工具中，結果難以整理、追溯與比較。

- **目標使用者（待驗證）**：有上線前檢查需求的小型產品團隊、校內專題團隊、負責測試的後端工程師。
- **部署場景**：自管的測試環境、隔離的 staging 副本與教學靶場；不提供公開的任意 URL 掃描服務。

## 3. 相對於手動使用工具，本系統增加什麼

| 面向 | 手動分別執行工具 | 本系統 | 驗證方式 |
|---|---|---|---|
| 授權範圍 | 靠操作者自律，輸入任何 URL 都能掃 | ScopeGrant 經管理員核准才能掃；`LAB_ONLY` 時 IP 必須在 `LAB_CIDR` 內；每次 scan 保存不可變快照 | SEC-01、SEC-02 |
| 出站控制 | 靠工具自己守範圍，但工具會自行解析 DNS、跟隨 redirect | 掃描容器只能連 egress guard，逐請求檢查 host、IP、port、path、method 與 redirect | SEC-03–SEC-08（以 canary 實際收包為準） |
| 掃描預算 | 各工具各自限速，總量無法控制 | guard 強制執行跨引擎共享的速率、請求數與時間預算，並以實際計數為準 | SEC-13、guard telemetry |
| 認證設定 | 每個工具各自設定 Token 或 Cookie，容易出現在命令列或 log | 統一的 auth profile：加密保存、只寫不讀、執行時才注入；掃描前做 protected preflight | SEC-14、SEC-15 |
| 任務與失敗語意 | 只看 exit code 與終端輸出，零告警、工具失敗、認證失效容易混淆 | 持久化的狀態機與各引擎狀態，零告警、失敗、timeout、未掃到分開標示；取消時先斷流量再停容器 | 故障注入測試、Gate C |
| 結果格式與去重 | 多份格式不同的報告，靠人工判斷是否重複 | 統一的 Observation/Finding；保守去重且不刪除來源；每筆 finding 都能追溯到原始證據 | 去重反例測試、RQ2 |
| 複掃比較 | 人工比對兩份報告 | 先判斷可比性，再分成 new / persistent / not_observed / inconclusive / not_comparable；「沒再看到」不等於「已修好」 | T22、RQ3 |
| 證據與秘密 | 原始輸出可能含 Token，散落在本機 | 原始證據加密且受限保存；一般 API、log 與報告只提供遮罩後的資料 | SEC-14、SEC-17、SEC-18 |

**限制聲明**：上表列的是本系統提供的流程與控制。整合後是否真的增加可確認的發現、或減少人工整理時間，要由 RQ1、RQ2 的實驗回答，不預先宣稱。系統不保證找到所有漏洞，也不取代人工滲透測試。

## 4. 範圍

### 4.1 P0：第一版必須完成（M0–M5）

- 平台 API key 與 project 權限
- Target 與 ScopeGrant（含管理員核准、期限、`LAB_ONLY`）
- OpenAPI 3.0 規格上傳（不抓遠端）
- 目標認證：靜態 Bearer、API key header、既有 Cookie
- PostgreSQL 工作佇列（`FOR UPDATE SKIP LOCKED`）
- runner、單次掃描容器與 egress guard
- ZAP Adapter（Web 與 API 兩個 profile）、Nuclei Adapter（凍結的模板清單）
- Observation/Finding、保守去重、OWASP Top 10:2025 與 API Security Top 10:2023 對應
- JSON/Markdown 報告、人工 triage、複掃比較
- 遮罩、稽核與實驗（Juice Shop、VAmPI、自製 fixture app）

各項的驗收重點見 `PROJECT_PLAN.md` §5.1。

### 4.2 P1：P0 Gate 通過後才開始（M6）

Schemathesis Adapter（security / contract / robustness 分開統計）、SARIF 匯出、dogfooding、OpenAPI 3.1、更精細的 operation 覆蓋率、CI 呼叫範例。

`SECURITY_AND_TESTING.md` §9 的 Gate A–D 沒有通過時，M6 改為補強，不接第三引擎。

### 4.3 不做

- **沒有任何自訂前端**：不開發 React、Vue、Next.js 或其他前端，也不做互動式儀表板。以 REST API、內建 API 文件（僅開發環境）、HTTP client 與 JSON/Markdown 報告展示。
- AI 自動判讀、RAG、原始碼 SAST 與白箱分析
- HTTPS 目標（列為延伸）、完整 GraphQL、WebSocket、SOAP、檔案上傳流程
- OAuth、SSO、MFA 自動登入
- 容器/主機 CVE 掃描、手機 App、全網資產盤點、任意 shell 或模板執行、外部 OAST、自動修補、正式站台、商用多租戶
- 第四套掃描工具

## 5. 研究問題

| RQ | 問題 | 主要衡量 |
|---|---|---|
| RQ1 | 在相同總掃描預算下，多引擎是否增加可確認的安全發現？ | recall、precision、獨有 TP、耗時、請求數 |
| RQ2 | 統一格式與去重是否降低人工整理負擔？ | 去重 precision/recall、誤合併、人工整理時間 |
| RQ3 | 系統是否能正確處理越界、失敗與複掃的不確定性？ | 越界時的實際收包數、取消與清理、錯誤狀態、誤判為已修補的次數 |

比較組別與實驗設計見 `PROJECT_PLAN.md` §3 與 `SECURITY_AND_TESTING.md` §5–§7。

## 6. 待驗證假設

以下是研究假設，不是已完成的市場調查（來源：`PROJECT_PLAN.md` §2.2）。

| # | 假設 | 驗證方式 | 驗證時點 |
|---|---|---|---|
| H1 | 多工具各自設定認證、範圍與輸出，導入步驟分散 | 記錄完成相同任務所需的步驟、時間與錯誤（人工工作量實驗，`SECURITY_AND_TESTING.md` §7.5，選做） | M7 |
| H2 | 開發者難以判斷多份告警是否重複 | 人工標記重複配對，量測誤合併與漏合併（RQ2） | M4 去重反例測試、M7 實驗 |
| H3 | 掃描失敗與零告警容易混淆 | timeout、憑證失效、Parser 錯誤等故障注入測試 | M1 起以 FakeRunner 驗證，M3–M4 以真實工具驗證 |
| H4 | 修補後缺少可比較的紀錄 | 以已知修補與未修補的 fixture 驗證複掃分類（RQ3） | M5（T22） |
| H5 | 掃描過程可能越界或洩漏測試 Token | 被封鎖靶場的實際收包數、秘密遮罩測試（SEC 測試矩陣） | M2 起 |

時間允許時，訪談 2–3 位有實際開發或測試經驗的人（選做，不影響 P0）。

## 7. 主要限制

- 只掃描自有或已取得書面授權的隔離靶場；未經授權掃描可能觸犯刑法第 36 章（§358–363）。
- P0 只支援 HTTP 靶場。
- 不宣稱能自動判斷 BOLA、多身分權限與業務邏輯問題；多身分權限測試列為後續研究。
- 不宣稱涵蓋全部 OWASP 風險；API6 與 API10 無法以 DAST 偵測。
