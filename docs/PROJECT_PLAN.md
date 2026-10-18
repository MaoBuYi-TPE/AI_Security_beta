# Web 與 API 多引擎動態安全檢測暨結果整合後端系統

版本：規劃稿 1.1（整合版）｜日期：2026-10-16｜狀態：範圍已於 2026-10-17 凍結（見 `REQUIREMENTS.md`）；未實作、未量測

## 1. 專題摘要（可改寫放入提案）

本專題針對需要檢查 Web 應用與 REST API、但缺乏專職資安人力的小型開發團隊，設計一套以後端服務為核心的多引擎動態安全檢測系統。

系統以授權範圍為前提，先整合 ZAP 與 Nuclei 執行不同面向的動態檢測；兩引擎通過驗收後，再加入 Schemathesis 進行 API 規格導向測試。系統透過以下機制，把原本分散的工具輸出轉為可供開發者檢視與追蹤的議題：

- 強制出站邊界
- 單次隔離容器
- 持久化任務管理
- 統一發現格式
- 保守去重
- 證據追溯
- 複掃比較

研究將以受控靶場及固定測試案例，在相同總掃描預算下，比較單一工具與整合流程在以下面向的差異：

- 已知弱點的檢出情形
- 重複資訊負擔
- 執行可靠性
- 人工整理時間

系統不保證發現所有漏洞，不將一般 API 規格違反直接視為資安漏洞，也不取代人工滲透測試。

## 2. 問題定義：不要把「整合工具」當成使用者需求

### 2.1 目標使用者（待訪談驗證）

主要使用者設定為：

- 有 Web/API 上線前檢查需求的小型產品團隊
- 校內專題團隊
- 負責測試的後端工程師

部署場景以自管的測試環境、隔離的 staging 副本與教學靶場為主，不以公開任意 URL 掃描服務為目標。

### 2.2 待驗證的痛點假設

| 假設 | 對應設計 | 要如何驗證，而非只靠宣稱 |
|---|---|---|
| 多工具各自設定認證、範圍及輸出，導入步驟分散 | 統一 target、auth profile、scan profile | 記錄完成相同任務所需步驟、時間及錯誤 |
| 開發者難以判斷多份告警是否重複 | 統一 Observation/Finding 與保守關聯 | 人工標記重複配對，量測誤合併與漏合併 |
| 掃描失敗與零告警容易混淆 | 完整任務/引擎狀態及覆蓋資訊 | 測試 timeout、憑證失效、Parser 錯誤 |
| 修補後缺少可比較的紀錄 | 版本、scope、auth、policy 快照與複掃差異 | 使用已知修補/未修補的 fixture 驗證 |
| 掃描過程可能越界或洩漏測試 Token | 出站約束、授權、秘密遮罩 | 檢查封鎖靶場的實際收包數與資料洩漏 |

上述是研究假設，不是已完成的市場調查。

時間允許時，可以訪談 2–3 位有實際開發或測試經驗的人。訪談為選做，不影響 P0。可以問：

- 最近一次掃描的流程
- 整理報告花了多少時間
- 認證設定遇到的困難
- 最常忽略的資訊

不要只問「你會不會想用」。

### 2.3 核心價值主張

**我們不取代既有掃描器，而是讓開發者能在同一個受控流程中，啟動互補檢測、辨識執行缺口、追溯證據，並比較修補前後的結果。**

相對於單獨使用 ZAP 或 Nuclei，可能增加的價值是工作流程的一致性和結果的可比較性。是否真的增加弱點檢出或減少工時，必須由實驗確認。不能只因工具數量增加，就宣稱準確率更高。

## 3. 題目定位與三個研究問題

建議題目：**Web 與 API 多引擎動態安全檢測暨結果整合後端系統之設計與實作**。

這是「系統設計 + 可重現實驗」型的畢業專題，不必硬包裝成新的漏洞偵測演算法。即使提供 Token 與 OpenAPI，仍屬於具規格/認證資訊的動態測試，不會因此變成原始碼白箱分析。

| 研究問題 | 比較方式 | 主要衡量 |
|---|---|---|
| RQ1：在相同總掃描預算下，多引擎是否增加可確認的安全發現？ | ZAP、Nuclei、ZAP+Nuclei；第三引擎完成後，追加 Schemathesis 與三引擎組合 | 已知案例的 recall、precision、獨有 TP、耗時與請求數。另以探索性分析檢視「多引擎一致」與 TP 的關係（不作為合併或升級規則） |
| RQ2：統一格式與去重是否降低人工整理負擔？ | 同一組輸出：未合併列表 vs 保守去重後列表 | 去重 precision/recall、誤合併、人工整理時間 |
| RQ3：系統是否能正確處理越界、失敗與複掃的不確定性？ | 注入故障，並使用已知的修補狀態 | 越界時的實際收包數、取消/清理、錯誤狀態、誤判為已修復的次數 |

## 4. 掃描工具選型

### 4.1 三個引擎，分階段加入

| 引擎 | 專題角色 | 結果來源 | 階段 |
|---|---|---|---|
| ZAP（2.17.x）[S22] | Web 爬取、被動/主動檢查、OpenAPI 導向的 API 掃描 | 固定版本的 JSON 報告，以及必要的流量/進度資訊 | P0（M3） |
| Nuclei（v3.11.x）[S23] | 以凍結的 HTTP 模板清單檢查已知問題、暴露資訊與錯誤設定 | JSONL findings、執行 metadata、guard 流量紀錄 | P0（M4） |
| Schemathesis（4.x）[S07] | 依 OpenAPI 產生 API 邊界/負向輸入與規格檢查 | 鎖定版本的 JSON/NDJSON；必要時加 JUnit | P1（M6，P0 Gate 通過後） |

表中版本是 2026-10 的查核值；T03 已鎖定確切版本與映像 digest（見 `TOOLS.md`）。各工具的執行方式見 `ARCHITECTURE.md` §5。

- **ZAP**：Automation Framework 可用於工作編排；API 掃描會依輸入的規格匯入端點。Web profile 與 API profile 不應混為同一套設定。[S02–S05]
- **Nuclei**：以模板執行檢查，提供 JSONL、速率與模板控制。本專題只使用受限的 HTTP 模板，不會把所有模板與協定全部打開。[S06]
- **Schemathesis**：規格/性質導向的動態 API 測試工具，不是單純的傳統漏洞掃描器。可輸出 JSON/NDJSON 等報告；實際格式以鎖定的版本為準。[S07–S09]

### 4.2 不要誇大第三引擎的安全意義

- 某個輸入造成 HTTP 500，可以是健壯性問題；回應不符 schema，可以是契約問題。
- 只有存在相應的安全影響與證據時，才適合人工歸類為資安發現。
- 預設保留 `security / contract / robustness / informational` 四類，並分別計數。

BOLA、權限越界與業務流程問題涉及「哪個身分可以存取哪個物件」，不能只靠 API 規格與一次回應就保證全面判斷。[S14] 多身分權限測試列為後續研究，不列為第一版已覆蓋的能力。

### 4.3 本版不再加第四套工具

不加入另一個大型 DAST、單一 SQL 注入工具或主機弱掃套件來湊數。

第三引擎的加入條件（P0 Gate）是：前兩個引擎已完成真實端到端掃描、解析、取消、錯誤處理與報告。條件未達成時，把時間用在可靠性和實驗上。

## 5. 功能範圍與明確排除

### 5.1 P0：第一版必須完成（M0–M5）

| 模組 | 最小可交付內容 | 驗收重點 |
|---|---|---|
| 平台存取 | 管理員、專案操作、唯讀三種 API key | 無公開註冊；跨專案不可讀寫 |
| 目標與授權 | Target + ScopeGrant，含期限與允許的 origin/IP/path/method；`LAB_ONLY` 時 IP 須在 `LAB_CIDR` 內 | 核准前不能掃；範圍變更需新快照 |
| API 規格 | 上傳 OpenAPI 3.0 JSON/安全 YAML，固定目標 origin | 僅同文件 $ref；不抓外部 URL |
| 目標認證 | 靜態 Bearer、API key header、既有 Cookie | 加密、只寫不讀、protected preflight |
| 任務管理 | PostgreSQL 工作佇列：建立、認領、查詢、取消、超時、故障追蹤 | 不因 API 或 runner 重啟而丟失狀態 |
| Runner 與出站邊界 | 單次容器（固定 digest、非 root、唯讀）、docker-socket-proxy、egress guard（scope、共享預算、telemetry） | 掃描器只連得到 guard；越界的實際收包為 0 |
| ZAP Adapter | Web 與 API 兩個受控 profile | 真實輸出可解析；零告警不等於失敗 |
| Nuclei Adapter | 凍結的模板 ID 清單與 JSONL Parser | 不執行任意模板；關閉 OAST；保存版本資訊 |
| 結果處理 | Observation、Finding、保守去重、OWASP Top 10:2025 / API 2023 對應 | 不刪除來源；不把同 CWE 的告警一律合併 |
| 報告與複掃 | JSON/Markdown 報告、triage、可比性判定 | 未再觀察到不自動等於已修補 |
| 安全與稽核 | 遮罩、scope、權限、審批/操作紀錄 | secrets 不進一般 log 或報告 |
| 實驗 | Juice Shop 選定案例、VAmPI vulnerable/secure、自製可切換 fixture app | 單工具與整合工具使用相同總預算 |

### 5.2 P1：P0 Gate 通過後（M6）

- Schemathesis Adapter（security / contract / robustness 分開統計）
- SARIF 匯出
- 用 Schemathesis 掃描平台自己的 API（dogfooding）
- OpenAPI 3.1 相容性
- 更精細的 API operation 覆蓋率
- 一份 CI pipeline 呼叫範例

報告以 JSON/Markdown 為主；HTML/PDF 報告與 dashboard 不在必要範圍內。

### 5.3 本版不做

- 介面與分析：自訂前端、AI 自動判讀/RAG、原始碼 SAST
- 目標與協定：容器/主機 CVE 掃描、HTTPS 目標（需要 CA 與 guard 測試，列為延伸）、完整 GraphQL 支援、WebSocket、SOAP、檔案上傳流程掃描
- 認證：OAuth/SSO/MFA 自動登入
- 其他：手機 App、全網資產盤點、任意 shell/模板執行、外部 OAST、自動修補、正式站台、商用多租戶

第三方靶場本身可能附帶頁面，不代表本專題需要開發前端。REST API 與內建 API 文件就足以展示後端。

## 6. 使用者流程

1. 操作人員向管理員取得有專案權限的 API key。
2. 操作人員建立 target，並申請 scope。
3. 管理員核對這是自有或已授權的環境，限定允許範圍與期限後核准。
4. 操作人員上傳已去識別化的 API 規格與必要的測試認證資料，選擇 profile 後提交 scan。
5. 系統回傳 scan_id。runner 在重新確認 scope 與認證後執行工具；所有流量都經過 egress guard。
6. 完成後，使用者查閱統一的 findings 與各引擎狀態，標註誤報或確認問題。
7. 修補後再建立新的 scan，做差異比較。

重要：舊 scan 一律保留。複掃是新的一次執行，不覆蓋舊證據，也不重用舊的任務狀態。

## 7. 後端技術與架構決策

| 層次 | 建議選擇 | 原因與取捨 |
|---|---|---|
| API | Python 3.12 + FastAPI + Pydantic 2 | 以有型別的 REST 契約實作，不做 UI |
| 持久化 | PostgreSQL + SQLAlchemy 2 + Alembic | 保存任務、結果、權限、快照與 migration |
| 非同步工作 | PostgreSQL 工作佇列，以 `FOR UPDATE SKIP LOCKED` 認領 [S28] | 掃描與工作在同一個 transaction 建立，不需要 broker 與 outbox |
| 啟動與隔離 | Docker 單次容器；runner 經 docker-socket-proxy 存取 Docker [S27] | 各掃描器環境分離；只有 runner 有 Docker API 權限 |
| 出站控制 | mitmproxy addon（egress guard）[S18] + internal Docker networks | 不能只依賴掃描器自己守 scope |
| 報告 | JSON + Markdown（P1 加 SARIF） | 易於 API/CI 使用，不做前端頁面 |
| 測試 | pytest、Hypothesis、pytest-socket；整合測試用 compose 的 `db-test`（`DECISIONS.md` §7）；分成 fixture/contract/integration/security/live 幾層 | Mock 與 live 分開，不混淆完成度 |
| 依賴固定 | uv.lock、映像 digest、模板 release/hash | 讓實驗與 Parser 版本可以追溯 |

FastAPI 官方說明：較重、需要獨立程序執行的工作，應交給外部的工作佇列工具處理。[S10] 本專題把掃描交給獨立的 runner 程序，並以 PostgreSQL 資料列作為工作佇列；不採用 message broker 的理由見 `DECISIONS.md` §3。

系統仍不宣稱 exactly-once：開始發流量後若中斷，就標記為 interrupted，由使用者以新的 scan 重跑。

架構採用「模組化單體 + 單一 runner」，不拆成微服務：

- api、worker（解析與報告）、runner、egress guard 是同一個 codebase 的不同程序，各自只拿最小權限。
- 同一 target 的引擎依序執行，共用掃描預算，降低競爭與故障排查成本。

詳細資料模型與狀態見 `ARCHITECTURE.md`；路由契約見 `API_CONTRACT.md`。

## 8. 專題要自己實作什麼

你不必重寫 SQL 注入或 XSS 的掃描邏輯。應該自己實作的是：

- 授權/範圍模型
- egress guard 的 scope 與預算規則
- 任務生命週期與工作佇列
- Adapter 與 Parser
- 憑證注入
- Observation/Finding 模型
- 去重規則與 OWASP 對應
- 可比性判定
- 實驗流程

這些部分都必須有測試和設計理由，才能和「單純寫三行 CLI 的包裝」區別開來。

不將「AI 寫了程式」列為功能成果；Claude Code 只是開發工具。未來的 AI 摘要可以用去識別化的證據作為輸入，但仍須保留引用和人工判斷；本版不以此為核心。

## 9. 可靠性、可重現性與限制

每次 scan 保存以下資訊：

- 版本：target、scope、spec、auth role 的版本
- 工具：映像 digest、ZAP add-on 版本、Nuclei 模板 hash
- 設定：profile、guard policy hash
- 執行：程式 commit、測試 seed、靶場快照
- 結果：guard 計數的實際請求數、完成原因

隨機工具、目標狀態與網路仍會造成差異。固定版本是為了提高可追溯性，不保證每次結果 byte-for-byte 相同。

限制：

- 沒有 OpenAPI 時，只做可發現的 Web/端點檢查，不宣稱 API 規格覆蓋完整。
- 認證失效時，標記 auth coverage 不完整。
- 前端瀏覽器的深度流程、複雜登入與業務邏輯問題，列為限制。

## 10. 時程（1 人，2026/10/16 – 2027/06/30，約 37 週）

| 里程碑 | 期間 | 交付 | 放行條件 |
|---|---|---|---|
| M0 可行性與環境 | 10/16 – 11/08 | uv、OrbStack、專案骨架與品質命令；lab compose；三工具經 proxy 的 smoke test；真實輸出 fixture；請求量量測；版本、digest 與授權條款紀錄 | 取得真實輸出樣本；不能只看到程序啟動 |
| M1 API/資料基礎 | 11/09 – 12/13 | FastAPI、DB、API key/project、target、ScopeGrant、spec、auth profile、scan 與 scanner_run 工作佇列、Idempotency、狀態機、FakeRunner、events、audit | 不啟動真工具，也能完成任務流程與權限測試 |
| M2 Runner 與安全邊界 | 12/14 – 01/24 | runner + socket-proxy、容器強化、internal networks、egress guard、共享預算、heartbeat/lease、取消、timeout、對帳 | 越界的實際收包為 0、取消後沒有孤兒容器；上學期成果展示 |
| M3 ZAP 真整合 | 01/25 – 02/28 | Web/API profile、auth preflight、JSON Parser；開始建立 fixture app 與 ground truth | 已知靶場的正常/異常、失敗與取消都能辨識 |
| M4 Nuclei 與結果整合 | 03/01 – 04/04 | 凍結的模板清單、JSONL Parser、Observation/Finding、rule_groups、OWASP 對應、去重 | 兩引擎完成同一端到端流程，且沒有誤合併 |
| M5 報告與複掃（P0 驗收） | 04/05 – 04/25 | triage、JSON/Markdown、可比性與差異分類、覆蓋率、原始證據加密、benchmark harness | Gate A–D 通過；不可比或認證失效時，不會被宣稱已修補 |
| M6 第三引擎或補強 | 04/26 – 05/23 | Schemathesis、SARIF、dogfooding、CI 範例 | P0 Gate 未過就不加第三引擎，改為補強 |
| M7 實驗與口試 | 05/24 – 06/30 | 重複實驗（約 3 週）、分析、報告、展示腳本 | 原始結果可追溯；能在乾淨環境重建一輪示範 |

- **學期安排**：M2 涵蓋期末考，M3 涵蓋寒假與農曆年，負荷已預先調低。學校成果展的日期確定後，再調整 M6–M7。
- **單人開發的補償做法**：
  - 每個里程碑結束時，跑 code-reviewer 與 security-reviewer agent。
  - 安全邊界設計、去重規則與實驗標記，請指導教授審閱。
  - ground truth 請同學抽樣複核。
- **進度落後時的降階順序**：
  1. 先砍 CI 範例。
  2. 再砍 SARIF。
  3. 最後把 M6 改為補強，不接 Schemathesis。

  不能用刪除授權、隔離和故障處理來換取工具數量。

## 11. 開發環境與資源假設

- **開發機**：Apple M1 Pro、16 GB RAM、macOS + OrbStack。
  - 規劃時 OrbStack 尚未啟動，`docker compose` 子命令也不能用。在 M0 修好之前，可以先用已安裝的 `docker-compose`（v5.1.2）。
- **記憶體**：
  - 規劃讓 OrbStack 使用 10–12 GB；ZAP 單次容器預估 2–3 GB，以 M0 實際量測為準。
  - T03 實測本機 OrbStack 預設上限為 **8 GiB**（低於規劃）。M3 ZAP active scan 前需確認是否調高，或據此調整 lab profile 預算，並在報告揭露。
  - 一次只跑一個 ZAP；靶機用 compose profiles 分開啟動。
- **隔離方式**：控制平面與 runner 在同一台機器，以 internal networks、docker-socket-proxy 與非 root 容器隔離。
  - runner 的 Docker 權限是殘餘風險。[S12]
  - 如果要掃描 lab 以外的授權目標，runner 與掃描容器需要移到獨立、可重建的 VM。
- **磁碟**：預留 50 GB 以上，放映像、靶機與實驗原始資料。

不需要 GPU，也不需要 LLM API 或向量資料庫。先不購買雲端服務。開源工具的實際授權與再散布要求需在 M0 記錄，不應把「可以下載」視為所有用途都沒有限制。[S02–S09]

證據的建議留存上限：加密的原始資料 7 日、遮罩後的報告 30 日，可依校內要求調整。磁碟容量、敏感資料與保留期間須寫入運維文件，不無限堆積 HAR 或 response body。

## 12. 主要風險與降階策略

| 風險 | 早期徵兆 | 應對 |
|---|---|---|
| 工具的 proxy/auth 設定不一致 | 工具直接連外，或登入前後結果相同 | M0 以經 proxy 的 smoke test 驗證；不受控的 profile 不放行 |
| 工具在只能連 guard 的網路中無法運作 | 解析不到靶機名稱，或繞過 proxy | M0/M2 實測；不能運作的工具或 profile 不啟用（fail closed） |
| runner 的 Docker API 權限 | 開發機上必須讓 runner 存取 Docker | socket-proxy 只開容器 API、驗證 ExecutionPlan、runner 不解析不可信資料；非 lab 用途改用獨立 VM |
| API 程式完成，但掃描仍不可靠 | 只有 Mock，沒有真實 Parser fixtures | M3/M4 各設 live DoD，不拖到期末 |
| 去重錯誤把漏洞藏起來 | 相同 CWE 被合併成一筆 | 用保守的語意映射、保留 observation、測試誤合併 |
| 預算太低，掃描被截斷 | ZAP 主動掃描在預算內做不完 | M3 依量測調整 lab profile，並在報告中揭露 |
| 三工具全開拖垮靶場 | 5xx 增加、延遲變長、記憶體上升 | 共用預算、串行執行、健康監測、狀態化停止 |
| 第三工具的結果不像資安漏洞 | 大量 schema 或 500 告警 | 分類並分開評估，不灌水 security 數量 |
| scope 太複雜而做不完 | 兩週過去仍沒有「拒絕越界」的測試 | 先只支援隔離的 HTTP 靶場；HTTPS 列為延伸 |
| 報告過度承諾 | 零告警被寫成「安全」 | 強制顯示範圍、失敗、未測項目與不確定性 |
| 實驗只為自己的規則量身打造 | 每加一個 fixture 就寫一個模板 | 保留 holdout、凍結模板、把自訂規則的實驗分開 |
| 單人進度落後 | 里程碑的放行條件未達成 | 依 §10 的降階順序處理 |

## 13. 驗收標準

以下所有數值都是**驗收目標**，不是現有成績。

- **功能**：兩工具都必須能從 API 建立掃描並取得真實 findings，並能展示這些情境：auth 掃描、取消、超時、工具壞掉、Parser 壞掉、部分結果、複掃比較。
- **安全**：
  - 預定測試集合中的越界流量，不得抵達被禁止的目標（以 canary 的收包為準）。
  - 跨專案讀取必須被阻止。
  - 已知秘密不得出現在一般回應、log 或報告中。
  - 網路 guard 失敗時，不得預設放行。
  - 測試集合通過，不代表全世界的繞過方式都已防住。
- **品質**：
  - 整體 coverage ≥ 80%。
  - scope/guard/狀態機/去重/遮罩模組的 branch coverage ≥ 90%。
  - 設計好的安全負向測試全數通過。
  - 受控重複執行以 ≥ 95% 正常完成率作為觀察目標；未達成時如實分析，不改寫數據。
- **研究**：
  - 需呈現單工具與整合版本的 TP/FP/FN、請求量、耗時、去重錯誤，以及至少一次已知的修補情境。
  - 不得預先承諾「比單一工具高多少百分比」。

## 14. 最終交付與展示

交付內容：

- 完整後端原始碼與依賴鎖檔
- Docker/網路設定、DB migration
- API 規格與操作文件
- 授權的靶場環境與測試集
- 已去識別化的輸出與實驗結果
- 畢業專題報告

原始密鑰、Token、個資與未遮罩的第三方證據，不交付到公開的 Git。

展示時以 API client 依序呼叫：

1. 建立 target 並申請 scope。
2. 提交兩引擎 scan。
3. 查詢狀態，以及 guard 計數的實際請求量。
4. 查詢 findings 與 evidence。
5. 展示同一個問題有多個來源。
6. 切換到已修補的靶場（VAmPI secure 或 fixture 修補版）。
7. 複掃並比較。
8. 展示越界被拒絕（canary 收包為 0）與取消。

現場不必等全量掃描跑完：可以使用已保存、並註明時間與版本的真實結果，再即時執行一個小型的受控案例。

建議的報告章節：緒論、需求分析、相關工具與文獻、系統設計（含 `DECISIONS.md` 的設計取捨）、系統實作、安全與測試、實驗分析、結論與限制。每個「改善」都要對應到實驗表格或測試證據。

## 15. 一句話界定成功

**成功不是接了三個工具，而是每個接入的工具都能在核准範圍內可靠執行，產生可追溯、不誤導的結果，並以實驗證明整合流程的價值與限制。**
