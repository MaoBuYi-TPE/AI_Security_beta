# 安全需求、測試計畫與實驗方法

狀態：待實作與待測試。只有達到以下測試要求後，才能在文件中標註對應能力完成。

## 1. 測試前提

本平台是會主動對外發送測試請求的系統。所有 live 測試僅限自有或權利人明確授權的隔離靶場，使用測試身分與可重建資料，不對公開 demo、學校正式系統、同學未授權專案或外部網站執行。

預設 LAB_ONLY；unit/contract 不可出網。live 測試需 `ENABLE_LIVE_LAB_TESTS=1`、有效 grant、已驗證隔離網路及明確的 pytest 標籤。測試 code 本身不應含任意 Internet URL 掃描流程。

## 2. 威脅模型

| 不可信來源/風險 | 受保護資產 | 控制 |
|---|---|---|
| 操作者輸入惡意 URL/spec | 內部管理網與其他網站 | scope、DNS/IP/redirect 驗證、封鎖出站、拒絕外部 refs |
| 操作者跨專案猜 ID | 他人目標、secret、報告 | key/project/object-level 授權 |
| 被測頁面或 API 回應 | Parser、報告、AI 開發流程 | 當資料處理、限制大小、編碼、不可當指令 |
| 被修改或過度危險的模板 | 靶場狀態、Runner | 審查 allowlist、固定 hash、禁 code/OAST/未受控協定 |
| Scanner 遭利用 | Runner 與控制平面 | 非 root、唯讀 rootfs、無 socket、只接 scan_net（只能連 guard） |
| 重複認領/Runner 中斷 | 掃描可靠性、靶場資料 | SKIP LOCKED 認領、lease、container label、reconciler、避免盲目重掃 |
| runner 的 Docker API 權限被濫用 | 開發機上的容器與資料 | socket-proxy 只開容器 API；驗證 ExecutionPlan 的 digest、參數、掛載與網路；runner 不解析不可信資料；非 lab 用途移到獨立 VM |
| 原始報告含 Token/個資 | 身分憑證與受測資料 | 加密受限存放、一般介面遮罩、留存刪除 |
| 報告說法誤導 | 使用者判斷 | 分開零告警/失敗/未測；人工 triage；複掃可比性 |

只寫一份使用同意書或 CLAUDE.md 不構成技術強制邊界；控制必須存在於程式、OS/網路和測試。[S01,S12,S13]

## 3. 安全測試矩陣

| 編號 | 情境 | 必須看到的結果/證據 |
|---|---|---|
| SEC-01 | 未核准/過期/撤銷 grant | 建立或開始掃描被拒，已執行者停止新出站 |
| SEC-02 | URL、scope origin、spec server 不一致 | 拒絕或固定綁定到核准 origin；不可打到 spec 內任意位址 |
| SEC-03 | redirect 至禁止靶場 | 禁止靶場實際收到的請求為 0，不只 API 顯示 blocked |
| SEC-04 | 測試 DNS 在驗證與連線間變更 | 未授權 IP 實際收包為 0，顯示 scope/IP 錯誤 |
| SEC-05 | 使用 IPv4/IPv6、替代 host 表示、userinfo 等差異 | 嚴格解析或明確拒絕；不能繞過 allowlist |
| SEC-06 | 連宿主/metadata/DB/docker-socket-proxy/Docker 控制端 | 應用層與網路層雙重阻擋；隔離接收端證明 |
| SEC-07 | 掃描器不使用 proxy 嘗試直連 | 網路層拒絕；不能僅靠 HTTP_PROXY 環境變數 |
| SEC-08 | 禁止 path/method、編碼路徑歧義 | 禁止端點實際收包為 0；無法可靠辨識時 fail closed |
| SEC-09 | HTTPS CONNECT/authority/SNI 不相符 | 在上游連線前拒絕；未核准目標無 TLS sniffing 連線 |
| SEC-10 | 上游憑證無效/guard 配置失敗 | 拒絕或標 profile 不可用，不以 skip verify 避開 |
| SEC-11 | OpenAPI remote/file ref、深度/大小異常 | 解析拒絕且無外部讀檔/出網 |
| SEC-12 | 非核准模板、shell、映像、mount 參數 | Schema/launcher 拒絕，未產生額外程序 |
| SEC-13 | 超過 target 合計速率/請求/時間預算 | 以 guard/靶場紀錄核對，包含多引擎與 preflight |
| SEC-14 | Token 位於 header/query/body/error message | 一般 API/log/report 無原文；raw 證據僅受限加密 |
| SEC-15 | Authorization/Cookie 跨 origin | 不傳送到其他 host；使用本機接收器確認 |
| SEC-16 | A 專案 key 讀寫 B 專案 scan/finding/artifact | 404/403，無資訊洩漏 |
| SEC-17 | 惡意 JSONL/XML/Markdown/大輸出 | Parser 有界失敗、無外部實體或命令執行、報告安全呈現 |
| SEC-18 | artifact path traversal/symlink/任意 storage key | 無法讀寫工作目錄以外內容 |
| SEC-19 | scan cancel 後工具仍跑 | 先禁止新流量、後回收工具；不是只改 DB |
| SEC-20 | 外部輸出內含提示要求讀 secret 或改安全設定 | 僅存為證據資料，不遵循；CI/開發流程不自動執行 |
| SEC-21 | ExecutionPlan 含未核准的映像、host mount、privileged、其他網路，或 runner 呼叫 exec/volumes 等 API | plan 驗證拒絕；socket-proxy 對未開放的區段回 403；沒有產生容器 |

SEC-03/04/05 等使用完全在本機測試網路的接收器與 mock DNS，不需要碰真實第三方資源。對所有已知測試通過只能代表測試集內有效，不是完備防禦的證明。

## 4. 一般工程測試

所有功能都採 TDD：先寫會失敗的測試，再實作。覆蓋率門檻：

- 整體 coverage ≥ 80%。
- 核心安全模組（scope/policy、egress guard、狀態機、fingerprint、遮罩）branch coverage ≥ 90%。

覆蓋率不是唯一的品質指標，安全負向測試必須全數通過。

### 4.1 Unit

測試項目：

- Target canonicalization、scope matching、guard policy 比對、policy budget
- request hash、狀態轉移、工作認領與 lease 轉移
- 版本可比性、severity mapping、fingerprint
- secret redaction、artifact path validation

常見和邊界輸入都要測。fingerprint 與 URL 正規化用 Hypothesis 做 property test；unit 測試以 pytest-socket 禁止連網。psycopg 經 libpq 連線，pytest-socket 擋不到，所以非整合測試另由 `tests/conftest.py` 封鎖 DB 連線；測試也不讀 `.env`（T04）。

### 4.2 Contract / Parser

每個鎖定版本保存遮罩後真實輸出 fixture：正常無告警、存在告警、非零退出但有有效 findings、格式截斷、未知欄位、缺必要欄位、空檔、重複事件、Unicode、超大單行/總量、timeout 後部分 artifact。版本不支援時明確 error，不默默漏掉資料。

### 4.3 Integration

以 PostgreSQL（compose 的 `db-test`，見 `DECISIONS.md` §7）+ FakeRunner 驗證。每個測試 session 以專屬的非 superuser 角色與全新資料庫執行，伺服器必須是 `cluster_name=secscan-test`；測試程序本身不碰 Docker daemon。驗證項目：

- 交易一致性
- SKIP LOCKED 認領、重複認領、lease 過期
- target 互斥
- 權限
- migration
- 報告與比較

普通 CI 不啟動真實掃描器，也不出網。

### 4.4 Live E2E

完整 API → scope → auth → queue → Runner → 工具 → Parser → Finding → report。工具只在隔離靶場跑。每個 Adapter 的 live success 與其 unit test 成功分開標示。

### 4.5 故障注入

在 queued/preparing/running/collecting/collected/normalizing 各階段，分別中斷 api、runner 或 worker。另外要測：

- 兩個 runner 同時認領同一個 run
- lease 過期，但容器仍在執行
- DB 暫時不可用
- guard 不可用（必須 fail closed）
- 磁碟滿、容器 OOM、解析例外
- Token 到期、手動取消

結果要求：無重複同 run 活躍容器；未證明舊 run 停止前不啟動新 run；partial evidence 不被刪除；狀態不能永久顯示 running；不將錯誤轉為「0 漏洞」。

## 5. 實驗資料與靶場

### 5.1 最小資料集

建立 12 個人工可確認的安全正例與對應 12 個修補負例，共 24 個受控案例。候選類型包括 SQL 注入、反射型 XSS、可見錯誤資訊洩漏、目錄/敏感檔案暴露與可確認的安全設定問題；實際類型以審核後的工具能力與安全場景為準，不保證每個引擎都能命中。

另建立 6 個 API 契約/健壯性正例與 6 個修補負例，獨立標記、不加入 security TP/FP。每個案例需記 case_id、target、method/path、auth role、弱點/檢查類別、預期行為、人工確認方式、修補差異與是否屬於測試支援範圍。

三類靶場：

1. 自己部署的 Juice Shop 選定案例（Web）[S16]。
2. VAmPI：以 `vulnerable=1/0` 切換弱點版與安全版，安全版作為負控制組（API）[S26]。
3. 自製可切換弱點版本的 fixture app：同時包含 Web 與 OpenAPI 案例，提供精確的 ground truth 與修補版。

crAPI、DVWA 是替代擴充，不增加必要工作量 [S17]。fixture app 只放在 lab_net，只為測試服務，不是在開發產品前端。

### 5.2 Ground truth

由本人依修補 diff、重現步驟與程式測試標記正/負例，不以「某掃描器報了」當作唯一的真實標籤。

接著請指導教授或同學抽樣複核至少 20% 的案例，分歧需記錄與裁定。單人標記可能造成的偏差，列為效度威脅。

保留約 25% 案例作為 holdout，在 mapper/template/profile 調整階段不使用。模板與規則凍結後才跑 holdout。不為每個測試案例另寫一條 Nuclei 模板後宣稱泛化能力；自訂模板需分成獨立實驗組。

## 6. 比較組與公平預算

P0 組別：A=ZAP、B=Nuclei、C=ZAP+Nuclei。P1 完成第三引擎才加入 D=Schemathesis、E=三引擎整合。契約/健壯性與安全分開評估。

重複次數與執行矩陣：

- 每組每類靶場重複 5 次。時間不足時至少 3 次，並在報告中揭露。
- 每次都重置為相同的資料快照，使用相同的認證、route 與 scope。
- P0 基本矩陣：3 組 × 3 類靶場 × 5 次 = 45 次執行。
- P1 完成後：5 組 × 3 類 × 5 次 = 75 次。沒有 OpenAPI 的靶場不適用 Schemathesis，該格記為 N/A。

這是計畫，不表示已完成。

主要比較採每個 scan **相同總請求數與牆鐘時間上限**（由 egress guard 強制執行），不是每個工具各給完整預算後讓整合組多用 2–3 倍資源。組合組先分配子預算並凍結分配，總額與單工具組一致。額外可做累加預算情境，但需獨立展示耗費。

記錄各工具自身限速與 guard 合計計數。以實際上游送出請求為基準，不只看 CLI 的 requests count。執行順序隨機化；Schemathesis 保存 seed，仍需重複執行以觀察隨機性。

## 7. 指標定義

### 7.1 檢出表現

`Precision = TP / (TP + FP)`。

`Recall = TP / (TP + FN)`，僅限列入評估、人工已知且在授權支援範圍的安全案例。分母不是所有可能漏洞；未支援類別另外披露，不為了好看刪掉已宣稱支援但沒找到的案例。

`F1 = 2 × Precision × Recall / (Precision + Recall)`。分母為 0 時顯示 N/A，不填 100%。同一真實問題由兩工具命中，在整合組只算一個 TP；CWE 不同或位置不同不能任意對齊。

可報每工具獨有 TP、聯集 TP、總請求量、牆鐘時間、CPU/RAM peak、完成率。使用中位數與範圍/IQR，重複樣本足夠時再附不確定性估計；小樣本不宣稱有普遍統計優勢。

另外，把 finding 依「是否有 2 個以上引擎命中」分成兩組，比較兩組的 precision，作為 RQ1 的探索性分析。這個分組不作為合併 finding 或升級 severity 的規則。

### 7.2 去重品質

先由人工標記哪些 Observation pairs 是同一問題。

`Dedup precision = 正確合併的 pair 數 / 所有合併的 pair 數`。

`Dedup recall = 正確合併的 pair 數 / 所有應合併的 pair 數`。

另報誤合併案例、漏合併案例、聚合前後條數。`1 - finding_count / observation_count` 只能稱列表壓縮比例，不是漏洞誤報率改善，更不是掃描器 precision 改善。

### 7.3 API 覆蓋

`Operation coverage = 至少一次實際請求的核准 (method,path) 數 / 可測核准 (method,path) 數`。

再分別報認證覆蓋、引擎/check 執行覆蓋及被排除的操作。單次對 endpoint 發 GET 不代表完成該 endpoint 所有安全測試。沒有可信分母時回 N/A。

### 7.4 複掃

用已知未修補、已修補、auth 失效、工具失敗、scope 減少、模板變動等情境，檢查 persistent/not_observed/inconclusive/not_comparable 是否正確。尤其統計「誤判已修補」的情形；第一版不自動關閉，因此需確認 API/報告也不暗示已修補。

### 7.5 人工工作量（可選）

讓 3–5 名具基礎開發背景者對相同輸出，完成辨識獨立議題、定位證據與指出未完成引擎的任務。比較未整合與整合呈現的時間/正確率，交錯先後順序降低學習效應。樣本小，只當探索性可用性結果，不宣稱代表全產業。

## 8. 資料保存與公開

每次實驗記錄 run_manifest、程式 commit、映像 digest、模板/spec hash、靶場 snapshot、seed、時間、預算、實際請求、狀態與標記表。原始資料只存隔離受限環境，加密且設定留存；公開附件以遮罩且去識別化資料為限。

建議遮罩 fixture 至少含一組可檢查的 synthetic secret，CI 搜尋它是否出現在不允許的輸出。不能只測 Authorization header，還需測 Cookie、query、body、stack trace、重現命令。

## 9. 發布前 Gate

Gate A：兩個真實 Adapter 通過 live e2e。

Gate B：SEC-01 至 SEC-20 適用測試有結果；未支援能力明確關閉。所有已啟用功能的必測安全案例通過。

Gate C：取消/故障/重送/partial 狀態測試通過。

Gate D：去重與複掃的反例測試通過，報告無未驗證誇大敘述。

Gate E：以乾淨環境（新 clone、新 volume）重建 smoke test，版本/輸出可追溯；可能的話，請同學依文件獨立重建一次。

未達 Gate 時，降低功能範圍或如實標記限制，不為準時展示而關閉保護或偽造數據。
