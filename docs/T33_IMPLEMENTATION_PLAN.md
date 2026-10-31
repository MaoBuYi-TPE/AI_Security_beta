# T33 實作計劃：Guard path 編碼的有條件放寬與 Lab 驗證

修訂日期：2026-11-01（Asia/Taipei）

狀態：實作中；測試、live 證據與合併結果以 TASKS 的交付紀錄為準。

本文件以使用者補充的 T33 計劃書為設計主體，取代本 chat 先前的實作方案。保留已授權的交付目標：完成驗證與審查後，以 PR 和 merge commit 合併回 main。

## 1. 本次修訂與範圍

| 項目 | 修訂後決定 |
|---|---|
| 編碼字元 | 採附件的 E 白名單；可接受參數中的 %27、%3C、%20 等，拒絕 %41、%7E、%2E 等 encoded unreserved。取代先前「只解碼為既有 literal 字元」的方案 |
| 排除規則 | 採整條路由的 exclusion-overlap；不只比對 decoded literal |
| 型別與分層 | GuardPolicyVersion 放 guard；PathEncoding、RequestPath 放 grants。實際請求不得轉成宣告用的 Route |
| domain 參數 | 政策／encoding 參數必填；只有設定入口預設 strict-1 |
| 歷史 run | guard_policy_version 保留 null，不回填；解析時映射 strict-1 |
| 實驗入口 | RunnerSettings 環境設定；正常 compose 寫死 strict-1，僅專用 live override 切換 |
| 結果比對 | canonical_path 只統一 %HH 的 hex 大小寫，不解碼、不改寫請求 |
| parser 版本 | 保留 PARSER_VERSION；用 guard policy version 區分政策，驗證舊 strict 輸入的結果相容 |
| worker | 核對 summary 與 DB 版本，逐行重算 method/path 授權；失敗時明確標為不可信 |
| API | 新增 engines[].guard_policy_version、guard_traffic.policy_version、guard_traffic.forwarded_encoded |
| 真實驗證 | 新增 route echo、Juice Shop path 參數規格、A/B 錄製、證據 contract 與突變檢查 |
| 合併 | 程式與測試、交付文件分開提交；PR merge commit、刪除已合併分支、同步 main |

使用者已確認：**驗收以鎖定 Flask／Werkzeug 與 Express Lab 的實際解析鏈為準；其他解析模型保留反例與限制，不宣稱全部安全。** 不擴充本次排除演算法去處理所有伺服器的別名。

本次包含 T33 全部實作與證據；不包含 T30、正式預設切換、每個 grant／scan 自行選版、HTTPS、query/body 規則、body _method 或 cookie 合併。

本機沿用 feat/t33-guard-encoded-params；已查得基底為 c61a5e8。最近查核時 GitHub 只有 main，T33 尚未推送或開 PR。執行開始須重新確認遠端狀態，不重新建立同名分支，也不覆蓋現有 TASKS 變更。

## 2. 安全設計與明確介面

### 2.1 版本

- GuardPolicyVersion：strict-1、encoded-params-1，定義於 guard/domain/policy.py。
- PathEncoding：REJECT、ROUTE_PARAMETERS，定義於 grants/domain/request_paths.py。grants 不依賴 guard。
- strict-1 凍結 T11–T16 的請求判斷；encoded-params-1 為待驗證的實驗版本。
- 公布後以每個版本的黃金語料固定判斷；改變政策判斷須增加新版本，保留舊實作以解析歷史 run。
- 未知版本拒絕，不偷偷改用 strict。只有歷史 DB null 明確映射 strict-1。

### 2.2 RequestPath 與受控解碼

新增 PathAmbiguity、RequestPath、parse_request_path、canonical_path。RequestPath 及其段落為 frozen 型別，保存原始 path、原始與 decoded 段落、是否含編碼及尾斜線；不使用 Route 的 None 表示編碼段。

1. 既有 request-target 形狀檢查先拒絕不可見 ASCII 與原始 #。在第一個原始 ? 切出 path，query 沿用原規則。
2. path 必須以 / 開頭，原始長度最多 512；先按原始 / 分段。維持根目錄與單一尾斜線語意，拒絕中間空段、原始 . 與 ..。
3. 一般字元沿用 [A-Za-z0-9._~!$&'()+,=:@-]。原始未編碼的大括號仍拒絕。
4. % 只能接兩個十六進位字元，須先嚴格驗證 triplet；不依賴接受正負號的寬鬆數字解析。
5. 每個 triplet 只解碼一次；decoded byte 只能屬於 E：

   空白、!、"、$、&、'、(、)、+、,、:、<、=、>、@、[、]、^、反引號、{、|、}。

6. 拒絕 encoded unreserved、/、反斜線、?、#、;、%、*、控制字元、DEL 與所有非 ASCII byte。
7. encoded-params-1 中，任一段若只由點、空白與 + 組成就拒絕，包括未編碼的一般段。strict-1 對 ..+ 的既有行為保持不變並揭露。
8. decoded {username} 永遠只是參數資料；不可送回 parse_route，也不可變成授權佔位。
9. canonical_path 僅把合法 %hh 轉為 %HH。不得 unquote、trim、替換 +、合併斜線或移除點段；原始資料保留供證據比對。
10. 轉送 request.data.path 與 query 完全不改寫。

拒絕 encoded unreserved 是本專案選擇的保守政策，**不是 RFC 宣告這些 URI 非法**。RFC 3986 §2.3、§2.4、§6.2.2.1 分別說明 unreserved 等價性、先分離元件再解碼，以及 percent hex 大小寫正規化：
[RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html)

### 2.3 ScopeRules.classify_request

維持既有 ScopeRules.classify、parse_route、Route、covers 的宣告語意；新增 covers_request 與 classify_request，接受獨立 RequestPath。

- 允許：段數、一般 literal 的大小寫與尾斜線符合原規則；含編碼的段只可由佔位涵蓋。必須由同一條完整 allowed pattern 授權，不能拼接不同 pattern。
- allow_all_paths 遇到編碼段回 PathAmbiguity 的 no-route-parameter。
- 排除：先比對整條 pattern 是否「可能相符」：段數相同、忽略尾斜線，且每個位置為排除佔位、請求編碼段，或一般 literal 不分大小寫相同。
- 可能相符且任何編碼段對到排除 literal，回 exclusion-overlap；所有編碼段只對到排除佔位則回 PATH_EXCLUDED。
- 不可能相符的排除不阻擋。所有排除檢查完成後才檢查 method 與 allowed route。
- 此規則會使 excluded /users/v1/_debug 阻擋同形 /users/v1/{username} 的全部編碼探測；這是刻意的覆蓋取捨，不改成子序列判斷。

### 2.4 reason、detail 與 log

下列歧義維持對外 PATH_AMBIGUOUS；detail 只進安全 log：

| detail | 條件 |
|---|---|
| syntax | 原始語法、長度、空段、原始未編碼大括號等不符 |
| percent-encoding | strict-1 的 path 含 % |
| invalid-percent | 不完整、非 hex 或帶正負號的 triplet |
| encoded-separator | 解出 /、反斜線、?、#、; |
| double-encoding | %25 |
| encoded-control | 控制字元、DEL、非 ASCII |
| non-canonical | encoded unreserved |
| encoded-wildcard | %2A |
| dot-segment | 段落只由點、空白、+ 組成 |
| no-route-parameter | allow_all_paths 沒有明確路由參數授權 |
| exclusion-overlap | 可能相符的排除 literal 與編碼段重疊 |

安全語法但沒有任何 allowed route 涵蓋時仍回 PATH_NOT_AUTHORIZED；其他現有 reason 保留。先檢查 path 語法，再依排除、method、允許順序判斷；多個語法錯誤按 path 由左至右取第一個，固定於黃金語料。

放行的編碼參數 detail 為 encoded-route-parameter。每筆有可信 policy 的決定記錄 policy_version；尚未驗證 policy 的拒絕填 null。path 上限由 200 改為 PATH_MAX_LENGTH（512）；仍不記 query、header 值與 token。

## 3. 持久化、開關與相容性

### 3.1 DB 與 API

- 新增 v0012_guard_policy_version，不修改已合併的 v0011。
- scanner_runs.guard_policy_version 可為 null；非 null 僅允許兩個明確版本且必須有 plan_hash。
- 不回填舊 run。null 表示未記錄政策版本，不能當成「已執行 strict」的流量證明。
- record_plan 在同一個 fenced update 寫入 plan_hash、profile hash 與版本；第一次寫 plan 必須同時有版本。
- 更新 scanner_runs_plan_once 的函式及 BEFORE UPDATE OF 欄位清單；防止只改版本、清空 plan、使用舊 lease 等繞過。
- downgrade 僅容許沒有實驗版 run 的資料庫，先還原 v0011 的函式與 trigger 再移除新欄位；存在 encoded-params-1 紀錄時拒絕降級，避免刪欄位後被舊程式誤認為 strict。升降級與拒絕行為只在隔離測試 DB 驗證，不能用降級切回嚴格政策。
- engines[].guard_policy_version 原樣揭露，可為 null；guard_traffic.policy_version 保存 Guard 回報值；forwarded_encoded 為精確整數或 null。
- 舊 result_details 缺新欄位時 API 回 null，不補造 0 或 strict-1。維持 4 KiB 上限，補 JSONB 實際位元組大小與序列化測試；不將逐筆 path 或 detail 分布塞進 DB。

### 3.2 Runner 與部署

- RunnerSettings.guard_policy_version 對應 RUNNER_GUARD_POLICY_VERSION，只接受 enum，預設 strict-1。
- cli/services 傳給 ContainerRunner；record_plan 與 RunEgress.open 使用同一值。實驗版啟動時記 warning。
- compose.yaml 的 runner 寫死 RUNNER_GUARD_POLICY_VERSION: strict-1，不使用環境插值。
- 新增 compose.guard-paths.yaml，只覆寫該 runner 的這一個環境變數；只有 make test-live-guard-paths 引用。
- LIVE_ENV、其他 live targets、.env.example 不加入實驗設定；一般 API client 不能選版。
- 明確界線：此方案保證預設 compose 與一般 API 嚴格，**不能保證直接啟動的 runner 不會讀到操作者自行設定的環境變數**。有主機控制權的操作者仍可啟用實驗，正式使用前另行決策。

### 3.3 Guard schema 與 telemetry

- policy schema 3 必填 policy_version；status.policy_schema 同步為 3。舊、新映像不符時 runner 不認領。
- summary schema 2 必填 policy_version；部署採停止認領、排空 run、一起更新 runner／Guard／worker。
- ForwardedRequest 的格式驗證接受 REJECT 與 ROUTE_PARAMETERS 語法的聯集；這只是結構解析，不代表該 run 有授權。
- recorder 對同 run 的記憶體紀錄與重啟續寫檢查版本一致；不能把兩版本混成同一份 summary。
- 舊 schema 1 summary 僅以精確舊欄位格式作 strict 歷史相容讀取；不能為 encoded-params-1 提供已驗證依據。未知 schema／版本拒絕。

## 4. Worker、parser、coverage 與認證計數

### 4.1 統一且明確的信任結果

新增明確的 telemetry 一致性／信任結果，區分可信、缺資料、不一致，不只把 exchanges 設成 None。

Worker 從 run 上下文取得 DB 版本（歷史 null → strict）、凍結 grant、scan/run id，依序：

1. 嚴格讀取 summary 與 JSONL，核對 run、scan、政策版本與既有 boot／計數規則。
2. 使用該 run 的 grant 與 encoding，重新判斷每筆 method/path 都應被放行。
3. 不一致時記安全錯誤代碼，保留可解析的 Guard 回報版本；不記 coverage、traffic_verified=false，不因這項資料錯誤重試。
4. 不一致狀態優先於所有「forwarded=0」捷徑；零流量不得掩蓋版本衝突或越權行。
5. 缺資料維持現有不足證據語意，不冒充成功量測；真正可信的零流量仍按既有規則處理。
6. parser 與 coverage 使用同一檢查入口／結果，不能一方拒絕紀錄、另一方重新讀取後信任。

這能證明**紀錄中的 method/path 與凍結政策一致**；JSONL 沒有完整 query、origin、header、DNS/IP，不能稱為完整「沒有越權流量」證明，也不能發現共用 classifier 的共同錯誤。仍須獨立靶機證據。

### 4.2 各消費端

- scope_reason 增加必填 encoding；由 run policy version 映射，不使用隱含預設。
- observed_operations 增加必填 encoding，使用 RequestPath。編碼段只對應 operation 佔位；不會因 decoded {x} 生成佔位。
- 防禦性解析失敗跳過該筆，不丟例外；若來源是該 run 的 telemetry，前述整體一致性檢查仍須判為不可信，不能靠跳過壞資料獲得 coverage。
- parser 的 not_answered、traffic 的認證健康度 key 使用 method 加 canonical_path；只統一 percent hex 大小寫。
- 原始 URI/path 不被替換；不合併不同 request 的資料，保留原有 method/path 粒度限制。
- PARSER_VERSION 維持；以舊 strict fixtures 與輸出快照證明相容。新增的信任檢查與結果欄位另記為 T33 行為，不宣稱所有不可信舊輸入也完全相同。
- forwarded_encoded 只有逐筆紀錄可信且 request 行數精確等於 summary.forwarded 才計算；缺一行也回 null。不能直接沿用允許少最後一行的 telemetry_complete 當作精確計數條件。strict 保留既有少最後一行的相容規則並揭露限制；實驗版缺一行就不宣稱完整流量已驗證，也不記 coverage。

## 5. 測試設計與驗證界線

### 5.1 Unit 與 integration

- strict-1 使用凍結的舊函式 oracle，保留所有現有 percent 拒絕、安全與故障案例。
- encoded-params-1 測 E 的每個字元、hex 大小寫、無效 triplet、所有 detail、一般點／+ 段、單一與多段 exclusion-overlap、literal 不涵蓋編碼段、allow_all_paths、同一路由完整授權。
- 變形測試：編碼段替換成新的普通 literal 後，strict 仍接受；hex 大小寫不影響判斷。
- 測 scope_reason、完整 Guard、parser 的同政策一致性，並驗證拒絕發生於 DNS／上游連線前。
- migration 測帶 queued、running、terminal 歷史資料的升降級與重升級，CHECK、trigger、lease，以及 DB／policy／API 版本一致。
- Worker 測 summary 不符、逐行越權、舊 run null、零流量但不一致、殘缺 telemetry、coverage 與 parser 共用信任結果。
- 新 API 欄位、舊結果 null、精確 forwarded_encoded、認證 hex 大小寫 key、4 KiB 上限皆有測試。
- 部署測試確認正常 compose 寫死 strict、override 只設一個變數且只被專用 target 引用、.env.example 無開關、Guard COPY 閉包含新模組。

### 5.2 Contract、解析模型與反例

新增 tests/url_models.py、test_guard_paths.py、test_guard_path_evidence.py；每個政策有固定 reason/detail 的 Python 黃金語料。

解析轉換包含：單次／兩次解碼、嚴格 UTF-8／latin-1、+ 轉空白、trim 空白／尾點、去副檔名、去 ; 參數、反斜線、大小寫折疊、合併斜線、remove_dot_segments，以及 Express 先路由後解碼參數。各模型以純函式固定語意，明定作用對象、順序、次數、空段與失敗結果，附最小範例；Hypothesis 測有順序的組合與 grant 邊界。

測試分為兩類，不能混為「所有模型安全」：

- **驗收性質**：政策自身不變式，以及與鎖定 Flask／Express route echo 實測相符的解析鏈。任何違反均阻擋實驗交付與合併，修復不得削弱既有安全案例。
- **對抗式探索**：其他伺服器／proxy 轉換及任意串接。保留重現案例與預期差異，報告其不受支持的條件；不能刪反例、把意外失敗改成無條件通過，或以轉換 grant literal 擴大實際授權。

必須保留的已知反例：

~~~text
allowed:  /a/{x}/{y}
excluded: /a/admin/{id}
request:  /a/admin.json/%27
探索模型：去除一般段落的副檔名
結果：/a/admin/' 可能落入 excluded
~~~

此反例說明附件演算法不涵蓋會做此別名轉換的解析鏈；本次不宣稱修復該類伺服器。如果鎖定 Lab 也重現這種越權，它就不是可接受的範圍外限制，必須阻擋驗收。

### 5.3 Live 與 route echo

- 不修改 tests/live/receiver.py。沿用原始 HTTP probe、receiver/canary、mitmproxy 映像內真實 flow contract。
- 在鎖定 VAmPI 映像的 Flask／Werkzeug、Juice Shop 映像的 Express 啟動只回報 route／參數的測試程式，僅使用隔離 Lab 網路。
- 先以不經 Guard 的固定探針記錄解析差異，再經兩種政策驗證。這是 Lab 的解析探針，不向 Lab 之外送流量。
- 如原映像無法執行，選擇相同 framework/router 版本、固定 digest 的替代映像；記錄差異。無法驗證版本等價時標為證據缺口，不以最新映像代替。
- 放行探針的 route 與參數須符合預期；拒絕探針在 receiver、canary、route echo 均不得出現。
- 固定語料逐字比較原始 path、hex 大小寫、+、%20、順序與重複次數。明確區分原始 request-target 證據與框架解碼後的參數。

## 6. A/B 實驗、來源證據與隱私

唯一新入口為 ENABLE_LIVE_LAB_TESTS=1 make test-live-guard-paths。

1. 啟動原有 secscan-live stack，使用 strict-1，執行兩版本固定 path／route echo 探針。
2. A 組：VAmPI 弱點版；Juice Shop path 參數規格。
3. 確認 A 組所有 run 結束、無 lease／掃描容器殘留後，以 compose.guard-paths.yaml 僅重建同一個 runner；確認 schema、心跳及實際政策版本。
4. B 組：VAmPI 弱點版、安全版；相同 Juice Shop 規格。
5. A、B 使用相同映像、grant、規格及預算，重新建立靶機與相同種子／認證資料，避免 A 改變的狀態影響 B。
6. 比較結果並完整清理；一次只啟動一個 ZAP／靶機。live 前停止可停止的測試 DB，避免同時占用記憶體；不移除既有開發資料。

VAmPI 完全沿用 T16 grant 與規格。Juice Shop 先確認鎖定映像實際存在的 GET path 參數端點，再以附件候選路由建立最小規格；加入佔位位置的 literal 排除，驗證 exclusion-overlap 與 %2500 拒絕。不存在的端點不得冒充可掃描案例。

A 組：轉送 path 不含 %、SQLi 編碼探針仍被拒。B 組：已轉送的編碼段均有明確路由授權、可信資料的 forwarded_encoded 正確、coverage 正確、負控制不得出現 40018。VAmPI 弱點版是否命中 40018 如實量測，不把「必須命中」當作放寬規則的理由；未命中須釐清 Guard、parser、ZAP 或目標行為。

「B 比 A 多出的只有編碼請求」改為對**同一份固定請求語料**作政策分類比較，另列 ..+ 收緊差異。完整 ZAP 掃描具有適應性，放行新請求可能改變後續爬取及探針，不能對兩次掃描的流量差集強加此斷言。

每個 run 在 recordings/guard-paths/<版本>/<情境>/ 保存：

- scan.json、guard-decisions.jsonl、telemetry.jsonl、summary.json、report.json、zap.log。
- target-requests.log、environment.json、analysis.json；記錄 run_id、來源 commit、app／Guard image ID、工具及靶機 digest、framework/router 版本、時間、hash、預算與統計。
- Guard allow log 是判定，不等於已轉送；轉送多重集合以已 commit 的 telemetry 為準，另查 server error／無上游回應。
- 靶機端先驗證既有 log 是否完整保留原始 request-target、來源 IP、編碼及重複請求；只核對 Guard lab IP，分開準備、preflight 與掃描的 run／時間窗。
- log 若解碼、截斷或無法可靠歸屬，使用固定 digest 的 live-only 被動封包擷取與重組；能力／掛載僅限擷取 helper，不提升 scanner 或產品 Guard 權限。無法取得原始證據時不得宣稱逐字相同。
- 成功對照的轉送與接收 method/path 多重集合及數量必須相等；失敗／連線中斷的未送達另列，不刪除樣本。固定探針另驗順序。
- 觀察與轉送證據只容許 hex 大小寫的 canonical 等價；原始位元組比對另保留，不以 canonical 等價冒充逐字相同。

完整原始證據只留受限、加密的本機儲存，不進 Git。衍生的 fixtures/guard 逐筆表僅含 method、不含 query 的 path、decision、reason、detail、policy_version、轉送／接收與 status；逐項審查 path 也可能包含 secret，列入 manifest、hash 與防洩漏檢查。

不預設「ZAP 不會把 secret 放進 path」；無法安全去識別且維持重播語意的項目不提交原文，改以合成等價案例並說明證據界線。detail 分布保存在安全 analysis／文件，不塞入 result_details。

## 7. 實作順序、TDD 與提交

0. 重查本機／遠端、保留現有 TASKS 變更；先將本設計寫入 DECISIONS §21，查核來源、框架版本、log、路由與 route echo 可行性。沿用現有 helper 時以原始碼為準：附件提到的 Measured、_vampi_lab、_record、_assert_invariants 目前位於 tests/live/test_lab_zap_live.py，必要時抽到共用測試模組，不直接假設存在於 zap_support.py。
1. grants：RequestPath、PathEncoding、PathAmbiguity、canonical_path、獨立 request matching；先寫 strict oracle、黃金與變形測試。
2. Guard：policy schema 3、status、reason/detail、summary schema 2、格式聯集、log、COPY 閉包與測試。
3. Contract：URL 模型、兩類安全／探索測試、已知反例與語料。
4. DB／runner／API：v0012、record_plan、版本一致、設定傳遞、compose override、部署與 integration 測試。
5. Worker／parser／coverage／traffic：必填版本與共用信任檢查、hex canonical、精確計數、零流量與歷史資料案例。
6. Live：固定探針、route echo、A/B harness、證據來源與錄製。首輪量測後形成有根據的觀察斷言；安全不變式預先固定，不依量測放鬆。
7. 在獨立 worktree 做突變檢查：分隔符、%、*、unreserved、點／+、literal 位置、多段排除、allow_all_paths、hex、預設、跨元件版本、worker 信任與 DB trigger；區分被測試捕獲、等價及無效突變。
8. 獨立 code-reviewer／security-reviewer 審查與修正；有執行行為變更時重建映像並重跑受影響 live。
9. 完成文件與證據 contract，執行最終檢查，再建立／更新 PR 與合併。

程式與測試、交付文件分開 commit。正式量測須對應可追溯的程式 commit；後續安全修正使用額外 fix commit 並重錄，不能以兩個 commit 的形式要求犧牲證據正確性。

已確認 Git 使用者為 MaoBuYi-TPE、11346013@ntub.edu.tw，提交前再核對。提交／PR 的工具歸屬據實記載；本次 Codex 實作不標成由 Claude Code 產生。附件若需保留 Claude 的設計來源，與實際程式作者歸屬分開說明。

## 8. 驗證與合併門檻

~~~sh
make test
make lint
make typecheck
make test-contract
uv run --locked pre-commit run --all-files
ENABLE_LIVE_LAB_TESTS=1 make test-live-guard-paths
ENABLE_LIVE_LAB_TESTS=1 make test-live-runner
ENABLE_LIVE_LAB_TESTS=1 make test-live-zap
ENABLE_LIVE_LAB_TESTS=1 make test-live-lab
~~~

採用補充計劃指定的完整回歸：test-live-zap 只掃既有隔離小型測試網站，其他真實 A/B 僅掃 Juice Shop／VAmPI。不得將 localhost:8000 的其他專案或任何 Lab 外目標納入。先確認 OrbStack 可用，需要時啟動；不人工讀取、輸出或編輯 .env 的秘密內容。

整體 coverage ≥80%，新安全模組及 Guard 核心 branch ≥90%。退出碼直接核對，不接 pipe 掩蓋錯誤；pre-commit 修改後重新檢查受影響內容。既有 golden fixtures 不擅自改寫，receiver.py 不修改。

目前已有的 1163 passed／7.67 秒只是舊程式相關測試基線，不是 T33 完成證據。

CRITICAL／HIGH 必修；任何等級只要涉及授權繞過、fail-open、版本錯配或必要證據失真也阻擋合併。已知範圍外模型以限制揭露，不冒充已修復；鎖定 Lab 的安全反例不可降格為限制。

## 9. 文件同步與剩餘風險

同步 DECISIONS §21 與 §15.10／§19.4／§20.7／§20.8 的交叉參照；SECURITY_AND_TESTING 的 SEC-08、案例表與 T33-VA-01；API_CONTRACT、ARCHITECTURE、TOOLS §7.8、SOURCES S105 起；TASKS、README、START_HERE、CLAUDE 的進度與指令。

來源須查核 RFC、鎖定框架實作及相關 proxy／路由差異的官方資料；其他伺服器與公開研究只作對抗模型及限制依據，不能替代 Lab 實證。

明列：

- 已驗證的 framework／版本／解析鏈；未驗證的 proxy 先解碼後重組請求、別名與 trim 行為。
- Windows／IIS、8.3 短檔名、::$DATA、尾點等不在驗收範圍，不能預先宣稱風險未擴大。
- strict-1 的 ..+ 行為、既有 keep-alive／pipelining 與 body _method 證據缺口。
- encoded path 的秘密遮罩限制、原始證據的存取與加密安排。
- runner 開關會影響其後認領的所有含佔位 grant；本次只在隔離實驗切換，不等於正式授權語意已決定。
- T33 完成不表示在所有伺服器上安全；T30 使用的政策、全域或 per-grant 正式啟用留待使用者看過證據後決定。

## 10. PR、合併與完成定義

1. 更新遠端狀態；main 若有變更，保留使用者修改並整合，重跑受影響檢查，不 force-push 主分支。
2. 推送 feat/t33-guard-encoded-params 並設定 upstream；既有同分支 PR 則更新，否則建立以 main 為 base 的 PR。
3. PR 標題為「T33：Guard 受控編碼路徑與雙政策 Lab 驗證」，建立後附加到本 chat。
4. 描述問題、實際政策、nullable 歷史版本、升降級／部署順序、測試與 A/B 結果、突變與審查、未證明事項；不聲稱不存在的 GitHub CI 已通過。
5. 核對最新 base、實際 head、可合併狀態與可用 checks；合併內容須與已驗證程式一致。
6. 必要門檻通過後依既有授權執行 gh pr merge --merge --delete-branch；不再停在只建立 PR。
7. 核對遠端 merged 與 main 的 merge SHA；乾淨工作區切回 main 並 fast-forward 同步。確認內容一致、工作區與資源清理，再重跑一般檢查；若合併引入程式差異，補受影響 live。
8. 最終交付 PR、merge SHA、差異、實際命令及退出碼、A/B 統計、剩餘風險與下一步。必要環境／證據缺失則如實列阻擋項並保留 PR 未合併。

預設始終 strict-1；合併程式不代表正式啟用 encoded-params-1。只有實作、測試、證據與審查符合本文件範圍後，才將 T33 標為 done。
