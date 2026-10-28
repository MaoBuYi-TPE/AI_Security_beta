# 安全需求、測試計畫與實驗方法

狀態：待實作與待測試。只有達到以下測試要求後，才能在文件中標註對應能力完成。

## 1. 測試前提

本平台是會主動對外發送測試請求的系統。所有 live 測試僅限自有或權利人明確授權的隔離靶場，使用測試身分與可重建資料，不對公開 demo、學校正式系統、同學未授權專案或外部網站執行。

預設 LAB_ONLY；unit/contract 不可出網。live 測試需 `ENABLE_LIVE_LAB_TESTS=1`、有效 grant、已驗證隔離網路及明確的 pytest 標籤。測試 code 本身不應含任意 Internet URL 掃描流程。

T10 起的測試隔離（`tests/isolation.py`，`DECISIONS.md` §14.9）：測試程序只能 connect 到 pytest 暫存目錄底下的 Unix socket，`DOCKER_HOST` 指向不存在的 socket（子程序的 `docker` CLI 也連不到 daemon）；沒有標記 `live` 卻用 `enable_socket` 的測試讓整個 session 失敗；沒有開關時 live 測試在收集階段就 skip。`make test` 不跑 live。

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

T06 已涵蓋：

- **target canonicalization**：
  - 接受與拒絕的對照表，每一類模糊寫法至少一例，並檢查錯誤訊息指出原因、不回顯輸入。
  - Hypothesis property test：結果 idempotent、輸出符合嚴格文法，而且標準函式庫 `urlsplit` 解出相同的 host 與 port。profile 以 derandomize 固定輸入，失敗可以重現。
  - 不解析 DNS。
- **grant 的範圍、預算、期限**：每個欄位的語法與邊界，以及狀態轉換表（所有狀態與動作的組合都明確決定）與掃描 gate。

T07 已涵蓋：

- **scope matching（route 層級）**：`covers()` 的對照表（佔位、大小寫、結尾的斜線、段數、根目錄），以及 Hypothesis 的性質：自反、排除至少和允許一樣寬、把 literal 換成佔位不會縮小涵蓋範圍、排除不分大小寫；`find()` 證明涵蓋與不涵蓋兩種結果都會出現。判斷的原因與先後（`PATH_EXCLUDED` → `METHOD_NOT_AUTHORIZED` → `PATH_NOT_AUTHORIZED`）。
- **規格的解析（SEC-11、SEC-17 的應用層）**：
  - JSON 與 YAML 的接受、拒絕對照表：billion laughs、`!!python/object/apply`、多份文件、directive、tab、重複的 key、`<<`、複合 key、`.inf`、`1e400`、NaN、超長整數、NUL、孤立的 surrogate、BOM、非法的 UTF-8、U+2028、超過深度與節點上限。錯誤訊息只有原因與位置，不含輸入的值。
  - 性質：BMP 內的任何 JSON 值，以 `json.dumps` 輸出後，JSON 與 YAML 兩個 parser 解回相同的值。
  - 很深或很多節點的 YAML 在超過上限時就停下（計算 parser 實際產生的事件數），不依賴 RecursionError。
  - 不做 I/O：把 socket、`urlopen`、`open` 換成會失敗的版本，處理含外部參照與外部 servers 的規格仍只得到檢查結果。
- **參照與 servers（SEC-02 的規格部分）**：外部參照（http、https、file、相對檔案、network-path、urn）、`#foo`、`%`、懸空、循環、參照鏈的長度、`operationRef`、discriminator、`externalValue`、`$id` 等；servers 的改綁、base path 的各種寫法與拒絕的情形，確認原本的 host 與帳密不出現在文件與訊息中。
- **審查後補上的測試**（code-reviewer 與 security-reviewer 的發現）：
  - 透過 `$ref` 轉一手繞過 Link 的 `server`、oauth2／OIDC 的拒絕（指向 `x-` 擴充、example 或區段底下），六種寫法都回 `UNSUPPORTED_SCHEMA`；components 的名稱不可以是 URL 或路徑；discriminator 的 mapping 只寫名稱也拒絕。
  - 成本有上限：合法的文件不組位置字串（把 `pointer_text` 換成會失敗的版本）、共用的參照鏈只走一次、還沒確認的長鏈走到上限就停（計算 `_resolve` 的呼叫次數）、JSON 在解析之前就以預估的節點數拒絕。
  - 不會變成 500：Hypothesis 在合法的文件中放入變化的 server URL、陣列索引與 YAML 的 `\U` 跳脫，只能被接受或拋出 InvalidSpecError；另有不合法的 IPv6 括號、超長的陣列索引與版本號、超出範圍的 `\U`、`%FOO` directive 的對照表。
  - 上傳讀取 body 超過時間上限回 408、途中斷線回 400；key 格式的 middleware 以 `root_path` 部署時仍涵蓋 `/api/v1`（與 Starlette 的 `get_route_path` 以性質測試比對）。

T08 已涵蓋：
- **secret 的加密（`SecretCipher`）**：`seal` 與 `reveal` 來回；context 不符、用錯金鑰、改動 token 解碼後的任何一個 byte（Hypothesis），都解不開；token 不含明文；以正確的金鑰加密、但內容不是預期格式的 token 也拒絕。換版（`rotate`）改用第一個金鑰、保留時間戳記、確認 context。金鑰設定的每一種錯誤寫法都拒絕，訊息不含金鑰；token 長度的公式以實際加密的結果核對。
- **secret 的格式**：bearer、header 的值、cookie-string 的接受與拒絕對照表（CR、LF、NUL、tab、非 ASCII、引號、分號、重複的 cookie 名稱…），以及 Hypothesis 的性質：依文法產生的一定接受，插入任何一個禁止的字元一定拒絕。header 名稱的拒絕清單以 Hypothesis 檢查任何大小寫的組合。secret 含平台 API key 的樣式就拒絕。錯誤訊息不含輸入。
- **preflight 的定義**：method、path（含佔位）、status 的邊界；expected_json 的 pointer（RFC 6901，編碼後再解析得到相同的 token）與值（布林不等於整數、浮點數、超過 ±(2^53 − 1) 的整數）；只看狀態碼、沒有內容比對的定義被拒絕。
- **PATCH 的規則**：每種組合都明確決定（沿用 secret、換類型必須附上新的 secret、沒有變更…）。
- **只寫不讀**：以 AST 確認 src 中沒有任何模組呼叫 `reveal`，`reencrypt_secrets` 只有本機 CLI 呼叫。API 文件中的 secret 是 writeOnly，任何回應的 schema 都沒有 secret。

T09 已涵蓋：
- **request hash 與 Idempotency-Key**：key 的格式（每個字元類別、長度的邊界、雙引號的寫法、CR、LF 與非 ASCII 被拒絕，訊息不回顯）；fingerprint 對每一個欄位與預算的每一項都敏感、和 engines 的順序無關（Hypothesis 對所有排列）、省略 budget 與每一項都是 null 相同；預算的界線（不超過 grant、正整數、布林不是整數）。
- **狀態轉移**：run 的 12 × 12 轉換全部明確決定；failed、timed_out、interrupted 必須有錯誤碼。scan 狀態的彙總：對照表，以及 Hypothesis 的性質（和 run 的順序無關、全部終止時一定是終止狀態、要求過取消而且還有沒終止的 run 時一定是 cancelling）。
- **引擎與 profile**：只開放 fake、執行順序固定、fake 必須單獨使用、profile 與 target 種類、規格的相容性。
- **事件的 payload**：只有白名單中的欄位，最大的 payload 也在 1 KiB 以內。

T10 已涵蓋：
- **ExecutionPlan 的驗證（SEC-12 的應用層）**：拒絕對照表，每一類至少一例：沒有政策的引擎、未核准的映像（tag 或 digest 不同、只差 repository）、shell 當 entrypoint、多或少一個 arg、arg 不符樣板（`5;id`、`1000`、前後空白、換行）、不在白名單的環境變數或值、輸入檔的名稱、數量與大小、不接受認證的引擎卻掛 secret、超過上限。Hypothesis：fake 建出的每個 plan 都通過驗證，組出的 body 都通過不變式。被拒絕的訊息不含值。
- **create body 的不變式（SEC-21 的應用層）**：逐一竄改 59 種危險的欄位（privileged、Binds、CapAdd、seccomp、可寫的 rootfs、host／其他網路、PID／IPC／userns 的 host 模式、device、sysctl、extra hosts、port、VolumesFrom、Tmpfs、Runtime、root 或其他 user、沒有記憶體或 pids 上限、swap、bind 的 mount、其他 volume、其他 run 的 subpath、路徑穿越、可寫的輸入、多出或少掉的 mount…）都被擋下；政策的 user 被改成 root 時也被擋下；IPC 或 cgroup namespace 不是 private、mount 被改成 bind 也擋下。審查後補上：組 body 的常數或掛載函式被改錯時，送出前的檢查（自己的一份字面值）仍然擋下；保留的網路名稱（host、bridge、none、default）與含 `.` 的名稱被拒絕。
- **Docker runtime**：以假的 HTTP adapter 確認每個請求的 method、path、query 與 body；create 遇到缺少的映像不 pull；409 是同名容器；403、500、連線錯誤與格式不符的回應都轉成不含回應內容的錯誤；刪除容器一併刪除匿名 volume；不讀環境變數的 proxy；只接受 `tcp://` 與 `unix:///`。
- **工作目錄與收集（SEC-18 的 runner 這一側）**：目錄 0700、輸入與 secret 0400、`O_EXCL`；收集拒絕指向其他 run 的 secret 的 symlink、symlink 的目錄、被換成 symlink 的 out/、hardlink、FIFO、讀不到的檔案、含控制字元或非 UTF-8 的檔名、超過深度、數量與大小的上限，開檔之後被換掉也會發現；拒絕的訊息不含檔名；不覆寫既有的 manifest。審查後補上：r-- 的目錄與 I/O 錯誤都是 UNREADABLE；目錄也計入條目數，超過上限就停（以無窮的目錄確認不會先讀完整個目錄；原本的程式 300 秒內沒有結束）；Unicode 的格式字元（bidi 覆寫、零寬字元）被拒絕；權限錯誤與磁碟滿轉成不含路徑的 WorkspaceError，寫 secret 失敗時不留下檔案；短寫會寫完；執行中的用量檢查（只 lstat、不跟隨 symlink）。
- **capability probe**：Docker 不可用、API 版本不含 1.45、scan_net 不是 internal 或沒有 isolated、少一個 volume、volume 不可寫、映像不在或架構不符，各自回報原因。
- **部署設定的靜態檢查**：只有 socket-proxy 掛 docker.sock（唯讀）；沒有服務是 privileged、有 host 模式或 device；app 服務都非 root、唯讀、`cap_drop: ALL`、`no-new-privileges`；映像以 digest 鎖定或本機建立（不 pull）；網路與 port；socket-proxy 的放行清單以相同的語意（自動加 `^$`、只比對 path）核對 10 個該放行與 33 個該拒絕的端點（含路徑穿越與未核准的映像），映像的規則是核准清單的逐字比對；內插到 regex 的名稱沒有特殊字元；secrets volume 是 tmpfs。

T11 已涵蓋（`tests/unit/guard/`，guard 的程式 branch coverage 100%）：
- **逐請求的判斷（SEC-02、SEC-05、SEC-08、SEC-09 的應用層）**：authority 的對照表（大寫、結尾的點、底線、別的 port、IP 的十六進位與 `[::ffff:…]` 寫法、Host 與 request target 不同、兩個 Host、HTTP/1.0 沒有 Host、`0080`），path 的歧義（`%`、`;`、`//`、`.`、`..`、反斜線、字面的 `{x}`、超過 512 字元），method 的大小寫與 TRACE、CONNECT，改寫目的地的 header（名稱中的 `_` 視同 `-`）與 query 的 `_method`（含多重編碼），header 的值含 CR、LF、NUL 或其他控制字元、名稱不是 token（`HEADER_INVALID`），Upgrade、scheme、`#`、`OPTIONS *`；檢查的順序；Hypothesis 的性質：只要放行，host、port 必然等於 origin、path 合語法、`ScopeRules` 判定在範圍內。
- **policy 與帳密**：schema 1 的嚴格解析（多或少的 key、重複的 key、布林當整數、浮點數、NaN、非 canonical 的 UUID／IP／origin、檔名與 run_id 不符、範圍規則）、Hypothesis 的來回、最大的 grant 在 512 KiB 以內；Basic 的嚴格解析（base64 的 canonical 寫法、大寫或沒有連字號的 UUID、token 的格式）、hash 比對。
- **位址（SEC-04、SEC-06 的應用層）**：每一個 DNS 答案都要合格（混合的答案、guard 自己、保留的位址、網段與廣播位址、目前 LAB_CIDR 以外、答案太多）。
- **addon**：放行時刪除 `Proxy-*`（含 `Proxy_` 的寫法）、綁定 IP、Host 寫回 canonical；靶機回應中的 `X-Secscan-Guard` 被刪除、guard 自己的拒絕保留；拒絕的旗標存在卻沒有回應時中止；407 與 403 的每個原因；不在範圍內就不解析 DNS；任何例外都拒絕、回應建立不了就中止；`request`、`server_connect`、`client_connected` 的第二道防線；log 中沒有 token、query 與 header 的值。
- **store、status、路由與啟動**：symlink、FIFO、目錄、超過大小、讀不到；只在檔案改變時重讀、損毀也快取、快取有上限；status 的新鮮度、版本、listen 與 enforcing；`/proc/net/route` 的預設路由、多一個網路、經 gateway；options 逐一核對（eager、upstream_cert、rawtcp、非空的 ignore_hosts、聽 0.0.0.0、streaming…）；路由或 options 不安全時不加入 addon、以非 0 結束；guard 載入的模組正好等於映像 COPY 的清單（`python -I -W error`）。
- **runner 的 guard 通道**：policy 以 0400 原子寫入、寫不出去就是 guard 不可用；封鎖與續約可以重複、封鎖之後不再續約、還沒寫入就封鎖不產生檔案；`not_after` 受 grant 的期限限制；proxy-url 帶著新的 token；sweep 只刪 policy 與暫存檔。

policy budget 留給 T12。

### 4.2 Contract / Parser

每個鎖定版本保存遮罩後真實輸出 fixture：正常無告警、存在告警、非零退出但有有效 findings、格式截斷、未知欄位、缺必要欄位、空檔、重複事件、Unicode、超大單行/總量、timeout 後部分 artifact。版本不支援時明確 error，不默默漏掉資料。

T07 加入上傳用的規格 fixture `tests/fixtures/openapi/vampi-openapi3.yml`：T03 輸入的 VAmPI 規格，只把登入回應 example 中的範例 JWT 遮罩成 `REDACTED_JWT`。manifest 的 `openapi_fixtures` 記下遮罩前後的 sha256，contract 測試檢查兩者與防洩密規則。

### 4.3 Integration

以 PostgreSQL（compose 的 `db-test`，見 `DECISIONS.md` §7）+ FakeRunner 驗證。每個測試 session 以專屬的非 superuser 角色與全新資料庫執行，伺服器必須是 `cluster_name=secscan-test`；測試程序本身不碰 Docker daemon。驗證項目：

- 交易一致性
- SKIP LOCKED 認領、重複認領、lease 過期
- target 互斥
- 權限
- migration
- 報告與比較

普通 CI 不啟動真實掃描器，也不出網。

API 與 CLI 的整合測試走正式的 request transaction，資料會真正 commit，所以另用一個全新的資料庫，不和 repository 測試共用（T05）。

T05 已涵蓋 project 層的權限：
- A 專案的 viewer、operator 讀不到 B 專案，回應與不存在的 project、不存在的路徑完全相同。
- viewer 不能寫入；非 admin 不能使用管理端點。
- key 不存在、secret 錯誤、已撤銷，以及已過期但 secret 錯誤的回應都相同；DB 只存 hash，回應、audit 與 log 都找不到完整的 key。
- 兩個連線同時撤銷同一把 key 時只算一次（以 `pg_stat_activity` 確認第二個請求在等列鎖，不靠固定時間的 sleep）。
- 遮罩以固定 seed 的隨機輸入檢查 idempotent，並檢查惡意輸入下仍是線性時間。
- 以突變檢查確認上述測試有鑑別力（`TASKS.md` T05）。

SEC-16 要求的 finding、artifact 跨專案測試，隨這些資源在 M3–M5 加入，尚未完成；scan 已在 T09 涵蓋（見下）。T07 的規格與 inventory 已涵蓋：A 專案讀寫 B 專案的 target、規格與 grant 預覽，回應與不存在的 id、不存在的路徑完全相同。T08 的認證設定同樣涵蓋：建立、查詢、版本歷史與 PATCH，回應與不存在的 id、不存在的路徑完全相同。

T08 已涵蓋認證設定：
- **secret 不外流（SEC-14 的平台這一側）**：以 canary 確認 secret 不出現在任何回應（含 4xx）與 header、DEBUG 等級的所有日誌、audit、DB 的明文；422 只說明欄位與原因，expected_json 的 key 也不回顯。FastAPI 內建的 telemetry 已關閉；查詢的路由拿不到加密元件。
- **context 的綁定**：密文搬到其他 profile，或同一個 profile 中另一種 type、另一個 header 名稱的版本，金鑰換版時都會發現。
- **DB 的最後一道防線**：每個 CHECK、FK、unique 與部分唯一索引都有違反測試；trigger 只允許清除密文與重新加密，其他修改、恢復已清除的密文、DELETE、TRUNCATE、INSERT 不帶密文都被擋下。
- **版本**：建立新版本時上一版的密文被清除，沿用時密文逐 byte 相同；每個 target 10 個、每個 profile 100 個的上限。
- **併發**：同時 PATCH 時版本連號、只留一份密文；沿用 secret 的 PATCH 會等金鑰換版 commit，複製到的是換版後的密文；反過來，金鑰換版也會等還沒 commit 的 PATCH，不會漏掉它新增的密文（審查時發現，修正前測試失敗）；先開始、後拿到鎖的 PATCH，清除時間不早於被清除版本的建立時間；同時建立時上限精確、相同的 role_label 回 409（都以 `pg_stat_activity` 確認後到的在等列鎖）。
- **金鑰換版的 CLI**：每個測試用全新的資料庫；新舊金鑰換版、移除舊金鑰後再確認、少了舊金鑰或 commit 失敗時什麼都不改。

T09 已涵蓋 scan 與工作佇列（佇列、FakeRunner 與需要 runner 的 API 測試，每個測試從 migrated template 複製自己的資料庫）：
- **交易一致性**：scan、run、凍結的 operation、事件與 audit 一起寫入；在寫入之後失敗時什麼都不留下；commit 之前其他連線認領不到它的 run。
- **SKIP LOCKED 與 lease**：兩個 consumer 同時認領時各拿一個 scan、不等待；別人鎖著的 scan（取消中、worker 解析前一個引擎）直接跳過（突變檢查找到後補上）；候選過時時鎖到之後再確認；前面的引擎還在送流量、要求過取消、其他引擎的 run 都不認領。心跳延長 lease、回報取消；過期或別人的 lease 不能延長、不能轉換，也不會被別人接手；對帳只處理過期的 fake run（runner 階段 → interrupted，解析中 → collected 之後再解析）。
- **target 互斥**：同時以不同的 key 為同一個 target 建立，一個成功、一個 409 `TARGET_BUSY`；同一個 key 回同一個 scan，不同內容回 409。
- **runner 啟動前的檢查**：撤銷 grant、停用 target、PATCH profile、grant 過期、`LAB_CIDR` 改了、origin 被改，排隊中的 scan 在 prepare 時 failed，不送出流量。
- **建立與撤銷、停用、PATCH profile 的先後**：兩個方向都以 `pg_stat_activity` 確認後到的在等列鎖；PATCH 等建立 scan 的 transaction，scan 綁定版本 1；PATCH 先拿到鎖時，scan 綁定版本 2。
- **取消與認領**：取消持有鎖時認領跳過它；認領持有鎖時取消等它，之後是 cancelling；事件的 sequence 連號。
- **權限（SEC-16 的 scan 部分）**：A 專案的 key 讀取、看事件、取消 B 專案的 scan，回應與不存在的 id、不存在的路徑完全相同；以 B 的 target、grant、規格、profile 建立回 404；viewer 不能建立與取消；清單只列自己 project 的 scan。
- **不洩漏**：canary 的 target secret、平台 key 與 Idempotency-Key 不出現在 scan 的回應、清單、事件與 audit。
- **DB 的最後一道防線**：四張表的每個 CHECK、複合 FK（引用其他 target、其他 project、不符的 role_label 與版本）、unique 與部分唯一索引都有違反測試；trigger 只允許改 scan 的狀態、取消與結束的時間，終止之後不可再改，run 的身分不可改，事件與凍結的 operation 不可修改。
- **DB 逾時**：每個連線的設定值；另一個 transaction 持有鎖時，API 等 1 秒後回 503 加 `Retry-After`，不是 500。
- **M1 審查後補上的測試**（code-reviewer 與 security-reviewer 的發現，修正前都先失敗）：
  - 撤銷不被持續的建立請求餓死：同一個 target 的第二個建立停在 target 的鎖上、還沒走到 gate；target 忙碌時，建立請求不取任何鎖就回 409。改成排隊之後，同一個 key 同時送出仍回同一個 scan、內容不同仍回 409 `IDEMPOTENCY_CONFLICT`（取得鎖之後先重查 key）。
  - 已要求取消、但 runner 遺失的 scan 是 interrupted；沒有要求取消就不能轉到 cancelling；只有 prepare 能讓 run 開始（`advance` 不能跳過 gate）。
  - 建立 scan 的 key 被撤銷之後，它排隊中的 scan 在 prepare 時 failed（`CREATOR_KEY_REVOKED`）。
  - run 與凍結的 operation 不能在其他 transaction 事後加入；已終止的 scan 的 run 不會被認領。
  - 清單的時間篩選換算成 UTC 會超出範圍時回 422（原本 500）；API 文件中 Idempotency-Key 的 pattern 要求引號成對。
- 以突變檢查確認上述測試有鑑別力（`TASKS.md` T09）。

T10 已涵蓋 runner 與 worker（真的 DB 佇列加上記憶體中的容器 runtime；每個測試用自己的資料庫）：
- **容器版的 prepare**：記下容器名稱與映像、以 FOR SHARE 讀出密文（PATCH 的清除等它 commit，以 `pg_stat_activity` 確認）；取消、gate 不通過、版本被取代時都沒有容器也沒有密文；in-process 的 prepare 不記容器。
- **分階段的對帳**：有容器的 run，lease 過期也不被標成 interrupted（容器可能還在執行）；worker 只把過期的解析退回 collected，不碰 runner 階段。
- **ContainerRunner**：成功（collected → worker → completed，事件依序）、失敗、OOM、超過時間上限、取消（在心跳時看到，先轉 cancelling 再停止容器）、prepare 時看到取消、gate 不通過、runner 被要求停止（interrupted）、lease 失效（停止容器、run 留在 running）、plan 被拒（Docker 收到 0 個請求）、create 或 start 失敗、容器消失、Docker 中途不可用、輸出被拒絕；每個情境都確認容器已刪除、secret 已刪除。審查後補上：工作目錄不可寫（runs 或 secrets）時 run 失敗、不建立容器；啟動前、執行中的未預期例外仍先清掉容器與 secret；查不到狀態時重試、持續失敗但刪除成功時 interrupted；執行中超過輸出上限就停止容器；寫不出 manifest；沒有 plan 的引擎不記下容器；啟動後立刻心跳、收集前延長 lease；stop 失敗時由強制刪除收尾；刪不掉 secret 不影響 run。secret 只在容器存在時存在，0400，不在 create body 中；沒有認證的 scan 不掛 secret；解不開或沒有金鑰時不建立容器。
- **常駐迴圈與 CLI**：啟動時清掉殘留的 secret（還有其他存活的 runner 時不清）、probe 不通過（含 volume 不可寫）不認領而且 60 秒後重新 probe、lease 失效或 Docker 失敗之後繼續；`runner --once`、`worker --once` 的 exit code、DB 不可用、設定錯誤、SIGTERM 的處理。
- **心跳與 `GET /scanners`**：同一個 owner 一列、最新的存活 runner、30 秒沒有心跳就不算存活、7 天後刪除；任何角色都 200、沒有 key 401、未整合的引擎回 `NOT_INTEGRATED`。
- **migration 0006**：容器欄位的每個 CHECK、trigger 只允許在 preparing → running 記下一次；runner_instances 的每個 CHECK 與 unique。
- **reveal 的呼叫者**：AST 檢查 src 中只有 `runner/service.py` 呼叫 `reveal`。

T11 已涵蓋 runner 與 egress guard 的整合（`test_container_runner_guard.py`：以一個 spy 把容器的操作、policy 的寫入與 run 的轉換記在同一個有序的 log）：
- 建立容器之前 policy 已寫好（範圍、`not_after`、`renew_until`、token 的 hash 與容器內 0400 的 proxy-url 相符）；每次心跳都續約、不超過 lease。
- 停止的順序：取消是封鎖 → cancelling → stop → 刪除容器 → 刪除 policy；逾時與 runner 停止都先封鎖；lease 失效且刪不掉容器、Docker 中途不可用時 policy 保持 blocked；封鎖寫不出去仍會停止容器。
- guard 不可用（停機、不見、過期）或寫不出 policy：failed（`GUARD_UNAVAILABLE`），不建立容器、不留下 secret；執行中 guard 停機、重啟、過期或續約失敗：interrupted（`GUARD_UNAVAILABLE`）。
- 常駐迴圈每一輪都讀 status（停機 5 秒後恢復就認領，不等 60 秒的 probe）；guard 不可用或 policy 目錄不可寫時不認領、`/scanners` 回報 `GUARD_UNAVAILABLE`；只有沒有其他存活的 runner 時才清除殘留的 policy。
- 佇列在轉到 running 時帶回 grant 的範圍與期限，取消、gate 失敗、profile 被取代時沒有。

T06 已涵蓋 target 與 scope grant：
- A 專案讀寫 B 專案的 target 與 grant（含核准、撤銷），回應與不存在的 id、不存在的路徑完全相同。
- viewer 不能建立 target 或申請 grant；operator 不能核准或撤銷。
- 狀態轉換：domain 的轉換表、service 與 API 的 200 與 409，以及 DB trigger 擋下 raw SQL 的非法轉換與範圍修改。
- 併發：同時申請（version 連號）、同時核准與撤銷、掃描 gate 與撤銷或停用的先後，都以 `pg_stat_activity` 確認後到的在等列鎖；另有「撤銷先開始、核准先 commit」的確定性測試（審查時發現原本會回 500）。
- 數量上限：每個 target 的待核准申請與每個 project 的 target 數。
- `LAB_CIDR`：設定驗證，以及建立 target、申請、核准、掃描 gate 四個時點的檢查。

仍未完成的部分：
- **SEC-01**：「建立或開始掃描被拒」已在 T09 實作並測試：建立 scan 時以 gate 拒絕，排隊中的 scan 在 runner 啟動前（prepare）重新判斷、不通過就 failed。「已執行者停止新出站」要到 M2/T13（guard 的 policy 改成 blocked），T09 的 fake 不送出任何流量。
- **SEC-02、SEC-05**：T06 只完成應用層（origin 的嚴格解析，以及 grant 綁定 origin 與 IP）；T07 把規格的 `servers` 改綁到 target 的 origin，並拒絕其他會讓工具連到別處的欄位。guard 的檢查與實際收包證據要到 M2，工具實際讀到的規格在 M3 驗證。
- **SEC-11**：T07 完成規格解析的部分（拒絕外部參照、大小與深度的上限，平台不讀檔也不連網）。工具（ZAP、Schemathesis）對規格的實際行為，包含參照炸彈，在 M3、M6 以容器的資源上限與 guard 的收包紀錄驗證。
- **SEC-17**：T07 只涵蓋上傳的規格（JSON、YAML）；工具輸出的 parser（JSONL、XML、Markdown）在 M3 之後。
- **SEC-14**：T08 只完成平台自己的 API、日誌、audit 與 DB（以 canary 測試）；工具的輸出、證據與報告中的 token（以已知的 secret 值精確遮罩）在 M3 之後，不標成完成。
- **SEC-15**：T08 只把認證設定綁定 target，並拒絕會影響連線、代理、路由或 method 的 header；secret 只送往核准的 origin、跨 origin 的 redirect 不轉送，要到 M2 的 guard 以接收端證明。
- **SEC-12**：T10 完成映像、指令、環境變數、輸入檔與掛載的驗證（unit），以及真的 Docker 上「被拒的設定沒有產生容器」（live）。模板的 allowlist 在 M4（Nuclei）加入。
- **SEC-18**：T10 只涵蓋 runner 的收集（symlink、hardlink、特殊檔、大小）；artifact 的 storage key、下載與 worker 的解析在 M3、M5。
- **SEC-21**：T10 完成：plan 驗證與 create body 的不變式拒絕（unit）；socket-proxy 對 exec、archive、logs、pull、build、network／volume 的建立、其他容器、清單、路徑穿越與編碼、未核准的映像等 31 個端點回 403／405，帶 host bind 或 VolumesFrom 的 create 被拒；探針前後 daemon 上的容器完全相同（live）。殘餘風險：proxy 不檢查 privileged、namespace、capability，runner 被攻陷時仍能建立 privileged 容器（`DECISIONS.md` §14.1）。
- **SEC-02 到 SEC-10（T11）**：guard 逐請求檢查，並以 live 的接收端與 canary 的收包紀錄證明（§4.4）。仍未涵蓋：工具實際的 proxy 設定與規格（M3）；HTTPS 的 CA 與上游憑證驗證（SEC-09、SEC-10 的 HTTPS 部分，M3 之前一律拒絕 CONNECT 與 https）；body 中的 `_method` 與 path 中的 `%`（`DECISIONS.md` §15.10 的取捨，T14 量測）。
- **SEC-01（T11 的部分）**：guard 逐請求檢查 run 的期限（`not_after` 受 grant 的 `valid_until` 限制）、封鎖與續約；grant 撤銷時停止執行中的 scan 在 T13。
- **SEC-19（T11 的部分）**：取消時先封鎖 guard、再停止容器（live 以時間線證明）；孤兒容器的回收在 T13。
- **SEC-15**：T11 的 guard 只放行 scan 的 target origin，任何帶著認證的請求都送不到其他 origin；跨 origin 的認證 header 規則（多個 origin）在 T12，工具實際送出的認證在 M3。

### 4.4 Live E2E

完整 API → scope → auth → queue → Runner → 工具 → Parser → Finding → report。工具只在隔離靶場跑。每個 Adapter 的 live success 與其 unit test 成功分開標示。

T11 已涵蓋（`tests/live/test_guard_live.py`；live 自己的 lab 網路 10.89.10.0/24 上的接收端 lab-target、lab-canary，以及 control_net 上的 control canary；接收端記下每一個 TCP accept）：
- guard 非 root、唯讀、沒有 capability、只接 scan 與 lab（固定在 .254）、policy 唯讀，healthcheck 通過；lab 那一側連不到 guard 的 proxy。
- 34 種越界的請求（帳密、別的 origin 與 IP 寫法、Host 不一致、userinfo、HTTP/1.0、排除與未授權的 path、編碼與點段、字面的佔位、method、改寫目的地的 header、`_method`、websocket、`OPTIONS *`、CONNECT、`https://`）都回 403／407／400，前後各一個允許的請求證明接收端在記錄：目標只收到這兩個，canary 與 control canary 都是 0（SEC-02、SEC-05、SEC-08、SEC-09）。
- 目標收到的請求：Host 是 canonical、沒有 `Proxy-*`、來源是 guard 的 lab 位址（DoD 的收包證明）。
- redirect：302 照樣轉送，跟隨到 canary 或排除的 path 都被拒絕（SEC-03）。
- DNS：同一個名稱改指向 canary、或兩個容器共用 alias，都回 `ADDRESS_NOT_ALLOWED`（SEC-04）。
- 經 guard 到 db、socket-proxy、api、control canary、`169.254.169.254`、`host.docker.internal`、`localhost.localdomain`、guard 自己都被拒；guard 容器內也連不到這些位址（SEC-06）。
- 掃描網路上的容器直連靶機、canary、guard 的 lab 位址都失敗，解析不到外部名稱、lab 的名稱與 db（SEC-07）。
- 期限到了、沒有續約、已封鎖、損毀的 policy 依序回 `RUN_EXPIRED`、`POLICY_STALE`、`RUN_BLOCKED`、407（SEC-01 的 guard 部分、SEC-10）。
- token 與 query 不在 guard、runner、api、worker 的 log 與 `docker inspect` 中；guard 的 log 只有不含 query 的 path。
- 取消（SEC-19）：每 20 ms 送一次請求的探針記下，放行與拒絕之間沒有交錯、取消後 10 秒內開始拒絕；guard 第一次回 `RUN_BLOCKED` 早於容器的 kill／die 事件；之後接收端沒有再收到。
- 在 guard 的映像中，以 mitmproxy 12.2.3 的真物件驅動 addon，確認單元測試的假物件和真物件一致（16 項，含刪除小寫的 `x-secscan-guard`）。
- 尚未涵蓋：同一條 keep-alive 連線上交錯的放行與拒絕、pipelining 與 header 值中夾帶的請求（接收端與探針每個請求一條新連線）；目前只有單元測試，記為證據缺口（`DECISIONS.md` §15.10）。
- fake scan：執行中有這個 run 的 policy、容器內有 0400 的 proxy-url，結束之後都刪除。

T10 已涵蓋（`make test-live-runner`，`tests/live/`；獨立的 compose 專案、自己的 DB，跑完一律拆除；fake 引擎，不連 lab）：api、runner、worker 沒有 docker.sock、不是 privileged；socket-proxy 唯讀掛 socket、只接 docker_net；runner 容器內呼叫不該開放的 API 都是 403／405、沒有產生容器；api、worker 連不到 socket-proxy；`GET /scanners` 顯示 fake 可用；fake scan 的容器非 root、唯讀、無 capability、IPC 與 cgroup namespace 是 private、只有三個 volume subpath（只看得到自己的 in/、out/ 與 secret）、secret 0400、解析不到 proxy／db／api／runner、沒有預設路由，完成後容器與 secret 都刪除；取消後 30 秒內刪除容器；secrets volume 是 tmpfs；canary secret 不在任何容器的 log 與設定中。

### 4.5 故障注入

在 queued/preparing/running/collecting/collected/normalizing 各階段，分別中斷 api、runner 或 worker。另外要測：

- 兩個 runner 同時認領同一個 run
- lease 過期，但容器仍在執行
- DB 暫時不可用
- guard 不可用（必須 fail closed）
- 磁碟滿、容器 OOM、解析例外
- Token 到期、手動取消

結果要求：無重複同 run 活躍容器；未證明舊 run 停止前不啟動新 run；partial evidence 不被刪除；狀態不能永久顯示 running；不將錯誤轉為「0 漏洞」。

T11 已涵蓋（egress guard，`tests/live/test_guard_failover_live.py`）：guard 停機時 `/scanners` 顯示 `GUARD_UNAVAILABLE`、新的 scan 留在 queued、對 guard 的連線失敗（fail closed），恢復後完成；guard 重啟（`boot_id` 改變）讓執行中的 run interrupted（`GUARD_UNAVAILABLE`）；runner 被 SIGKILL 之後，孤兒容器的請求在 lease（30 秒）內開始被拒絕（`POLICY_STALE`）、接收端不再收到；設定錯誤、只接一個網路、模組損壞的 guard 以非 0 結束、從未監聽。

T10 已涵蓋（容器版的 runner）：runner 收到 SIGTERM 時停止並刪除容器、run 標成 interrupted（live 實測 1.3 秒）；lease 失效時停止容器；Docker 中途不可用時刪除 secret、不把 run 標成結束的狀態；容器 OOM、消失、create／start 失敗。lease 過期而容器仍在執行、孤兒容器在 T13。

T09 已涵蓋（fake 引擎，沒有容器）：兩個 consumer 同時認領；lease 過期之後不被接手，由對帳標成 interrupted（runner 階段）或退回 collected（解析中）；runner 停太久、lease 失效時在第一次心跳就停止；DB 等鎖逾時回 503；手動取消（排隊中、prepare 前、執行中、解析中）。容器、guard、磁碟、OOM 與 Token 到期在 M2 之後。

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
