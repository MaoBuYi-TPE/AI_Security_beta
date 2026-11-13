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

T12 已涵蓋（guard 的程式 line 與 branch coverage 100%；`DECISIONS.md` §16）：
- **預算與速率（SEC-13 的應用層）**：policy schema 2 的嚴格解析（速率、burst、剩下的請求數、認證 header 的名稱）；GCRA 的間隔、burst、等待的上限（超過不保留位置）、閒置不累積、依 scan 分開、過期的 key 清除；名額先保留、轉送才確定，拒絕、DNS 失敗、`request` hook 的重查、trailer、`error` hook 與取消（`CancelledError`）都釋放；用盡時不解析 DNS；等待之後重查 run（等待中被封鎖就拒絕）。
- **telemetry**：summary 與每一行的嚴格解析；轉送時先寫 summary 再附加一行，寫不出來就拒絕這個請求、名額回到轉送之前；拒絕只計 token 驗證過的 run，定期寫入；guard 重啟時由 summary 接續計數與序號，summary 損毀或屬於別的 scan 時 fail closed；過期的檔案與閒置的計數清除；path 不含 query，telemetry 中沒有 header 的值；telemetry 目錄不可寫時 status 不是 enforcing、結束時再寫一次。
- **preflight（§12.5）**：JSON Pointer 的嚴格比對（型別、陣列索引的前導 0 與 `-`、跳脫、指不到不等於 null）；原始 HTTP 回應的解析（chunked、header 的折行、缺少結尾、超過 64 KiB；長串空白加非法字元在 50 毫秒內拒絕，審查發現的 ReDoS）；`passed`、`failed`（含登入頁的 HTML）、`inconclusive`（含匿名的對照沒有有效回應）、`blocked`、`not_executed` 的判斷；plan 只接受 `http://<origin><path>`（沒有 query、帳密、換行）；runner 以 sha256 核准 script，改一個字就被拒絕；`header_line` 拒絕換行與 NUL。
- **coverage 與用量**：請求對應到最具體的 operation（佔位符、結尾的斜線、method）；沒有回應的不算、認證被拒絕（401、403）的不算 authenticated；preflight 的請求不算；`budget_usage` 遇到不明的數字就是 null；`coverage_measured` 要所有 run 都結束、每個容器 run 都已對應；`authenticated_operations` 要 preflight 是 `passed`；guard 保留中的名額有上限。

T14 已涵蓋（`DECISIONS.md` §18；新的 domain 模組 line 與 branch coverage 100%）：
- **ZAP 的 AF plan**：web 與 api 的 job 順序；spider 從 / 開始、一個執行緒、`postForm` 只在 grant 允許 POST 時打開、robots 與 sitemap 只在範圍內時讀取、Git／DS_Store／SVN 關閉；api 以只含 eligible operation 的文件匯入、`targetUrl` 是 target 的 origin 加 base path；activeScan 的 `defaultThreshold` 是 off、只有白名單的規則（web 與 api 各一份；排除的 16 個類別代表逐一確認不在任何一份）；report 只能是 `traditional-json` 而且 `alwaysRun`；任何字串含 `${` 就拒絕（AF 的變數代換）；以 PyYAML（YAML 1.1）解析的結果和 JSON 相同。
- **時間與預算**：maxDuration 取剩下的時間、請求數除以速率、grant 的期限中最小的，再減保留的 60 秒；不到下限就不執行；job 的上限至少 1 分鐘（0 是不限）（T16 改成 job 的上限一律是 0，只由 plan 的 maxDuration 限制，`DECISIONS.md` §20.5）。Hypothesis：任何預算下都不超過任何一個上限。
- **grant → context 的 regex**：literal、佔位、`allow_all_paths`、排除不分大小寫與結尾的斜線但不涵蓋底下的 path、預設 port 的寫法；模擬 AF 把 url 加成 `url.*` 的 include 之後仍不擴大範圍（負向前瞻的排除）；Hypothesis 以 Python 的 re 和 guard 的 `covers()` 對照。
- **zap.properties**：proxy 的帳密與速率逐行核對；token 不是 43 個 base64url 字元（含換行、`=`、反斜線）、速率或 port 超出範圍都拒絕；repr 不顯示 token。
- **probe 的判斷**：退出 0、版本相同、必要的 add-on 是審查過的版本（同一個 add-on 取最大的檔案）才相容；退出 2 是不相容（未知的規則 ID），其他是失敗；報告或清單讀不到、格式不符、超過 64 KiB 都是失敗；不認得的行略過。
- **只含 eligible operation 的規格**：只留下 eligible 的 operation（以含 base path 的 path 比對）、保留 path 層級的 parameters、刪掉 `x-` 與空的 path item；`servers` 不是 origin 加 base path 就拒絕；`operationRef` 指向被刪的 operation 時 fail closed；輸出是 compact JSON、不比輸入大；VAmPI 的規格只留下 GET。
- **政策與 admission（SEC-12）**：每個 zap 的 plan 與 probe 的 plan 都通過；script 的 sha256 與政策一致，改一個字（含拿掉 `-silent`、`-nostdout`）就被拒絕；`ZAP_AUTH_HEADER_VALUE` 永遠不能在 plan；anonymous 只能有模式，header 模式一定有名稱與 host；模式和 `target_auth` 不一致被拒絕；輸入檔的名稱與大小（最大的規格放得下）；超過上限。create 的 body：zap 只有宣告的 tmpfs（改 path、拿掉 noexec 或 nosuid、加大、多一個、缺少都被拒絕），其他引擎加上 tmpfs 被拒絕；所有引擎的 healthcheck 必須是 NONE；送出前的檢查以自己的 tmpfs 字面值核對（改了引擎政策也擋下）。
- **workspace**：manifest 記下退出碼與輸入檔的 hash；空的 secret 目錄只能建立一次；`zap.properties` 是已知的 secret 檔、會被刪除；`read_output` 不跟隨 symlink（檔案或被換掉的 out/）、只讀一般檔案、有大小上限。
- **probe 的步進**：通過之前是 `ENGINE_PROBE_PENDING`、期間其他引擎照常可用；通過之後帶版本、同一個映像不再執行；失敗與不相容以退避重試、每次新的 id；逾時就停止並刪除；Docker 在啟動時出錯是失敗；刪不掉的容器留下 secret 目錄（下次啟動的清理依它找回）；映像不在時不執行；runner 停止時刪除執行中的容器。
- **審查之後補上的**（T14 的 code-reviewer 與 security-reviewer）：
  - **掃描的 script 以 dash 實際執行**（容器的路徑換成暫存目錄與替身）：
    - anonymous 時 unset 所有 `ZAP_AUTH*`，有 secret 檔就 exit 64。
    - header 模式下，值原樣 export（含 `$`、反引號與空白），有沒有結尾的換行都一樣；缺少檔案、前綴不符、值是空的、缺少 header 名稱或 SITE、不認得的模式都 exit 64。
    - out/ 寫不了就 exit 65。
  - **AF plan 的內容由 runner 的政策獨立檢查**：
    - 以下都被拒絕：檔案中或解析之後（`\u0024` 跳脫）有 `${`、不在白名單的 job、報告的範本是 `-plus`、報告的目錄不對、兩個報告或沒有報告、`defaultThreshold` 不是 off、不是 JSON、超長的整數、過深的巢狀。
    - probe 的 plan 以 sha256 核准。
    - 規格不經過 AF 的代換，照樣接受 `${`。
  - **probe 的樣板不接受任何環境變數或認證**。
  - **會改 method 的規則**（20018、40045、40048）只在 grant 允許 POST 時執行。
  - **範圍外的排除**：結尾有換行的 URL 也擋得下。
  - **probe 執行中超過用量上限就停止**；報告中超長的整數是失敗、不是例外。
- **API 的設定**：zap 的 web profile 需要 grant 允許 GET /（只檢查 zap）；`GET /scanners` 的版本與三個新的能力代碼。

T15 已涵蓋：
- **狀態機**：`normalizing → timed_out` 要有錯誤碼；`aggregate()` 的 `checks`（preflight 的每種組合，Hypothesis 另外檢查順序無關、終止與否）。
- **遮罩（SEC-14）**：`secret_masking` 每種形式（原樣、JSON、HTML、百分比編碼的大小寫與 `+`、JSON 包 HTML）；不論怎麼切塊結果都相同（Hypothesis）、最長的形式優先、近似比對是線性時間、值不在 repr。`redact_url`、`redact_text`：帳密、敏感參數、header、cookie、JSON 欄位，重複套用結果不變、線性時間。`display_text`：NUL、孤立的 surrogate、bidi、控制字元換掉，輸出一定存得進 PostgreSQL（Hypothesis）。
- **收集（SEC-18）**：全空白的檔名被拒絕；兩階段、暫存檔在 out/ 之外、hash 是遮罩後的內容、跨塊邊界的 secret、變大超過上限被拒絕、走訪之後被換成 symlink、hardlink 或目錄被換掉都被拒絕、寫入失敗的訊息沒有路徑、沒有留下暫存檔。
- **parser（SEC-17）**：真實的報告都接受；由真實報告衍生的每一種壞掉的輸出都是問題代碼、不丟例外（截斷、空檔、非 UTF-8、重複的 key、NaN、浮點數、超長的整數、過深的巢狀、超過上限、缺少或型別錯誤的欄位、其他版本）；任意的 bytes 與 JSON 只會得到判定（Hypothesis）。
- **判定**：退出碼與 AF 摘要的每種組合、沒有報告的退出碼 1、報告列出但讀不到、log 缺少；重複的事件；欄位的截斷在遮罩之後；識別不含 ZAP 每次都不同的 instance id。
- **排除**：每一層各自的計數、telemetry 缺少時改看拒絕訊息、有 telemetry 時目標放進拒絕的文字不能隱藏告警、有上游回應就算目標的回應（不看 status）。`scope_reason` 和 guard 的完整判斷一致（Hypothesis）。

### 4.2 Contract / Parser

每個鎖定版本保存遮罩後真實輸出 fixture：正常無告警、存在告警、非零退出但有有效 findings、格式截斷、未知欄位、缺必要欄位、空檔、重複事件、Unicode、超大單行/總量、timeout 後部分 artifact。版本不支援時明確 error，不默默漏掉資料。

T15 的 ZAP fixture（`tests/fixtures/zap/<情境>/`，真實輸出，`make record-fixtures` 錄製、人工審查之後搬入；離線的情境在 `--network none` 錄製）：`clean`（零告警）、`findings`、`timeout`（plan 的 maxDuration，退出碼 2）、`unanswered`（目標沒有回應，mitmproxy 的 502 被告警）、`unreachable`（連不到 host，退出碼 1、有報告）、`engine-error`（ZAP 啟動失敗，退出碼 1、沒有報告）。壞掉的輸出在測試中由真實報告的位元組衍生，不存成檔案。`tests/contract/test_zap_fixtures.py` 固定每份輸出判讀的結果（`make test-contract`）。

T20 把 T30 的 fixture app 弱點版錄製升為 golden（`tests/fixtures/zap/fixture-vuln-{web,api}/`，原樣複製，`report.json`、`zap.log` 的 sha256 等於 runner manifest；審查：只有 lab 主機、沒有 Authorization／Bearer／Cookie 的值、JWT、平台 key 或種子 token；manifest 記下錄製時的 grant 以重建 scope）。`test_zap_fixtures.py` 加上兩個情境（觀察數 23／11 等於平台當時寫入的數量），`test_dedup_recorded_outputs.py` 以真的 parser 與 `plan_links` 斷言實際的分群（DEDUP 表）。這些錄製只用於去重的回歸，不用來調整規則（holdout 在 T27／T28）。

T07 加入上傳用的規格 fixture `tests/fixtures/openapi/vampi-openapi3.yml`：T03 輸入的 VAmPI 規格，只把登入回應 example 中的範例 JWT 遮罩成 `REDACTED_JWT`。manifest 的 `openapi_fixtures` 記下遮罩前後的 sha256，contract 測試檢查兩者與防洩密規則。

### 4.3 Integration

以 PostgreSQL（compose 的 `db-test`，見 `DECISIONS.md` §7）+ FakeRunner 驗證。伺服器必須是 `cluster_name=secscan-test`；測試程序本身不碰 Docker daemon。

每個測試資料庫有兩個專屬的非 superuser 角色，和開發／正式環境相同（T23b-b1，`DECISIONS.md` §31）：
- `<db>_owner`：擁有資料庫與所有物件，只用於 migration、DDL 的故障注入，以及驗證 trigger 那一層的語句；
- `<db>_app`：只有 v0025 的逐表 DML。api、worker、runner 與 CLI 的測試以它執行。
- **以 owner 執行**：只驗證 schema 的 6 個模組、findings 與 triage 的 `session` fixture，以及個別測試中的 DELETE、TRUNCATE、停用 trigger 與 DDL 的故障注入（`tests/integration/conftest.py` 的說明）。

驗證項目：

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

SEC-16 的 artifact 部分：T21 依使用者決定不提供 artifact 下載，改以報告涵蓋（§4.3 的 TRIAGE／REPORT 表：A 專案的 key 對 B 專案的 triage、triage-events、報告的建立／查詢／清單／下載、停用 profile 與引用 B 專案的比較快照，一律與不存在相同的 404）；scan 已在 T09、observation 已在 T15、scan 的 finding 清單已在 T19 涵蓋（見下；`GET /findings/{id}` 在 T20）。T07 的規格與 inventory 已涵蓋：A 專案讀寫 B 專案的 target、規格與 grant 預覽，回應與不存在的 id、不存在的路徑完全相同。T08 的認證設定同樣涵蓋：建立、查詢、版本歷史與 PATCH，回應與不存在的 id、不存在的路徑完全相同。

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
- **SEC-01**：「建立或開始掃描被拒」已在 T09 實作並測試：建立 scan 時以 gate 拒絕，排隊中的 scan 在 runner 啟動前（prepare）重新判斷、不通過就 failed。「已執行者停止新出站」在 T13 完成（見下方 T13 與 §4.4）。
- **SEC-02、SEC-05**：T06 只完成應用層（origin 的嚴格解析，以及 grant 綁定 origin 與 IP）；T07 把規格的 `servers` 改綁到 target 的 origin，並拒絕其他會讓工具連到別處的欄位。guard 的檢查與實際收包證據要到 M2，工具實際讀到的規格在 M3 驗證。
- **SEC-11**：T07 完成規格解析的部分（拒絕外部參照、大小與深度的上限，平台不讀檔也不連網）。工具（ZAP、Schemathesis）對規格的實際行為，包含參照炸彈，在 M3、M6 以容器的資源上限與 guard 的收包紀錄驗證。
- **SEC-17**：T07 只涵蓋上傳的規格（JSON、YAML）；T15 涵蓋 ZAP 的 JSON 報告與 log（§4.1、§4.2）；**T18 涵蓋 Nuclei 的 JSONL（逐行嚴格解析、壞行整份 OUTPUT_INVALID、大小上限）**；**T21 涵蓋平台報告的安全呈現**（§4.3 的 REPORT 表：JSON 跳脫、Markdown 以 CommonMark 實際解析的 token 不變式、Hypothesis 與惡意輸入集合、8 MiB 上限）；Schemathesis 的輸出在 M6 之後。
- **SEC-14**：T21 補上平台報告這一側（canary 不出現在 JSON 與 Markdown，§4.3 的 REPORT-01）；**T23a 的離線部分已實作（`DECISIONS.md` §30）：原始證據在 run 結束（解析完成、失敗或逾期）之後以只給 runner 的金鑰加密、7 天後清除；報告內容與人工複測摘錄以只給 api 與 worker 的金鑰加密、30 天後清除；三組平台金鑰分開、可換版；`benchmarks/results` 以本機的 bench 金鑰加密（§4.3 的 KEY、SEAL、EVID、CONT、RET、ROT、BSEAL 表）。這不是全程靜態加密：執行、收集與等待解析期間是明文（§8 的剩餘風險）。T23a 的 Live 在 2026-11-12 通過，T23a 完成；**SEC-14 仍不標完成**，P0 的完成條件見 `DECISIONS.md` §30.14。**T08 只完成平台自己的 API、日誌、audit 與 DB（以 canary 測試）；T15 完成 ZAP 的輸出與觀察（以已知的 secret 值精確遮罩，`DECISIONS.md` §19.5）；**T18 完成 Nuclei 的 JSONL 輸出與觀察（runner 以 `SecretMasker` 做位元組級遮罩、parser 以 `redact_text`／`redact_url` 做文字層遮罩，涵蓋 extracted-results／request／response／curl-command，`DECISIONS.md` §24.3）**；Schemathesis 的 token 在 M6 之後，不標成完成。
- **SEC-15**：T08 只把認證設定綁定 target，並拒絕會影響連線、代理、路由或 method 的 header；secret 只送往核准的 origin、跨 origin 的 redirect 不轉送，要到 M2 的 guard 以接收端證明。
- **SEC-12**：T10 完成映像、指令、環境變數、輸入檔與掛載的驗證（unit），以及真的 Docker 上「被拒的設定沒有產生容器」（live）。Nuclei 模板的 allowlist 已在 **T17** 凍結（清單＋每檔 sha256＋`-ni -duc -pt http` 等執行設定，`DECISIONS.md` §23；清單外的模板一律不執行）；**T18 把凍結的 42 個模板以 InputFile 掛進 `/scan/in`、admission 以每檔 `ContentDigest` 核准（清單外的模板無法掛載，不用 `-id`），並加 `-dut` 只跑簽章模板（§24.2）**。
- **SEC-18**：T10 涵蓋 runner 的收集（symlink、hardlink、特殊檔、大小）；T15 涵蓋遮罩的兩階段與 worker 只讀 manifest 列出的檔案；**T21 不提供 artifact 下載**（只能以 report id 下載平台產生的報告，`?path=`、`?storage_key=` 不影響結果，`/artifacts/{id}/download` 回 404，§4.3 的 REPORT-05）。
- **SEC-21**：T10 完成：plan 驗證與 create body 的不變式拒絕（unit）；socket-proxy 對 exec、archive、logs、pull、build、network／volume 的建立、其他容器、清單、路徑穿越與編碼、未核准的映像等 31 個端點回 403／405，帶 host bind 或 VolumesFrom 的 create 被拒；探針前後 daemon 上的容器完全相同（live）。殘餘風險：proxy 不檢查 privileged、namespace、capability，runner 被攻陷時仍能建立 privileged 容器（`DECISIONS.md` §14.1）。
- **SEC-02 到 SEC-10（T11）**：guard 逐請求檢查，並以 live 的接收端與 canary 的收包紀錄證明（§4.4）。仍未涵蓋：工具實際的 proxy 設定與規格（M3）；HTTPS 的 CA 與上游憑證驗證（SEC-09、SEC-10 的 HTTPS 部分，M3 之前一律拒絕 CONNECT 與 https）；body 中的 `_method`（`DECISIONS.md` §15.10 的取捨；T14 的小型網站沒有這個欄位，T16 以真的靶機量測）。path 中的 `%`：T14 的 live 量測中，ZAP 對 path 參數的攻擊有 83% 以 `PATH_AMBIGUOUS` 被拒（`TOOLS.md` §7.5），維持 fail closed，覆蓋的缺口在 T16 量化。
- **SEC-01（T11 的部分）**：guard 逐請求檢查 run 的期限（`not_after` 受 grant 的 `valid_until` 限制）、封鎖與續約。T13 補上執行中的停止：grant 撤銷或到期、target 停用、建立者的 key 撤銷時，runner 在下一次心跳先封鎖 guard、再停止容器。
- **SEC-19（T11 的部分）**：取消時先封鎖 guard、再停止容器（live 以時間線證明）。T13 補上 runner 遺失時的回收：對帳先封鎖、再強制刪除孤兒容器，確認之後才結算。
- **SEC-15**：T11 的 guard 只放行 scan 的 target origin，任何帶著認證的請求都送不到其他 origin。T12 以 live 證明（§4.4）：帶著 `Authorization` 的請求只到達 target，另一個 origin 的接收端沒有任何連線；preflight 的帶認證請求只送到 target。使用者決定維持只放行 target origin，跨 origin 的認證 header 規則（多個 origin）延後；工具實際送出的認證在 M3。
- **SEC-13（T12）**：guard 強制 scan 共用的請求數與速率，preflight 也計入；以 live 的接收端與 guard 的 telemetry 證明（§4.4）。實作以 scan 為單位（P0 同一個 target 同時只有一個 scan，和「target 合計」等價；多個 runner 時要改 key，`DECISIONS.md` §16.8）。延遲 body 只能累積 11 個已核准的請求。仍未涵蓋：多個真的引擎依序共用預算（M3、M4；目前以 preflight 加上不送流量的 fake 證明分配與扣除的規則）、依量測調整 lab profile 的預算（M3）。
- **SEC-12（T14）**：zap 的政策（映像、兩個以 sha256 核准的 script、環境變數與 `target_auth` 的對應、輸入檔、上限）與 create body 的新規則（只有宣告的 tmpfs、healthcheck 關閉）。
- **SEC-02、SEC-05、SEC-11（T14 的部分）**：交給 ZAP 的規格只有 eligible 的 operation、`servers` 與 `targetUrl` 都是核准的 target；規格中其他 URL（externalDocs、license、contact、draft-04 的 `id`、examples）與參照較深的規格以 live 的 canary 驗證（§4.4 的 T14）。
- **SEC-14（T14 的部分）**：proxy 的 token 與目標的 secret 不在 zap 容器的 Env、Cmd、Labels、`out/zap.log` 與報告中（live）；`-configfile` 的值只在 tmpfs 的 log（`-nostdout`）。工具輸出與證據的精確遮罩在 T15。

T12 已涵蓋（真的 DB 佇列）：
- 預算：容器版的 run 分到剩下的請求數並記下；之後的 run 扣除之前的 run 實際轉送的數量與流量的秒數，轉送數不明時整份扣除；剩 0 不建立容器（`BUDGET_EXHAUSTED`）；用量超過分到的數量被 DB 的 CHECK 拒絕；寫回用量要持有 lease。
- runner：guard 的 summary 說用盡 → 封鎖 → 停止 → `timed_out`（`BUDGET_EXHAUSTED`），不等到牆鐘上限；結束前寫回 guard 的計數；沒有 summary 而且同一個 guard 是 0；guard 重啟、summary 損毀或屬於另一個 boot、容器沒確認刪除時留空；沒有啟動容器、plan 被拒絕時是 0。
- preflight：有 auth profile 的 scan 第一個 run 是 preflight；`prepare_launch` 帶回綁定版本的定義；容器拿到 0400 的 `auth-header`（`Authorization: Bearer …`），結束後刪除；profile 被取代時 preflight 與之後的 run 都在 prepare 失敗。
- worker：依 runner 收集的輸出判斷五種結果；沒有讀取器（in-process）是 `not_executed`；只有 preflight 的 run 能寫結果；coverage 的對應、preflight 不算、沒有轉送、轉送數不明、telemetry 缺少或比轉送數多；寫入 coverage 之後中斷能在重試時完成；lease 失效的 run 跳過、不讓 worker 結束。
- API：`budget_usage`、`auth.preflight`（in-process 跑完是 `not_executed`）、coverage 的新欄位與 limitations。

T13 已涵蓋（真的 DB 佇列、記憶體中的容器 runtime、tmp 中的 policy 目錄；spy 把 policy 的寫入、容器的操作與 DB 的轉換記在同一個有序的 log）：
- schema（migration 0009）：`container_removed_at` 只能寫入一次、只有記下容器的 run 能寫、不早於開始；已終止的 run 只允許補寫它，同時改其他欄位（用量、錯誤碼、結束時間、coverage）都被 trigger 拒絕；downgrade 還原原本的 trigger。
- 對帳（SEC-19、DoD 2、DoD 3）：執行中的孤兒是封鎖 → 刪除容器 → 結算（`interrupted`、`LEASE_EXPIRED`，用量留空、scan 重新彙總）→ 刪除 policy；要求過取消也一樣是 `interrupted`；lease 有效的不碰；Docker 不可用時不結算、policy 保持 blocked、同一段中斷只記一次，恢復之後結算；409 只延後那一個；404 直接結算；label 不符的容器不刪、run 照常結算；已結束的 run 留下的容器只記下刪除的時間，worker 仍能解析；preparing 時中斷、或記下刪除之後才中斷的 run 不必呼叫 Docker 就結算。
- 不重複啟動（DoD 1）：lease 過期而容器仍在執行時，另一個 runner 不認領同一個 scan 的下一個引擎，結算之後才會；兩個 reconciler 只結算一次；凍結的 owner 在結算之後不能再心跳、轉換或寫入用量；建立容器之前的心跳發現 lease 失效就不建立容器。
- 啟動時依證據清理：已結算或 DB 沒有的 run 留下的 policy、secret 與容器被清掉；待處理、lease 有效的保留；Docker 不可用或 409 時保留 blocked 的 policy；暫存檔超過 60 秒才刪；迴圈啟動時先對帳再認領，之後每 10 秒一次。
- 撤回授權（SEC-01）：心跳以不加鎖的讀取回報 grant 撤銷、到期、target 停用、origin 改變、`LAB_CIDR` 不符、建立者的 key 撤銷；撤銷還沒 commit 時心跳不等待（以 `Race` 的背景連線確認）；同一個 session 中讀到新的值。runner 執行中看到 → 封鎖 → stop → remove → `failed`（該錯誤碼），不收集輸出；建立容器之前看到 → 不建立；同時要求取消時走取消；in-process 的 FakeRunner 也停止。
- 解析重試：第 3 次過期是 `failed`（`PARSE_ATTEMPTS_EXHAUSTED`），每個 run 各自計數；worker 遇到單一 run 的例外只記類別（不記訊息）、繼續處理其他 run，DB 的錯誤照舊結束。

T14 已涵蓋（真的 DB 佇列、記憶體中的容器 runtime 模擬 ZAP 的容器：啟動那一刻記下 secret 檔、輸入檔與環境變數）：
- **plan 與 secret**：anonymous 的 web run 只有模式的環境變數、只有 plan.yaml、spider 從 / 開始；secret 是 proxy-url 與 zap.properties（0400），zap.properties 的密碼與 proxy-url 的 token 相同、帳號是 run_id、速率是 scan 的速率；容器刪除之後 secret 全部刪除。api run 交給 ZAP 的規格只有 eligible 的 operation（grant 只允許 GET：DELETE 不在）、servers 與 targetUrl 是 target。帶認證的 run：preflight 先跑，zap 的環境變數只有模式、header 名稱與 host，auth-header 是 `Authorization: Bearer …`，值不在 create 的 body 與輸入檔中。
- **退出碼**：0、1、2 收集輸出，manifest 記下退出碼與 plan.yaml 的 hash；64、65、3、143 是 `ENGINE_FAILED` 而且不收集；OOM 是 `RESOURCE_LIMIT_EXCEEDED`。
- **預算**：剩下的時間（100 秒）或請求數（200 個）不夠 ZAP 執行時不建立容器、`BUDGET_EXHAUSTED`。
- **取消**：執行中的 zap run 被取消時停止、刪除容器與 secret，run 是 `cancelled`。
- **runner 的加固**：沒有 plan 的引擎（schemathesis）不會拿到其他引擎的 plan、不記下容器與映像。
- **佇列**：zap 的 api run 在 prepare 時拿到上傳時正規化的文件、base path 與凍結為 eligible 的 operation；web run 與其他引擎沒有規格。
- **迴圈與 probe**：probe 期間 fake 照常認領、zap 是 `ENGINE_PROBE_PENDING`，runner 停止時刪除執行中的 probe 容器；zap 的 run 等 probe 通過之後才執行，能力記下版本。
- **API**：T15 起接受 zap、**T18 起接受 nuclei** 的 scan（schemathesis 仍是 422 `ENGINE_UNSUPPORTED`）；zap 的 web profile 而 grant 沒有 `GET /` 是 422 `PROFILE_INCOMPATIBLE`，fake 不受這個規則影響。

T15 已涵蓋（真的 DB）：
- **schema**：artifacts、observations 的每個 CHECK、唯一約束與複合 FK（不能跨 scan 引用、報告屬於同一個 run）；沒有直接 FK 到 scans；不可修改、刪除或 TRUNCATE；run 的結果欄位一致，run 結束之後被 trigger 凍結。
- **worker**（`tests/integration/test_worker_zap.py`，真實的輸出經 runner 的收集）：每份 fixture 的 run、scan、observation 與 artifact；壞掉的輸出是判定、不是崩潰（NUL 與孤立的 surrogate 不再讓 worker 反覆失敗）；寫入是原子的，第二次寫入與失效的 lease 被拒絕；寫入之後中斷時重試以存下的判定結束，輸出已刪除也一樣；解析中要求取消、授權撤回不中斷解析；解析期間延長 lease，失效時留給對帳。
- **runner**：secret 在收集之前已不在 secret 檔，仍以 provision 時的值遮罩；proxy 的 token 與 base64 的形式；preflight 的輸出不遮罩；收集的過程中持續心跳，lease 失效時中止。
- **API（SEC-16）**：`GET /scans/{id}/observations` 的欄位、順序、分頁、limit 的上限、引擎篩選；其他 project 與不存在的一樣 404；`GET /scans/{id}` 的 `result`；`GET /scan-profiles` 只列可用的 profile 與引擎。

T19 已涵蓋（真的 DB；`DECISIONS.md` §25）：
- **schema**（`test_findings_schema.py`）：findings 的每類 CHECK（OWASP 的格式與來源一致、CWE 與來源一致、參數位置與名稱、列舉）、`(target_id, fingerprint)` 唯一、first／last seen 的複合 FK；trigger 讓身分、對應、triage 與 lifecycle 不可修改，聚合只會往上，不能 DELETE／TRUNCATE；finding_observations append-only、每個觀察最多一次。
- **連結**（`test_finding_linker.py`）：同一次 scan、同一個位置有 ZAP 的錨點時 nuclei 的 header 觀察併入 → 一個 finding（最高等級、衝突、對應）；別的 scan、別的位置、錨點規則的其他 variant 都不佐證；CORS 兩個 finding；技術識別保留技術名；fallback 單一引擎、unclassified；冪等；複掃沿用同一個 finding、聚合只往上；不同 target 不共用；有規格時 route 樣板化；身分失效（`auth.lost`）或 preflight 沒有通過 → 另一個未驗證的 finding；lease 失效不連結；兩個 run 同時連結不死鎖、不重複；ZAP 還在 collected 或 normalizing 時 worker 不認領同一個 scan 的 nuclei（依 sequence 解析）。
- **worker**：解析入庫之後連結（ZAP golden 的 11 個觀察都連結到審查過的群組；nuclei 的 fallback 標 needs_review）；中斷之後重試只補上沒有連結的觀察。
- **API（SEC-16）**（`test_findings_api.py`）：`GET /scans/{id}/findings` 的欄位（category、原始 CWE、未對應的原因、相關的 finding）、來源彙總、排序、篩選（含 category、needs_review）、分頁、不合法的值 422；只列這個 scan 的 finding、sources 只算這個 scan；其他 project 與不存在的一樣 404，沒有 key 是 401。

T20 已涵蓋（`DECISIONS.md` §26）：

**去重的反例（DEDUP；Gate D 的去重部分）**：`tests/unit/findings/test_dedup_counterexamples.py` 以真的 taxonomy 與 `plan_links` 比較 fingerprint；`tests/dedup_support.py` 的不變式（每個 finding 的觀察在 method、route、參數、身分、物件上都相同；不同的規則只能是同一個審查群組的成員；跨引擎只限佐證群組且有同一次 scan、同一個位置的錨點）在 unit、contract、integration、live 共用。

| 編號 | 不應合併的情況 | 層級 |
|---|---|---|
| DEDUP-01 | 同 CWE-89、同一個 path 的不同參數（POST /login 的 username 與 password） | unit、contract（真實錄製）、live |
| DEDUP-02 | 同一個參數名、位置不同（query 與不明） | unit |
| DEDUP-03 | 同 CWE-693 的不同群組（CSP 與 X-Content-Type-Options） | unit、contract |
| DEDUP-04 | 未審查規則的不同參數 | unit |
| DEDUP-05、06 | 同 route、不同身分（anonymous／standard_user／admin） | unit |
| DEDUP-07 | 同一個身分、驗證有效與失效 | unit（T19 的整合測試另有真的 guard 計數） |
| DEDUP-08、18 | 同一個規格樣板的不同物件（fallback，v2；帶參數也一樣） | unit（舊程式下 RED） |
| DEDUP-09 | 沒有規格時不同物件是不同的字面 route | unit |
| DEDUP-10 | 同一個參數的不同弱點（SQLi 與 XSS；真實錄製 GET /go `next` 的三個群組） | unit、contract |
| DEDUP-11 | 同一個規則的不同 variant（審查過與未審查） | unit |
| DEDUP-12 | 未審查的規則不跨引擎合併 | unit |
| DEDUP-13 | CORS 兩個工具只標示相關 | unit、T19 的整合與 live |
| DEDUP-14 | 技術識別以技術名區分 | unit |
| DEDUP-15 | 佐證只限同一次 scan | unit、T19 的整合 |
| DEDUP-16、17 | 不同 method、不同 target | unit |

合併的對照組（必須合併，避免反例只靠「什麼都不合併」通過）：MERGE-01 只有標題、等級、信心、工具 CWE 不同；MERGE-02 佐證的 header；MERGE-03 審查過的參數群組跨物件；MERGE-04 endpoint 粒度不看參數；MERGE-05 同一個 role label 的不同 auth profile（刻意的合併）；MERGE-06 同一個物件的複掃；真實錄製中 /search 的兩個 X-Content-Type-Options 觀察只有 query 不同。另外三個 Hypothesis 性質：只改一個身分維度一定拆開、只改非身分欄位一定合併、任意一批觀察的規劃都滿足不變式。

- **schema（v0015）**（`test_findings_schema.py`）：連結帶著在 finding 上保留的序號；沒有保留、重複或沒有序號的連結被拒絕；保留了卻沒有連結（含直接改計數、新的 finding 宣稱有連結）在 commit 時失敗；連結數不能減少；觀察與 finding、first／last seen 的 scan 與 finding 屬於不同 target 時拒絕；連到不存在的 finding 是 FK 的錯誤；第二個寫入者等第一個 commit，別人保留、還沒提交的序號不能用（讀者看到的連結數 H 之內都已提交，rollback 不留空號）；升級依連結順序回填序號；既有資料跨 target 時升級失敗、停在 0014。
- **寫入端**（`test_worker_zap.py`）：有觀察但 manifest 沒有這個 run 的報告 artifact 時整筆不寫入。
- **追溯 API（SEC-16）**（`test_finding_provenance_api.py`，真的佇列與 linker）：明細有上限、不含 storage_key；每個觀察追到報告 artifact（sha256、大小）與 run（映像、plan_hash、版本）；連結的值是寫入時的值（舊的 taxonomy_sha256 原樣回傳）；沒有引用報告的舊觀察 artifact 是 null、不丟掉；跨 3 次 scan 的歷史與觀察在翻頁之間新增 scan 也不重複、不遺漏（同一個 as_of）；1,500 個觀察的 finding 15 頁完整，1 筆與 100 筆的頁 SQL 數相同、明細與歷史也都在 12 個以內（沒有 N+1）；明細帶舊的 as_of 時 seen、engines、recent_scans 是快照的值；近期只留 5 次 scan；部分失敗（ZAP timed_out 或 succeeded、nuclei 預算不足 failed）時已取得的觀察可追溯、歷史列出 0 個觀察的失敗引擎、scan 不是 completed；中斷之後重試沒有重複；scan_id、engine 篩選；不合法的值 422；其他 project 與不存在的一樣 404（帶 as_of、scan_id、engine 也一樣，參數的檢查在權限之後），沒有 key 是 401。

**複掃的反例（RESCAN；T22，Gate D 的複掃部分）**：純分類、scan 可比性及實際事實建構分開測試；`tests/unit/comparisons/` 不連網，`test_comparison_facts.py`／`test_comparisons_api.py` 以真的佇列與 linker 驗證。人工 triage 與報告的完成度仍屬 T21。

| 編號 | 情境／必要結果 | 層級與測試位置 |
|---|---|---|
| RESCAN-01 | 引擎 succeeded 但沒到原位置 → inconclusive | unit：classification、evaluation |
| RESCAN-02 | 位置有回應但無規則完整執行證明 → inconclusive | unit：evaluation（實際 producer 維持 rule_completed=false） |
| RESCAN-03 | role 不同 → not_comparable；role 未知／preflight 失效／rejected → inconclusive | unit：classification、evaluation；integration：comparison_facts |
| RESCAN-04 | 一個來源失敗、逾時或時間上限未知，不能由另一個成功來源遮掩 → inconclusive | unit：classification、evaluation |
| RESCAN-05 | fingerprint／mapping／taxonomy hash 不同或未知 → inconclusive＋人工確認，兩側有告警也一樣 | unit：classification、comparability、evaluation；integration：comparison_facts |
| RESCAN-06 | scope 排除原位置／origin 改變 → not_comparable；無法解析或缺 path → inconclusive | unit：evaluation |
| RESCAN-07 | spec 新增、移除、內容改變或有 spec 卻缺 hash → 不接受負面結論 | unit：comparability、classification |
| RESCAN-08 | 規則集／模板、映像、components 或 profile 定義改變／未知 → 不接受負面結論 | unit：provenance、input_validation、evaluation |
| RESCAN-09 | 有參數但無法證明參數可比 → inconclusive；不擷取名稱或值充數 | unit：classification、evaluation、worker/location_summary；schema 約束 parameters_unknown |
| RESCAN-10 | telemetry 缺漏、缺明細檔的零流量、重複序號或錯配 → locations_recorded=false，不據此判漏報為修補 | unit：worker/telemetry_reader；integration：worker_zap、comparison_facts |
| RESCAN-11 | current-only 但 baseline 無覆蓋 → inconclusive，不猜 new；零 finding 是空快照，不等於完整掃描 | unit：classification；integration：comparisons_api |
| RESCAN-12 | 同位置 related／佐證群組換身分 → reidentified＋人工確認，不自動合併 | unit：reidentification、evaluation；integration：comparisons_api（真的雙引擎 linker） |
| RESCAN-13 | baseline finding 身分未驗證 → inconclusive；不能以 current 的健康身分補正 | unit：classification、evaluation |
| RESCAN-14 | 同 OpenAPI 樣板但只請求另一個物件 → inconclusive，逐一核對原始字面 path digest | unit：evaluation；integration：comparison_facts（只讀 digest） |
| RESCAN-15 | fixture／profile 不同 → not_comparable；同 scan、逆序、跨 target、未終止各有明確錯誤 | unit：comparability、evaluation；integration：comparisons_api |
| RESCAN-16 | 觀察已寫入但尚未連結 → observations_complete=false，不當作零告警 | integration：comparison_facts |
| RESCAN-17 | 同一對同時建立／先到者回滾、audit 故障、未封存 commit → 單一完整快照或全部回滾 | integration：comparison_transactions，真實多連線／等鎖／commit |
| RESCAN-18 | 無權 scan、viewer 寫入、偽造證據、跨 target FK、封存後改寫／追加／TRUNCATE → 拒絕 | API 與 schema／transactions；SEC-16 的比較部分 |

**人工 triage 與報告（TRIAGE、REPORT；T21，Gate D 的報告部分；`DECISIONS.md` §28）**：

| 編號 | 反例 | 測試 |
|---|---|---|
| TRIAGE-01 | 沒有證據、未 confirmed、一次改兩個欄位、回到 open、resolved 時改 triage → 拒絕；任何人工操作序列不送 resolve 都到不了 resolved（Hypothesis） | unit：findings/test_triage_domain；integration：triage_api |
| TRIAGE-02 | rescan_not_observed 只接受 not_observed（v1 不會產生，現行版本拒絕）；manual_retest 只接受平台證據都成立、只缺 rule／parameter 的 inconclusive；每個拒絕原因各一個反例 | unit：triage/test_evidence；integration：triage_api（構造的封存快照） |
| TRIAGE-03 | 人工複測聲明的每一項一致性檢查（route、Host 與 absolute-form 的 authority、參數名稱（query 的名稱；位置不明時另有 header 名稱與 body 的鍵名，不做子字串比對）、狀態列、身分、過時或未來的時間、結果、空白或過大的摘錄、client 自填平台欄位）；遮罩後才計算雜湊；`platform_checks` 只列實際執行的檢查；縮排的 header 與 target 的自訂 header 名稱也遮罩；`observation_ids` 只接受這個 finding 的觀察 | unit：triage/test_attestation；integration：triage_api；live 的反例斷言拒絕原因只來自平台條件 |
| TRIAGE-04 | 比較之後的新觀察、target 有進行中的 scan → 拒絕；比較快照在人工 resolve 之後不變 | integration：triage_api、test_triage_races |
| TRIAGE-05 | 自動重開（R1–R4）：較新的 scan 再現才重開，failed／timed_out 的 run 也算；沒觀察到不重開也不關閉；mapping 不同不重開但標示需要人工確認；重試不重複；重開之後可再 resolve | integration：finding_linker_reopen |
| TRIAGE-06 | DB 層繞過：未升版、跳版、升版沒有事件、事件鏈不符、事件被修改或刪除、摘錄缺少、系統事件引用其他 target、resolved 不是 confirmed、watermark 由 trigger 寫入、新 finding 版本不是 0、有資料時 downgrade。T23a 起摘錄是密文：DB 只允許換版（密文換密文）與到期之後只能一次的清除，不能刪除；明文雜湊改由 API 在加密之前與解密之後核對（§4.3 的 CONT、RET 表） | integration：triage_schema、sealed_content_schema |
| TRIAGE-07 | 併發（G1）：同版本兩個 PATCH、人工與自動重開互搶、resolve 期間建立的 scan、比較快照與 linker 的鎖；故障注入（G2）：每一步之間拋錯整筆回滾、重試只重開一次 | integration：triage_races、triage_transactions（各連續 5 次） |
| REPORT-01 | 不可信字串只在 code token 中、沒有連結／圖片／HTML／URL 樣式；JSON 跳脫；canary 不出現；白名單欄位與 golden JSON Schema | unit：reports/test_encoding、test_document；contract：test_report_schema |
| REPORT-02 | 截斷以整個 finding 為單位、摘要計數不變、開頭與結尾都有說明；真實的 8 MiB 與多位元組字元；大小分布偏斜時截斷點等於逐一嘗試的結果、每個 finding 只投影與渲染一次（成本與分布無關）；比較快照只列最新的 10 份並揭露省略數；先遮罩再截斷 | unit：reports/test_document、test_render |
| REPORT-03 | 用語：平台文字的誇大字詞只在否定說明中；需要人工確認的 resolved 不算 resolved | unit：reports/test_document；live 的報告核對；integration：reports_api（completed 與 timed_out 直接套用 live 的報告核對） |
| REPORT-04 | 佇列：SKIP LOCKED、舊 worker 重新認領之後不能完成、最多 3 次、內容寫入後失敗整筆回滾、快照與 PATCH 隔離、同時建立的配額；報告專屬的 DB 錯誤立即釋放、其他 DB 錯誤讓 worker 結束、lease 失效留給對帳；failed 不計入每個 scan 的配額；WorkerLoop 每圈一份 | integration：report_queue、report_worker；reports_schema（狀態轉換、內容只寫一次、雙向核對；T23a 起內容是密文，DB 只核對內容存在、只允許換版與到期之後的清除，明文的 sha256 改由 API 下載時核對，§4.3 的 CONT、RET 表） |
| REPORT-05 | 下載：只以 report id、sha 不符不送出內容、header（nosniff、CSP sandbox 與 frame-ancestors、no-store、ASCII 檔名）、其他 project 404、viewer 不能建立 | integration：reports_api |

正例保留：兩側有觀察且版本可靠 → persistent；純函式所有層證據完整時可得到 new/not_observed，移除必要證據就不再成立。這些人工構造的正例不是工具完成證據。實際 producer 的負面分類不放寬；端點請求與工具退出碼均不能代替完整性。

**引擎子預算（BUDGET；T31，`DECISIONS.md` §29.1、§29.2）**：

| 編號 | 檢查 | 測試 |
|---|---|---|
| BUDGET-01 | 沒有 `engine_budgets` 時配額和之前相同（剩下的全部），下一個引擎拿到前一個剩下的 | integration：engine_budgets（另有既有的 queue_launch 測試不變） |
| BUDGET-02 | 有指定時每個 run 的配額取較小值（請求數與秒數各自取）；Hypothesis：不超過剩下的與上限 | unit：scans/test_allocation；integration：engine_budgets |
| BUDGET-03 | ZAP 沒用完的份額不轉給 Nuclei；總額仍然限制有上限的 run（清理的秒數讓 Nuclei 少拿）；總額用完時開始之前就 `BUDGET_EXHAUSTED` | integration：engine_budgets |
| BUDGET-04 | 建立時的檢查：單引擎、缺少、重複、多列、合計超過、超過總額、低於最小時間窗、0、負數、bool、字串、未知欄位、空清單 → 422，不寫入 | unit：scans/test_allocation；integration：engine_budgets（API） |
| BUDGET-05 | 沒有子預算時 fingerprint 和 T31 之前逐位元組相同（golden hex）；順序不影響；同 key 不同子預算 → 409 | unit：scans/test_request；integration：engine_budgets |
| BUDGET-06 | DB：上限不能修改或事後加上（trigger）；上限同時有無、正整數、只屬於掃描引擎（允許清單）；有上限時只寫請求數（舊 runner）被擋下、超過上限被擋下；新增 run 時不能預填配額、配額只寫一次；沒有上限的舊資料列經 repository 讀回不違反 domain 的規則 | integration：engine_budget_schema |
| BUDGET-07 | API 列出每個 run 的上限、分到的配額與 guard 計數；沒有容器時是 null；audit 只在有指定時記下 | unit：scans/test_scan_out；integration：engine_budgets |
| BUDGET-08 | migration v0020 升降級、model 與 migration 沒有漂移、CHECK 數量；還有未結束、帶上限的 run 時 downgrade 拒絕，結束之後 downgrade 成功且 trigger 函式都移除 | integration：migrations、schema_constraints |
| BUDGET-09 | `scans` 的最小時間窗常數和 `scanners` 的 plan 相同，並以 ZAP 的 `plan_seconds` 驗證邊界；harness 的常數和平台相同 | unit：scans/test_allocation、bench/test_spec |
| BUDGET-10 | guard policy 的 `max_requests` 與容器的時間上限都等於分到的配額 | integration：engine_budgets |

**benchmark harness 與評估（BENCH；T31，`DECISIONS.md` §29.3、§29.4）**：

| 編號 | 檢查 | 測試 |
|---|---|---|
| BENCH-01 | 實驗規格的嚴格檢查：未知欄位、靶場只能三種（不接受 URL）、總預算不超過平台 grant、引擎依平台的執行順序、子預算依平台規則、experiment 的份額凍結且合計等於總額、重複次數、quota、最壞情況的總時間在 grant 的有效期內；YAML 的重複鍵、別名、多份文件、過大、`!!set` 等其他型別 | unit：bench/test_spec |
| BENCH-02 | 排程由種子決定；任何種子都是同一組 scan 的排列；比較區塊整塊移動、baseline 在前 | unit：bench/test_schedule（Hypothesis） |
| BENCH-03 | 結果目錄獨占建立、0700／0600、不覆寫；秘密檢查（key 格式、Bearer、JWT、session 的原值；T23a 加上 Fernet 金鑰的形狀與 bench 金鑰本身）不回顯值；SHA256SUMS 偵測修改、多出與缺少（T23a 起列的是加密檔）；manifest 欄位齊全（T23a 起是版本 2，每個檔案有明文與密文的 sha256）、不完整的 session 不評估 | unit：bench/test_results、test_manifest、test_cli |
| BENCH-04 | API 的 JSON → 紀錄：缺欄位、型別不符、分頁不一致、未結束、fixture 一律失敗；樣本先通過平台真正的輸出 schema；經真的 API 收集有子預算的 scan 與比較快照 | unit：bench/test_collect；integration：bench_collection（TestClient 與 db-test） |
| BENCH-05 | 偵測指標：recall 以案例、precision 以議題；未裁定、分母 0、holdout、平台阻擋、不支援、auth role、修補版的 FP；歧義停止評估 | unit：bench/test_evaluate、test_ground_truth（含 Hypothesis 的性質） |
| BENCH-06 | 引擎歸屬：各引擎偵測、獨有、聯集；2 個以上引擎的 finding 另算 precision | unit：bench/test_evaluate |
| BENCH-07 | 資源與完成度：guard 計數的加總、不明就是不明、被請求數或時間截斷、牆鐘時間；覆蓋沒有量測是 N/A；不是工具或預算結果的錯誤碼（允許清單之外）與 interrupted、cancelled 讓整批作廢 | unit：bench/test_scoring、test_evaluate |
| BENCH-08 | 去重：跨引擎合併的 precision／recall（標記完整才算）、誤合併、漏合併、有 2 個以上觀察的 finding、列表壓縮比例 | unit：bench/test_scoring |
| BENCH-09 | 複掃：誤判已修補（仍存在卻 not_observed）；inconclusive 不算；修補版上仍 persistent 另列；holdout 等被排除的案例只計數（和偵測相同的排除規則） | unit：bench/test_rescan |
| BENCH-10 | 跨重複：中位數、範圍，IQR 在 n ≥ 4 時才算，N/A 另計；smoke 與未凍結的 ground truth 標明不是正式結果 | unit：bench/test_stats |
| BENCH-11 | `benchmarks/` 不 import `secscan`、`tests`、DB、Web 框架、Docker、網路與子程序；純函式的模組不碰檔案；`cryptography` 只有 `benchmarks/sealing.py` 可以 import（T23a） | unit：bench/test_black_box（AST） |
| BENCH-12 | `make bench` 的前置是 `ENABLE_LIVE_LAB_TESTS`、規格與名稱的檢查，recipe 只遞迴執行 `test-live-runner`；使用者給的值以環境變數交給 shell；`bench-check`、`bench-evaluate` 離線 | unit：bench/test_make_targets、test_cli |
| BENCH-13 | Live smoke：經 API 跑完 A、B、C 與一個比較區塊，manifest 與 guard 計數齊全，子預算在真實執行中有效 | live：test_bench_live（**需要使用者另外授權；尚未執行**） |

**原始證據與內容的加密（KEY、SEAL、EVID、CONT、RET、ROT、BSEAL；T23a，`DECISIONS.md` §30）**：

| 編號 | 反例 | 測試 |
|---|---|---|
| KEY-01 | 三組平台金鑰的格式、數量（1–4）、互不共用（以解碼後的 bytes 比對）；錯誤訊息指出是哪一組的第幾把、不含金鑰；api、worker、runner 缺自己的金鑰就停止；`check-encryption-keys` 只顯示數量 | unit：security/test_key_rings、test_cli_keys；api：test_app_factory；integration：runner_cli |
| KEY-02 | compose：worker 沒有 SECRET 與 EVIDENCE、api 沒有 EVIDENCE、runner 沒有 CONTENT；保留期限只傳給套用它的程序；沒有服務用 `env_file` | unit：test_deployment |
| KEY-03 | AST：`reveal` 仍只在 runner；`unseal` 只在報告下載與 triage；`unseal_stream`／`read_stream_header` 只在 `runner/evidence.py`；`CurrentContentCipher` 只到報告與 triage 的路由；`content_cipher(...)` 只由 api、worker、本機指令與 v0022 建立；`cryptography` 只在兩個加密模組（import-linter） | unit：test_blob_cipher_callers、test_secret_reveal_callers、test_cipher_dependency |
| KEY-04 | 金鑰、明文、密文不出現在 repr、錯誤訊息、log 與 API 回應（canary） | unit：security/test_blob_cipher、test_key_rings；integration：sealed_content、evidence_cli |
| KEY-05 | `make env`：在暫存目錄執行真的 recipe；冪等、只附加缺少的金鑰、任何一個是空值時在寫入之前停止、不改既有的值、終端不顯示金鑰、檔案 600；不碰真正的 `.env` | unit：test_make_env |
| SEAL-01 | 單一 token 與分塊兩種格式的往返（Hypothesis 的任意切塊）；context 或路徑不符；竄改、截斷、調換順序、重複、少了最後一塊、把一塊或整個檔案搬到別的檔案或 run、持有金鑰者偽造的標頭與塊都解不開；大小上限；超長路徑 | unit：security/test_blob_cipher |
| SEAL-02 | 換版：新金鑰在前時改用新金鑰、舊金鑰移除之後解不開的會報錯；錯誤不回顯內容 | unit：security/test_blob_cipher |
| EVID-01 | 每一種終止狀態（含沒有收集、取消、沒有 manifest 的殘留）都會加密；非終止狀態、容器還沒確認刪除的不加密；沒有目錄的記為 `none` | integration：evidence_keeper、evidence_schema |
| EVID-02 | 先驗證才刪除：暫存檔、fsync、rename、fchmod、驗證任何一步失敗都保留明文、不寫 `run_evidence`、引擎變成不可用（`EVIDENCE_SEALING_FAILED`），一輪成功之後恢復；API 如實顯示 pending | unit：runner/test_evidence_vault、test_keeper；integration：evidence_keeper |
| EVID-03 | 中斷恢復：`.sealing-*`、`.rotating-*`、`.masking-*` 的處理；rename 之後、刪除明文之前中斷時重做同一個檔案；長檔名、hardlink、symlink、特殊檔案、深度與條目數上限 | unit：runner/test_evidence_vault、test_fs |
| EVID-04 | 逾期：從第一次 `collected` 起算（注入時間落在兩次 `collected` 之間）；`collected` 或 lease 過期的 `normalizing` 超過期限 → `failed`／`PARSE_DEADLINE_EXCEEDED` 並加密、scan 狀態重算；鎖住之後重新確認條件；有效 lease 的解析不受影響；worker 舊 lease 的寫入被拒 | unit：scans/test_lifecycle；integration：evidence_keeper |
| EVID-05 | 加密之後整個目錄的位元組中沒有明文的 canary；孤兒目錄先加密才清除；probe 的目錄評估完就刪除 | unit：runner/test_evidence_vault；integration：evidence_keeper、runner_loop_probe |
| EVID-06 | keeper：每輪的時間與數量上限、停止、例外（變成不健康）、停擺判斷、換版中拿不到 lock 也算不健康；不阻擋主迴圈的心跳；`--once` 結束時不健康就 exit 1 | unit：runner/test_keeper；integration：runner_loop、runner_cli |
| EVID-07 | API 的 `engines[].evidence`、artifact 的 `encrypted`／`purged_at` 如實反映狀態；`export-evidence` 先驗證、寫 audit 才輸出，解密之後和 artifact 的 sha256 相符；解不開時不輸出任何內容 | integration：evidence_keeper、evidence_cli、finding_provenance_api |
| EVID-08 | 隔離（`DECISIONS.md` §30.12）：同一個目錄連續 3 次因為深度、條目數或路徑總長度超過上限而加密失敗才隔離，2 次不會；三種上限共用連續的計數、各有錯誤代碼；中間有其他種類的失敗就重新計數、成功就清除；其他種類的失敗、清除時的失敗、runs volume 的目錄數量超過上限都不會隔離；孤兒目錄也會隔離；寫入隔離紀錄失敗時維持不健康、之後重試；隔離後下一輪恢復健康、其他 run 照常加密，之後每一輪（含重啟的 keeper）都跳過這個目錄；明文保留原狀（canary 還在）；API 顯示 `manual_intervention_required`、`hold` 與 `encrypted: false`；audit `evidence.hold`；log 不含路徑；退避的次方有上限；隔離已 commit、回應卻遺失時，下一輪依 DB 清掉退避、恢復健康；路徑總長度第一次超過就停止走訪 | unit：runner/test_backoff、test_keeper_holds、test_fs、test_evidence_vault、scans/test_evidence_hold；integration：evidence_holds |
| EVID-09 | DB 與人工復原：trigger 只允許已終止、容器已刪除、沒有 `run_evidence` 的 run，或沒有 run 紀錄的孤兒目錄被隔離；新的隔離不能已解除；`resolved_at` 只能寫一次，run 必須已有 sealed（不是 none）的紀錄，同時改其他欄位被拒；`held_at`、`resolved_at` 由 DB 決定；隔離中的 run 新增 none 或 sealed 的 `run_evidence` 在 commit 時被拒，兩邊以交易鎖串行化（`lock_timeout` 確認會等）；外鍵的 scan 必須相符；其他修改、DELETE、TRUNCATE 被拒；5 個 CHECK，錯誤代碼的清單和 domain 一致；有紀錄時拒絕 downgrade。第二次解除得到 `HoldNotActiveError`。`retry-evidence`：沒有隔離時 exit 1、沒有任何改變；audit 寫不進去就不開始；等不到鎖時不動檔案；仍然超過上限時保留隔離與明文、寫 audit；指定較高的上限之後 `run_evidence` 是 sealed、隔離已解除、audit 完整，之後照常到期清除；孤兒目錄；目錄不存在時不記成 none；加密之後 DB 寫入失敗時寫入結果的 audit（`EVIDENCE_SEALED_NOT_RECORDED`），再執行一次就完成；參數的範圍（含 `--max-path-chars` 的絕對上限）與理由的檢查（含無法以 UTF-8 表示的字元）；路徑總長度超過預設上限時，以較高的上限重試才成功。API 的顯示以還沒解除的隔離優先。retention-status 的數量、錯誤代碼與目錄名稱（不含路徑）。`sealed/` 超過條目上限的目錄可以清除，其中有子目錄時 fail closed | integration：evidence_holds、evidence_retry、migrations、schema_constraints；unit：runner/test_evidence_vault |
| EVID-10 | 掛載範圍（`DECISIONS.md` §30.13）：只有 runner 與 `runs-init` 掛載 runs volume 的根目錄；worker 只以 subpath `active` 唯讀掛載；api、guard 不掛載；`runs-init` 是獨立、最小的服務（不使用 `x-app`，沒有 environment、env_file、secrets、網路與多餘的掛載，唯讀 rootfs、`restart: "no"`、`cap_drop: ALL`），以合併之後的設定逐項比對；runner 與 worker 依賴它成功結束；`make up`、`make down` 與搬移指令共用 `APP_COMPOSE`，只有搬移指令使用 `--no-deps`；`volumes.runs.name` 與 `RUNNER_RUNS_VOLUME` 是同一個運算式；掃描容器的 subpath 是 `active/<run>/in`、`out`（舊的 layout 與 `held/` 都被拒絕）；`ArtifactReader` 在成功與錯誤路徑都關閉 FD；worker 看得到 `held/` 或 `.layout`（掛到根目錄）時不啟動；程式不使用 `os.link`；只有 runner 的模組與 runner 容器內的指令提到 `held`。compose 的秘密只出現在需要它的服務自己的 environment，頂層的 `x-*` 不引用任何秘密（延伸 KEY-02）：以真的 `docker compose`、暫存的 project directory 與虛構的秘密確認，`config runs-init --format json` 的輸出不含秘密，每個服務只拿到自己的秘密，api、runner、worker 的 DB 連線設定不變（Docker 驗證 F1） | unit：test_deployment_runs、test_deployment、test_compose_secrets、runner/test_container_spec、worker/test_artifacts、runner/test_held_writers |
| EVID-11 | 隔離的一致性：keeper 第 3 次上限失敗時以 inode 新增紀錄，同一輪搬到 `held/` 並記下隔離完成；有有效的解析 lease 時不搬；對帳表的每一列（隔離中的四種位置、已隔離與解除中的正常、待完成、違反 I1／I2 與衝突、遺失、未知的 `held/` 目錄）；對帳不因同名的條目就補寫（symlink、inode 不符），補寫之前先確認身分再 fsync；搬移的四種失敗寫進 DB、只讓這個目錄退避、keeper 維持健康；15 分鐘後 CRITICAL 與 audit（每個目錄一次，直接查 DB）；隔離中的紀錄先處理，超過一頁的已隔離紀錄不會擋住它們；重新隔離的 audit 寫入失敗時下一輪補寫；`seal`、`purge`、匯出碰到 `held/` 的目錄時 fail closed；layout 不正確時 `check()` 失敗；trigger 的五種轉換與拒絕的情況、時間由 DB 寫入、9 個 CHECK（關閉 trigger 也擋得下）、v0024 的升降級（已搬移 layout 時拒絕降級、降級之後的函式和 0023 相同）；每個中斷點之後檢查 I1–I3 | unit：runner/test_isolation、test_hold_moves、test_keeper_holds、test_evidence_vault、test_layout；integration：evidence_hold_isolation、evidence_holds、migrations、schema_constraints |
| EVID-12 | 復原與搬移指令：`retry-evidence` 隔離中與位置不符時不做任何改變；在 `held/` 加密並逐一驗證之後才寫 `releasing_at`、搬回、在 `active/` 再驗證（不通過就搬回 `held/`）；每個中斷點（寫 `releasing_at` 之前、搬回之前、搬回之後寫 `resolved_at` 之前、`active/` 驗證失敗）再執行一次就完成；`sealed/` 中有加密檔以外的條目就不搬回；`rotate-evidence-keys` 也處理 `held/`，兩個區域都列出之後才換版；`migrate-runs-layout`：dry-run 不做任何改變、搬移、重跑、中斷之後完成、衝突時不完成、symlink 不跟隨、其他條目不動、UUID 名稱、但不是目錄的條目在計畫階段就阻擋、身分不符的隔離不寫入而其他照常、lease、未確認刪除的容器（附脫困方式）與鎖的前提、容器內的 volume 名稱與掛載；`init-runs-layout` 不需要 DB 與金鑰、每個條件；make target 以假的 `docker` 實際執行：非預設的名稱、project name 改變、預設與實際的 volume 同時存在、標籤不符、解析失敗不退回預設、已停止的容器、`docker ps` 失敗；retention-status 的「隔離未完成」段落與緊急標示，不含路徑 | integration：evidence_retry、runs_layout、runner_cli；unit：test_runs_layout_make、test_runs_volume、runner/test_layout |
| CONT-01 | DB 中報告與摘錄的位元組沒有明文的 canary；下載與 triage-events 解密正確；把別的報告或摘錄的密文搬過來時回 500、不送出內容 | integration：sealed_content、reports_api |
| CONT-02 | v0022：降到 0021 塞入舊格式的列再升級 → 舊明文被加密、期限是升級時間加 30 天；有舊資料而缺金鑰、舊內容和 sha256 不符時停止且資料不變；沒有舊資料時不需要金鑰；`--sql` 模式拒絕舊資料；有密文時拒絕 downgrade | integration：content_migration、migrations |
| RET-01 | 只清除到期的：run 目錄（7 天）、報告內容（410、配額不計、重送照舊）、摘錄（tombstone、事件不變）；時間可注入 | integration：evidence_keeper、sealed_content |
| RET-02 | trigger：`run_evidence` 只能 sealed → purged 一次；報告內容只允許換版與到期之後的清除；摘錄只允許換版與只能一次的清除；其他 UPDATE、DELETE、TRUNCATE 被拒 | integration：evidence_schema、sealed_content_schema、reports_schema、triage_schema |
| ROT-01 | 證據與內容的換版：全部換成新金鑰、沒有舊金鑰時保留原狀並列出、和 keeper 互斥（拿不到 lock 時不改任何檔案）、已清除的略過、audit 只記數量 | integration：evidence_cli、rotate_content_keys_cli |
| BSEAL-01 | 結果加密：磁碟上沒有明文與明文暫存，結果目錄的位元組中沒有明文的 canary；`SHA256SUMS` 與 manifest v2 的雙重 sha256；金鑰檔的權限、擁有者、symlink 與位置（repo 之外）的檢查；`create-key` 不覆寫 | unit：bench/test_sealing、test_results、test_manifest |
| BSEAL-02 | 讀取與 `bench-evaluate`：金鑰錯誤、遺失、截斷、竄改、改名或搬到別的結果目錄都清楚報錯、沒有部分輸出；拒絕有明文檔案的目錄 | unit：bench/test_sealing、test_results、test_cli |
| BSEAL-03 | `bench-seal`：先核對原目錄的 `SHA256SUMS`、只寫 partial 目錄（O_EXCL），驗證之後才 rename；不碰原目錄；驗證失敗時刪掉 partial、中斷時留下 | unit：bench/test_sealing、test_cli、test_make_targets |

審查之後新增的反例（`DECISIONS.md` §30.11）：
- EVID-02、EVID-06：runs volume 不存在或不能寫時不記下任何 none 或 purged（5 種 vault 操作、keeper 的一輪、整合測試）；孤兒目錄的加密檔解不開、任何非預期的例外都不讓 keeper 的執行緒結束；正常停止保留最後一輪的結果；失敗的 run 與孤兒退避、不擋住其他 run，退避中仍不健康；退避的間隔倍增而且有上限。
- EVID-03、EVID-05：掃描容器改成 000 的目錄與檔案照常加密；刪除明文之前先 fsync `sealed/`；`entries()` 超過上限就失敗（換版不截斷、不改任何檔案）。
- EVID-04：worker 持有 run 的列鎖時，逾期處理不等鎖、不算失敗；沒有 collected 事件的 run 以建立的時間起算。
- EVID-07：列表寫 audit `evidence.list`、以 ASCII 跳脫工具決定的檔名；還沒加密的目錄回明確的錯誤。
- CONT-01、RET-01：清除在 API 讀完 metadata 之後才 commit 時回 410；金鑰不對與 sha256 不符分開記錄；一次清除處理多批；清除時的 DB 錯誤不讓 worker 結束。
- RET-02：只寫 `content_purged_at`、沒有刪除內容的 transaction 在 commit 時被拒（`reports_purge_complete`）；報告、摘錄與 `run_evidence` 的清除時間不能晚於現在；v0021 有 sealed 或 purged 的紀錄時拒絕 downgrade；v0022 的密文上限常數和 domain 一致。
- KEY-01：EVIDENCE 與 CONTENT 共用金鑰時，每個 admin 指令與 `make migrate` 都停止（格式錯誤留給各指令說明）。
- BSEAL-01：bench 金鑰檔以 O_NOFOLLOW 開檔、對 fd 檢查（檢查之後換成 symlink 也讀不到別的檔案）；上層目錄別人可以寫入、是 symlink 或不存在時拒絕；放在結果目錄中時拒絕。

空轉檢查（故意改壞之後必須有測試失敗，確認之後改回、不提交）：拿掉「先驗證才刪除」、容器確認刪除之前就加密、到期之前就清除、拿掉最後一塊的檢查、逾期改從最後一次 `collected` 起算、加密失敗時引擎仍然可用——六項都被抓到。Live 的證據斷言（`tests/live/evidence_assertions.py`：run 目錄只剩密文、沒有 canary、export 的 sha256 等於 artifact）已更新，2026-11-12 在 `make test-live-fixture-findings` 與 `make test-live-fixture-rescan` 中執行通過。export 的 sha256 比對只在 findings 中執行（`DECISIONS.md` §30.13 的「Live 驗收」）。

T23b-b1 的 DDL／DML 分權（`DECISIONS.md` §31；預期矩陣在 `tests/db_privileges.py`）：

| 編號 | 內容 | 位置 |
|---|---|---|
| ROLE-01 | <ul><li>catalog 和預期矩陣完全相同：每張表的八種權限、沒有 GRANT OPTION 與欄位授權、PUBLIC 沒有任何表與 sequence 的權限；</li><li>資料庫只有 CONNECT，schema 只有 USAGE，sequence 沒有權限；</li><li>函式都是 trigger 函式、SECURITY INVOKER、固定 `search_path`，ACL 只有 owner；</li><li>`pg_default_acl` 只有 owner 的全域函式條目。之後新建的 SQL 函式與 trigger 函式，ACL 也只有 owner：應用程式角色與只有 CONNECT 的角色呼叫都是 42501；</li><li>有未分類的表就失敗。</li></ul> | integration：db_privileges |
| ROLE-02 | <ul><li>所有資料庫中應用程式角色的擁有權是 0；</li><li>資料庫與每個物件由 owner 擁有，`public` 由 `pg_database_owner` 擁有；</li><li>兩個角色的屬性；沒有成員關係，也不經繼承成為 owner 或任何預先定義角色；</li><li>角色與資料庫層級的設定只有 `timezone`；</li><li>應用程式角色所有的授權依賴（`pg_shdepend` 的 a），只有目標資料庫、`public` 與矩陣中的表；</li><li>不能以 `GRANT ON PARAMETER` 設定 `session_replication_role`、`lo_compat_privileges`。</li></ul> | integration：db_privileges |
| ROLE-03 | <ul><li>以應用程式角色執行，都是 42501，共約 120 個語句：<ul><li>DDL；</li><li>停用、修改、刪除與新增 trigger；</li><li>改寫函式、刪除約束；</li><li>建立 table、temp table、schema、function、view、rule、policy、index，以及啟用 RLS；</li><li>COMMENT、OWNER TO、REASSIGN OWNED；</li><li>ALTER DATABASE、ALTER SCHEMA；</li><li>SET ROLE、SET SESSION AUTHORIZATION；</li><li>三種方式設定 `session_replication_role`；</li><li>ALTER SYSTEM、CREATE EXTENSION；</li><li>COPY PROGRAM、`pg_read_file`、`lo_import`、REINDEX；</li><li>以 DO 執行 DDL；</li><li>每張表的 TRUNCATE，只能新增的表的 UPDATE、DELETE，其他表的 DELETE；</li><li>projects 與 audit_events 的列鎖；</li><li>`run_rule_locations` 的 SELECT、`alembic_version` 的寫入。</li></ul></li><li>`GRANT … TO PUBLIC` 只有警告、ACL 不變。</li><li>之後 trigger、函式定義、CHECK 與擁有者都不變。</li><li>應用程式角色能改自己的參數，造成服務中斷（剩餘風險 2）。`DROP OWNED BY` 自己撤銷不了 owner 授予的權限。</li></ul> | integration：db_privileges |
| ROLE-04 | <ul><li>沒有 EXECUTE 時 trigger 照常觸發：23000，不是 42501；</li><li>identity 取號不需要 sequence 的權限；</li><li>執行期的每一種列鎖、advisory lock；</li><li>readiness 是 READY。</li></ul>**報告鎖**（L1 至 L8）：<ul><li>L1 同一個 idempotency key 等鎖之後取得第一份報告；</li><li>L2 不同的 project 不阻塞；</li><li>L3 雜湊碰撞只排隊；</li><li>L4 commit 與 rollback 都釋放；</li><li>L5 等鎖逾時是可重試的 55P03；</li><li>L6 和 keeper、v0023 的鍵空間不同；</li><li>L7 既有的並行測試照常通過；</li><li>L8 projects 的列鎖是 42501。</li></ul>**加上** api、worker、runner 與 CLI 的整合測試都以應用程式角色執行。 | integration：db_privileges、report_lock、report_queue |
| ROLE-05 | **下列情況都停止，資料不變**：<ul><li>沒有 `DB_OWNER_PASSWORD`；</li><li>owner 與應用程式角色相同；</li><li>以 superuser、應用程式角色或不擁有資料庫的角色執行；</li><li>應用程式角色擁有物件；</li><li>角色或資料庫層級的設定；</li><li>default privileges；</li><li>成員關係與高風險屬性；</li><li>找不到應用程式角色；</li><li>v0025 沒有應用程式角色的名稱、或有未分類的表；</li><li>owner 有高風險屬性或成員關係；</li><li>PUBLIC 有 TEMPORARY 或 `public` 的 CREATE；</li><li>非預期的 default privileges；</li><li>parameter ACL（應用程式角色或 PUBLIC）；</li><li>`ALTER ROLE ALL`。</li></ul>**其他**：<ul><li>連不上 owner 時不轉印驅動程式的訊息；</li><li>offline 的 SQL，含 `-x app_role`；</li><li>head → 0024：default ACL 那一列消失、PUBLIC EXECUTE 還原；再升到 head 時，權限與 ACL 和第一次完全相同。</li></ul> | integration：migration_roles、migrations；unit：db_roles_cli |
| ROLE-06 | `migrate-db-roles`：<ul><li>**dry-run**：列出的物件等於實際的物件，沒有任何改變；</li><li>**移轉**：<ul><li>應用程式角色不擁有物件，owner 擁有原本兩者的聯集；</li><li>第三個角色的資料庫與物件、`postgres` 中的物件不變；</li><li>之後 migrate 到 head，權限符合矩陣、readiness 是 READY；</li></ul></li><li>**拒絕、而且沒有任何改變**：參數化的 20 種情境，加上兩個獨立的測試：<ul><li>第二個資料庫；</li><li>其他資料庫中的物件或授權；</li><li>schema、large object、一般函式、view；</li><li>第三個角色的物件、superuser 的物件；</li><li>default privileges、成員關係、角色或資料庫層級的設定；</li><li>owner 已存在，但屬性、成員關係、密碼或其他資料庫不符；</li><li>parameter ACL（應用程式角色或 PUBLIC）、`ALTER ROLE ALL`；</li><li>獨立的測試：開著的連線、不同的 cluster；</li></ul></li><li>**錯誤的路徑**：<ul><li>分類之後才新增的物件；</li><li>建立 owner 失敗：訊息不含密碼；</li><li>DB 錯誤、事後檢查不符：都 rollback；</li><li>等鎖逾時：可重試；</li><li>commit 失敗：結果不確定；</li><li>superuser 的密碼錯誤；</li><li>owner 登入失敗。</li></ul></li><li>**owner 的密碼**：以本機產生的 SCRAM verifier 建立；沒有 migration 的資料庫不寫 audit；</li><li>**中斷**：完全 rollback，再執行一次就完成；</li><li>**重跑**：S1、S2 不寫入任何東西；</li><li>**密碼**：輸出與日誌都不含密碼（canary）；</li><li>**unit**：以合成的 `pg_shdepend` 資料測分類器；SCRAM 的核對；非 loopback 與缺少的密碼。</li></ul> | integration：db_roles_cli；unit：db_roles_scope、db_roles_cli |
| ROLE-07 | <ul><li>`DB_OWNER_PASSWORD` 只在 `db` 的 environment，api、runner、worker 沒有任何 `DB_OWNER_*`；</li><li>initdb 和 `MigrationCredentials` 是同一組變數；</li><li>`make env` 補上它，而且冪等。</li></ul> | unit：compose_secrets、make_env |
| ROLE-08 | 分權之後的 T23a：<ul><li>應用程式角色不能停用 `evidence_holds_guard`、`run_evidence_hold_check`、`run_evidence_guard`；</li><li>不能刪除 9 個 CHECK、不能以 `session_replication_role` 繞過；</li><li>不能 DELETE 或 TRUNCATE `evidence_holds`、`run_evidence`。</li></ul>EVID 與隔離的既有測試以應用程式角色執行；「關閉 trigger 也擋得下」的 CHECK 測試由 owner 執行。 | integration：db_privileges、evidence_hold_isolation、evidence_holds |

### 4.4 Live E2E

完整 API → scope → auth → queue → Runner → 工具 → Parser → Finding → report。工具只在隔離靶場跑。每個 Adapter 的 live success 與其 unit test 成功分開標示。

T23b-b1 的 live 驗收（`make test-live-db-roles`，`tests/live/test_db_roles_live.py`；**尚未執行**，G3 需要另外授權）：
- 全新的 volume 由 initdb 建立兩個非 superuser 的角色，資料庫由 owner 擁有；
- migration 以 owner 執行：每個物件的擁有者是 owner、版本是 head、權限等於預期矩陣、只有 owner 的全域函式 default ACL；
- api、runner、worker 的連線都是應用程式角色；
- 應用程式角色的 DDL、停用 trigger、TRUNCATE、`session_replication_role` 被拒；
- 三個服務的環境變數名稱中沒有 owner 的帳密：只在容器內列出名稱，值不離開容器。

G3 另外重跑 `test-live-runner`、`test-live-fixture-findings`、`test-live-fixture-rescan`，確認分權之後的端到端流程。

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

T14 已涵蓋（`make test-live-zap`，`tests/live/test_zap_live.py`；live 自己 lab 網路上的小型網站 `zap_site.py` 與 canary；T14 時 API 以只給 live 的預覽開關啟動，T15 移除；量測的數字在 `TOOLS.md` §7.5）：
- capability probe：runner 啟動時以真的 ZAP 映像、掃描相同的強化設定執行；`GET /scanners` 顯示 2.17.0；probe 容器已刪除。
- web、anonymous（SEC-02、SEC-05）：
  - 網站只收到 GET 與 HEAD，沒有 `/admin`，沒有任何認證 header；canary 沒有連線，guard 只看到 target。
  - 修正前 ZAP 送出的 52 個 POST（grant 不允許）都被 guard 擋下；會改 method 的規則依 grant 篩選之後是 0。
  - 報告與 `zap.log` 收集到 out/，manifest 記下退出碼。
  - 2 MiB 的回應取得成功。
- api、bearer（SEC-02、SEC-05、SEC-11、SEC-14、SEC-15）：
  - ZAP 只送出規格中 eligible 的 operation，DELETE 一次也沒有。
  - 規格中指向 canary 的 URL（contact、license、externalDocs、servers、schema 的 `id`、example）連線數是 0。
  - `Authorization` 只送到 target，值正確。
  - token 與 proxy 的 token 不在 Env、Cmd、Labels 與 out/。
  - path 參數的百分比編碼攻擊被 guard 以 `PATH_AMBIGUOUS` 拒絕（覆蓋的缺口，見 `TOOLS.md` §7.5）。
- `api_key_header`、cookie：值正確、只送到 target；請求數較少的預算讓 ZAP 在 maxDuration 內自己結束。
- 取消（SEC-19）：policy 先變成 blocked，容器才收到 kill；之後網站沒有再收到請求；ZAP 收到 SIGTERM 之後約 2 秒結束。
- 參照炸彈（3^8）：在容器的上限內完成，沒有連到其他 host。
- 尚未涵蓋：
  - Juice Shop 與 VAmPI（T16）。
  - 和 ZAP 自己的 session cookie 合併的情況（網站不發 `Set-Cookie`）。
  - HTTPS。
  - T11 的同一條連線上多個請求的證據缺口。

T13 已涵蓋（`tests/live/test_revocation_live.py`、`test_guard_failover_live.py`；live 的 lab 網路上自己的接收端）：
- SEC-01（執行中）：fake 容器執行中，以借用的 proxy-url 每 20 ms 送一次請求；管理員撤銷 grant 之後 10 秒內開始拒絕（`RUN_BLOCKED`，之後 policy 刪除是 407），放行與拒絕沒有交錯；之後接收端沒有再收到；容器在 30 秒內刪除；fake 的 run 是 `failed`（`SCOPE_REVOKED`）。
- 先後的證據（取消、撤銷、對帳）：唯讀掛載 policy volume 的觀察者每 1 ms 讀一次 policy，記下它變成 blocked 的時間；docker events 以即時串流記下容器的 kill／die（兩者都是 VM 的時鐘）。三條路徑都是 policy 先變成 blocked，容器才收到 kill。T13 才改用這個方法：T12 加上速率限制之後，探針的請求在 guard 中等待、醒來才判斷與記錄，guard 的 `RUN_BLOCKED` log 會落在 kill 之後約 0.1 秒（T13 的第一次 live 執行因此失敗了三個測試，產品的順序沒有錯：integration 的 spy 也確認先寫 blocked 再 stop）。`docker events --since` 的重播會被其他容器的事件擠掉，也改成在建立 scan 之前開始串流。
- runner 中斷（SEC-19、DoD 1、DoD 2）：runner 被 SIGKILL，guard 在 lease 內開始回 `POLICY_STALE`；重啟之後 run 與 scan 是 `interrupted`（`LEASE_EXPIRED`）、容器被刪除、這個容器只有一個 `create`、重啟之後有 `destroy`、policy 檔已刪除、`budget_usage` 的請求數是 null、接收端的計數不再增加；同一個 target 再建立的 scan 完成。
- lease 過期而容器仍在執行（DoD 3）：SIGKILL runner 之後以 db 容器內的 psql 把 lease 設成過期（容器自己的環境變數，密碼不經過測試），重啟 runner：policy 先變成 blocked、容器才收到 kill；之後接收端沒有再收到；run 是 `interrupted`，這個 run 只建立過一個容器。

T12 已涵蓋（`tests/live/test_budget_live.py`、`test_runner_live.py`；live 的 lab 網路上自己的接收端）：
- SEC-13：上限 3、送 5 個允許的請求：前 3 個到達 target，之後是 `BUDGET_EXHAUSTED`、接收端沒有收到；summary 記下轉送 3、用盡、拒絕 2；三個轉送的請求相隔至少 0.5 秒（2 req/s）；jsonl 有 3 個請求與 3 個回應，沒有 Authorization 的值。
- SEC-15：帶著 `Authorization` 的請求只到達 target 的 origin；另一個 origin 的接收端沒有任何連線。
- preflight 的端到端：綁定 auth profile 的 scan 經 API、runner、busybox 容器、guard 送出帶認證與匿名的 `GET /me`，target 收到兩個請求（只有第一個帶 `Authorization`、Host 是 canonical、沒有 `Proxy-*`、來源是 guard），結果 `passed`，`budget_usage` 是 2，coverage 有量測依據；canary secret 不在接收端的紀錄中。實作時以這個測試發現 busybox nc 半關閉連線的問題（`DECISIONS.md` §16 的依據）。

T10 已涵蓋（`make test-live-runner`，`tests/live/`；獨立的 compose 專案、自己的 DB，跑完一律拆除；fake 引擎，不連 lab）：api、runner、worker 沒有 docker.sock、不是 privileged；socket-proxy 唯讀掛 socket、只接 docker_net；runner 容器內呼叫不該開放的 API 都是 403／405、沒有產生容器；api、worker 連不到 socket-proxy；`GET /scanners` 顯示 fake 可用；fake scan 的容器非 root、唯讀、無 capability、IPC 與 cgroup namespace 是 private、只有三個 volume subpath（只看得到自己的 in/、out/ 與 secret）、secret 0400、解析不到 proxy／db／api／runner、沒有預設路由，完成後容器與 secret 都刪除；取消後 30 秒內刪除容器；secrets volume 是 tmpfs；canary secret 不在任何容器的 log 與設定中。

T15 已涵蓋（`make test-live-zap`；數字在 `TOOLS.md` §7.6）：
- 完整的閉環：API → 真的 ZAP → worker → `GET /scans/{id}/observations`；每個觀察都是網站真的收到的請求；manifest 的 hash 等於 runs volume 中遮罩之後的檔案。
- 遮罩（SEC-14）：bearer、`api_key_header`、cookie 三種認證，靶機把 secret 寫進回應、ZAP 帶進報告，out/ 與 API 都看不到原文，看得到佔位。
- 語意：maxDuration 是 `timed_out`、觀察保留；零告警是 `succeeded`；目標沒有回應是 `NO_TARGET_TRAFFIC`，ZAP 對 mitmproxy 錯誤頁的告警不入庫。
- 尚未涵蓋：active scan 真的命中的告警（小型網站沒有弱點）、guard 的 403 被告警的情況，都在 T16 以 Juice Shop、VAmPI 量測。

T16 已涵蓋（`make test-live-lab`，`tests/live/test_lab_zap_live.py`；Juice Shop v20.3.0 與 VAmPI 由測試在 live 自己的 lab 網路上逐一啟動；數字在 `TOOLS.md` §7.7 與 `DECISIONS.md` §20.6）：
- 每個 run：`plan_hash` 與和 `/scan-profiles` 相同的 profile 定義、`result.guard_traffic`；guard 只看到 target 的 host 與 port；每個觀察的 (method, path) 都是 guard 為這個 run 轉送過的請求；報告在 8 MiB 以內。
- 正例：Juice Shop 的 REST 搜尋（操作者上傳的規格）命中 SQL Injection（`q`）。VAmPI 的 SQLi 的探測被 guard 以 `PATH_AMBIGUOUS` 拒絕（平台的漏報，以斷言固定證據）。負例：VAmPI 安全版沒有 active scan 規則的告警。
- token 失效：90 秒的 VAmPI token → `guard_traffic.auth.lost`、coverage 的 `AUTHENTICATION_LOST`、`authenticated_operations` 是 null。preflight 不被 200 騙過（Juice Shop 的 whoami，第一輪的量測）。
- 工具超時：plan 的 maxDuration → `timed_out`（`ENGINE_TIMEOUT`）、觀察入庫。取消：`cancelled`、沒有殘留的容器、之後 guard 不再為它轉送。

T16 的小型案例表（ground truth 的初稿；完整的 12＋12、6＋6 在 T30。來源 `SOURCES.md` S103、S104；「平台結果」是第二輪的 live 量測）：

| case_id | target | method／path | auth role | 類別 | 預期 | ZAP 能否偵測 | 平台結果 | 確認方式 |
|---|---|---|---|---|---|---|---|---|
| T16-JS-01 | Juice Shop | GET `/rest/products/search?q=` | anonymous | security：SQLi（Database Schema） | 正例 | 主動（40018） | **命中**（High、信心 Low） | `q=apple'` 回 500（SQLite 的語法錯誤） |
| T16-JS-02 | Juice Shop | GET `/` 等頁面 | anonymous | security：缺 CSP | 正例（設定） | 被動（10038） | 命中 | 回應沒有 `Content-Security-Policy` |
| T16-JS-03 | Juice Shop | GET 靜態資源 | anonymous | security：CORS `*` | 正例（設定） | 被動（10098） | 命中 | 回應有 `Access-Control-Allow-Origin: *` |
| T16-JS-04 | Juice Shop | GET `/ftp` | anonymous | security：目錄列表（Confidential Document） | 正例 | 主動（0） | **漏報** | 回 200、標題 `listing directory /ftp`；ZAP 有請求，Directory Browsing 沒有告警 |
| T16-JS-05 | Juice Shop | 前端路由的 XSS（DOM、Reflected） | anonymous | security：XSS | 正例 | 需要瀏覽器（AJAX spider） | 不在範圍 | traditional spider 走不到 |
| T16-VA-01 | VAmPI 弱點版 | GET `/users/v1/{username}` | anonymous | security：SQLi | 正例 | 主動（40018） | **漏報**（guard 的 `PATH_AMBIGUOUS`） | 對照實驗（不經 guard）命中；`name1'` 回 500（`sqlite3.OperationalError`） |
| T16-VA-02 | VAmPI 安全版 | GET `/users/v1/{username}` | anonymous | security：SQLi | 負例 | — | 沒有告警 | 對照實驗也沒有；`name1'` 回 404 `User not found`（ORM 查詢） |
| T16-VA-03 | VAmPI（兩版） | 所有回應 | standard_user | security：缺 `X-Content-Type-Options`、`Server` 版本 | 正例（設定，兩版都有） | 被動（10021、10036） | 命中 | 回應的 header |
| T16-VA-04 | VAmPI 弱點版 | GET `/books/v1/{book_title}` | standard_user | security：BOLA | 正例 | 不在 ZAP 能力範圍 | 不在範圍 | 以另一個使用者的 token 讀別人的書 |
| T16-VA-05 | VAmPI 弱點版 | POST `/users/v1/register`（`admin`） | anonymous | security：mass assignment | 正例 | 不在 ZAP 能力範圍 | 不在範圍 | 註冊之後 `/me` 的 `admin` 是 true |
| T16-VA-06 | VAmPI 弱點版 | GET `/users/v1/_debug` | anonymous | security：過度資料暴露 | 正例 | 不在 ZAP 能力範圍（白名單沒有） | 不在範圍 | 回應含所有使用者的密碼 |

T22 的複掃 live 流程（`make test-live-fixture-rescan`，`tests/live/test_fixture_rescan_live.py`）已完成三次有效校準與固定斷言後的最終執行（2026-11-07，`DECISIONS.md` §27.14）：
- 使用同一個 target、grant、host、IP 與 port，依序重建 fixture 弱點 baseline、弱點 control、修補版及 240 秒小預算弱點版；不是比較兩個不同 target。
- 真實 ZAP → Nuclei 經 guard 與 worker，讀取比較 API。核對 findings 聯集、觀察方向、分類數量、重複建立 200、後續 scan 不改變舊快照。每個量測 run 核對 profile 定義、plan_hash、觀察位置屬於 guard 轉送集合、實際收包不含規則 header、終止後掃描容器清理。
- 修補對照逐一檢查 baseline 中已對應的 finding，不以任何一筆 SQLi 代替整組；涵蓋 fixture 實際補上的 CSP、XCTO、anti-clickjacking、Referrer-Policy、CORS 與指定參數案例。每個案例另記 `checked`、`baseline_not_observed` 或 `no_automatic_mapping`，未命中與未對應不算驗證通過。
- 校準至少三次後才固定穩定的實測斷言，然後完整執行一次。錄製在 gitignore 的 `recordings/fixture-rescan/`，結果記 `DECISIONS.md` §27.14。
- 實測（`post-fix-1`、`post-fix-2-rerun`、`post-fix-3`、`final`，四次都 1 passed；另一次因主機闔蓋睡眠導致 Docker 停止回應，屬環境故障、不計次數）：弱點→弱點 comparable、不需人工（persistent 29、inconclusive 2）；弱點→修補 comparable、不需人工（persistent 8、inconclusive 24）；小預算 different、需人工（inconclusive 30–31）。四次的 new、not_observed、not_comparable 都是 0；12 個修補案例 6 個 checked（都是 inconclusive）、6 個 no_automatic_mapping，「誤判已修補」為 0。
- 固定斷言 `assert_calibrated_structure`：三組的 comparability、是否需要人工、snapshot 是否帶理由與 not_comparable=0；數量只記範圍，不寫死。
- S1–S4 只是前期證據可行性實測；兩次 180 秒 run 都 timed_out 的 S4 不能冒充完整複掃驗收。目前採 rule_completed=false 的保守退路，三種比較都直接斷言 `new == 0`、`not_observed == 0`，每個 finding 的來源證據亦不得宣稱規則完成；包含沒有 ground truth 對應的 finding，不只核對已知修補案例。
- Nuclei `/3` 的模板 error 保留正向 observations，但 run 是 `failed/ENGINE_REPORTED_ERRORS`。live 僅在 `engine_errors > 0`、scan `results_complete=false` 且其餘流量／來源／修補不變式皆通過時接受此特定部分失敗；其他失敗碼、取消、中斷及 ZAP failed 不放寬。成功 run 的錯誤數必須為零。
- 每輪用新的 `LIVE_PYTEST_ENV="SECSCAN_RECORD_DIR=$PWD/recordings/fixture-rescan/run-name"`；測試開始前拒絕已存在目錄，寫檔使用 exclusive create。修補案例核對另存 `ground-truth.json`，不混稱比較快照。

### 4.5 故障注入

在 queued/preparing/running/collecting/collected/normalizing 各階段，分別中斷 api、runner 或 worker。另外要測：

- 兩個 runner 同時認領同一個 run
- lease 過期，但容器仍在執行
- DB 暫時不可用
- guard 不可用（必須 fail closed）
- 磁碟滿、容器 OOM、解析例外
- Token 到期、手動取消

結果要求：無重複同 run 活躍容器；未證明舊 run 停止前不啟動新 run；partial evidence 不被刪除；狀態不能永久顯示 running；不將錯誤轉為「0 漏洞」。

T13 已涵蓋：見 §4.3 的 T13（integration）與 §4.4 的 T13（live）。各階段中斷 runner 的結果：queued 不受影響；preparing → `interrupted`（不必呼叫 Docker）；running、collecting、cancelling → 封鎖、刪除容器之後 `interrupted`；collected、normalizing 照常解析（容器沒刪掉的另外刪除）；解析中斷 3 次 → `failed`。Docker 長時間不可用時，run 停在 running（policy 保持 blocked、guard 拒絕它的流量），是「狀態不能永久顯示 running」唯一的例外（`DECISIONS.md` §17.2）。

T11 已涵蓋（egress guard，`tests/live/test_guard_failover_live.py`）：guard 停機時 `/scanners` 顯示 `GUARD_UNAVAILABLE`、新的 scan 留在 queued、對 guard 的連線失敗（fail closed），恢復後完成；guard 重啟（`boot_id` 改變）讓執行中的 run interrupted（`GUARD_UNAVAILABLE`）；runner 被 SIGKILL 之後，孤兒容器的請求在 lease（30 秒）內開始被拒絕（`POLICY_STALE`）、接收端不再收到；設定錯誤、只接一個網路、模組損壞的 guard 以非 0 結束、從未監聽。

T10 已涵蓋（容器版的 runner）：runner 收到 SIGTERM 時停止並刪除容器、run 標成 interrupted（live 實測 1.3 秒）；lease 失效時停止容器；Docker 中途不可用時刪除 secret、不把 run 標成結束的狀態；容器 OOM、消失、create／start 失敗。lease 過期而容器仍在執行、孤兒容器在 T13（見 §4.3 的 T13 與下方）。

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

#### 5.1.1 T30 fixture app 的案例表（strict-1）

自製的 fixture app 在 `tests/live/fixture_app/`（弱點版 insecure＝正例、修補版 secure＝負例，以啟動參數切換；跑在 guard 映像上）。事實來源是 `cases.py`，與這張表、OpenAPI 規格（`tests/fixtures/openapi/fixture-app-openapi3.yml`）三者對齊；不連網的程式測試 `tests/contract/test_fixture_cases.py` 逐案例驗證弱點版呈現、修補版修正。「平台結果」是 2026-11-01 的 live 量測（`make test-live-fixture`；數字見 `docs/TOOLS.md` §7.8）。strict-1 的 guard 只擋 path 中的百分比編碼，被擋下的案例標為「平台阻擋」，不計入掃描器漏報（`DECISIONS.md` §21.5、§22）。holdout 的案例在規則凍結前不使用（§5.2）。

T18 另以真的 nuclei 掃同一個 fixture app（`make test-live-fixture-nuclei`）：弱點版的可利用 CORS（FX-06）由 `cors-misconfig` 命中、修補版不命中，與 ZAP 10098 構成「同一問題多來源」；實跑驗證 plan_hash、與 /scan-profiles 一致的定義、`observed ⊆ forwarded`（guard-403 不誤報）、平台阻擋與共享預算（`DECISIONS.md` §24.5）。錄製到 `recordings/fixture-nuclei/`（gitignore），人工審查後才搬進 fixture。

OWASP 標記（T19 更正，`DECISIONS.md` §25.10）：Top 10:2025 由案例的 CWE 查官方的 CWE 清單（`findings/taxonomy/owasp_top10_2025.json`）而來，`test_fixture_cases.py` 核對一致；清單中沒有的 CWE 不標分類，不改 CWE 去湊。API Security Top 10:2023 是 curated。T30 初稿誤用了 2021 的編號（例如「A03:2025 Injection」），正負例與量測結果不受影響。

T19 以同一個 scan 同時跑 ZAP 與 Nuclei（`make test-live-fixture-findings`）：worker 把觀察連結到 finding。依使用者的簽核（`DECISIONS.md` §25.14），弱點版 FX-05 的缺 header 以 ZAP 為準、nuclei 在同一次 scan 同一個位置佐證時併入一個 finding（等級取最高值、標衝突）；FX-06 的 CORS 兩個工具偵測的行為不同，是兩個互相標示相關的 finding；修補版沒有 CORS 的 finding。

T20 擴充同一個指令（`DECISIONS.md` §26.8）：每個 finding 以追溯 API 翻完明細、歷史與觀察（同一個 as_of）；所有 finding 的觀察聯集等於 scan 的觀察、互不重疊；每個觀察的 artifact sha256 與大小等於 runs volume 的檔案，run 的 plan_hash、映像與版本和 scan 一致；去重的不變式成立；弱點版 POST /login 的 SQLi 在 username、password 上是兩個 finding（DEDUP-01 的 live 版本）。另加部分失敗的情境：同一個 fixture、時間預算 240 秒（先跑 3 次校準、結果相同才寫死斷言）——ZAP `timed_out`／`ENGINE_TIMEOUT`（時間上限）、nuclei `failed`／`BUDGET_EXHAUSTED`（沒有 plan、沒有容器）、scan `timed_out`（不是 completed）；ZAP 已取得的觀察都可追溯，流量秒數不超過預算。

安全案例（12 個正例＋12 個修補負例）：

| case_id | method／path | auth | 類別（OWASP） | ZAP 能否偵測 | 平台結果 | 人工確認方式 | 修補差異 | holdout |
|---|---|---|---|---|---|---|---|---|
| T30-FX-01 | GET `/search` | anonymous | SQLi（query 參數 q，CWE-89，A05:2025） | 主動（40018） | **命中**（40018×3） | q=apple' 回 500（sqlite OperationalError） | 參數化查詢，q 當資料 |  |
| T30-FX-02 | GET `/greet` | anonymous | 反射型 XSS（query 參數 name，CWE-79，A05:2025） | 主動（40012/40014） | **命中**（40012） | name=`<b>x</b>` 原樣反射（未轉義） | 以 html.escape 轉義 |  |
| T30-FX-03 | POST `/login` | anonymous | SQLi（表單 user/pass，CWE-89，A05:2025） | 主動（40018） | **命中**（40018） | `admin'--` 註解掉密碼條件即登入 | 參數化查詢，壞值回 401 |  |
| T30-FX-04 | GET `/search` | anonymous | 錯誤訊息／堆疊洩漏（CWE-209，A10:2025） | 被動（90022）/人工 | 漏報（無 90022；以 40018 間接命中） | 500 回應 body 含 OperationalError | 錯誤只回一般訊息 | ✓ |
| T30-FX-05 | GET `/` | anonymous | 缺安全 header／CSP（CWE-693，A06:2025） | 被動（10038、10021） | **命中**（10038、10021、10020） | 回應缺 CSP 與 X-Content-Type-Options | 每個回應補 SECURITY_HEADERS |  |
| T30-FX-06 | GET `/api/users` | anonymous | CORS 反射並帶憑證（CWE-942，A02:2025、API8:2023） | 被動（ZAP 10098）與 nuclei cors-misconfig | **命中**（ZAP 10098、nuclei cors-misconfig） | 反射 Origin 並帶 `Allow-Credentials: true`（可利用） | 不輸出 CORS header |  |
| T30-FX-07 | POST `/login` | anonymous | Cookie 缺 HttpOnly/Secure（CWE-1004，A02:2025） | 被動（10010/10011） | 漏報（spider 未提交登入表單取得 Set-Cookie） | Set-Cookie 缺 HttpOnly、Secure | 補 HttpOnly; Secure; SameSite |  |
| T30-FX-08 | GET `/go` | anonymous | 開放轉址（query 參數 next，CWE-601，A01:2025） | 主動（20019） | **命中**（20019 External Redirect） | next=外部 URL 回 302 指向外部 | next 僅允許白名單相對路徑 |  |
| T30-FX-09 | GET `/backup.sql` | anonymous | 敏感檔案暴露（CWE-530，不在 Top 10:2025 的清單） | 主動/人工 | 漏報（無檔案暴露告警，同 Juice Shop /ftp） | 回 200、body 含帳密 | 回 404 | ✓ |
| T30-FX-10 | GET `/api/orders/{id}` | standard_user | BOLA／IDOR（CWE-639，A01:2025、API1:2023） | 不在 ZAP 能力範圍 | 不在範圍（GET 已轉送；人工確認） | 以 alice 的 token 讀 bob 的 order（1002）回 200 | 只允許讀自己的 order，否則 404 |  |
| T30-FX-11 | POST `/api/users` | anonymous | Mass assignment（CWE-915，A08:2025、API3:2023） | 不在 ZAP 能力範圍 | 不在範圍（人工確認） | 註冊帶 is_admin=true 後 is_admin 為真 | 白名單欄位，is_admin 一律 0 |  |
| T30-FX-12 | GET `/api/users` | anonymous | 過度資料暴露（CWE-213，API3:2023） | 不在 ZAP 能力範圍 | 不在範圍（人工確認） | 回應含 password／secret_note | 只回 id、username、email |  ✓ |

contract/robustness 案例（6 個正例＋6 個修補負例；獨立標記，不加入 security TP/FP；由 `test_fixture_cases.py` 與人工確認，不以 ZAP 評）：

| case_id | method／path | 檢查 | 弱點版 | 修補版（修補差異） | holdout |
|---|---|---|---|---|---|
| T30-FX-C1 | GET `/api/orders/{id}` | 壞輸入狀態碼（非整數 id） | 回 500 | 回 400 |  |
| T30-FX-C2 | POST `/api/users` | 缺必填欄位 | 回 500 | 回 400 |  |
| T30-FX-C3 | GET `/api/users/{id}` | 回應不符宣告 schema | 多出 password、id 為字串 | 符合 OpenAPI schema | ✓ |
| T30-FX-C4 | POST `/api/users` | 型別混淆（body 為陣列） | 回 500 | 回 400 |  |
| T30-FX-C5 | PUT `/api/orders/{id}` | 未文件化 method | 回 500 | 回 405 |  |
| T30-FX-C6 | POST `/api/users` | 格式錯誤的 JSON | 回 500 | 回 400 | ✓ |

平台阻擋（另記，不計入上面 12）：

| case_id | method／path | 類別 | 平台結果 | 說明 |
|---|---|---|---|---|
| T30-FX-PB-01 | GET `/users/{username}` | SQLi（path 參數 username，CWE-89，A05:2025） | 平台阻擋（PATH_AMBIGUOUS） | 探測需 path 中的 `%27`，strict-1 下 guard 擋下、不到達靶機（同 §20.7 的 VAmPI path SQLi）；T33 的 `encoded-params-1` 放寬後才可達。修補版以參數化查詢修正 |

live 量測另外命中數個超出這 12 個列舉案例的告警（弱點版 web：40003 CRLF Injection、6 Path Traversal、10202 Absence of Anti-CSRF Tokens、10020 Missing Anti-clickjacking Header），如實記錄於 `TOOLS.md` §7.8，不改變 12＋12、6＋6 的計數。

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

T31 已實作子預算的凍結（`DECISIONS.md` §29.1）：建立 scan 時以 `engine_budgets` 凍結各引擎的嚴格上限，每個 run 取「剩下的」與上限的較小值，沒用完的份額作廢。實驗規格要求 experiment 的組合組凍結份額、合計等於單工具組的總額。仍然存在的偏差（份額作廢讓 C 的實際用量少於總額、引擎順序固定、清理的秒數、Nuclei 被上限停止就沒有輸出）由每個 run 的配額與 guard 計數（`engines[].usage`）與 manifest 揭露。正式的總額與份額由 T27 校準後凍結。

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

T22 的量測需分開列出 persistent、inconclusive、not_comparable 與需人工確認筆數，並保留 new/not_observed 為零的結果，不拿 inconclusive 當「驗證修補成功」。弱點→弱點是工具變異對照，弱點→修補是已知修補案例，小預算 current 是不完整覆蓋的反例；三組都必須沿用同一 target 與 scope。

校準至少三次且最後另跑完整驗證；每次保存四個 scan 的工具／模板／profile 身分、狀態、預算與比較快照。仍存在的 ground truth 被判 not_observed 的筆數必須為零；已修補案例允許 inconclusive，不能以增加「修補率」為由放寬證據。現有工具訊號不能證明完整規則執行，因此不能以這一版計算「自動驗證修補成功率」。T22 實測（§4.4）：四次有效 live 執行中仍存在的 ground truth 判 not_observed 為 0；已自動對應的 6 個修補案例（20 個 finding）全部是 inconclusive，另 6 個案例沒有自動對應、未逐一驗證。後續正式 benchmark（T31/T28）另報可信分母與限制。

### 7.4.1 T31 的實作（`benchmarks/`，`DECISIONS.md` §29.4）

- precision 以議題計：偵測到的案例與裁定為真的另一個議題是 TP，修補版上對上案例的 finding 與裁定為誤報的議題是 FP；同一個議題由多個 finding 或兩個工具命中只算一次。finding 層級的 precision 列為次要。
- recall 只算 security、supported、適用這個 scan 的 auth role、存在於這個版本的案例；holdout 預設排除，只有凍結的 ground truth 才能納入。
- 還有未裁定的 finding 時 precision 是 N/A；分母為 0 都是 N/A。一個 finding 對上兩個案例就停止評估。
- 去重的 predicted pair 以 finding 層級表示（同一個 finding 有 2 個以上引擎的來源）；逐一 observation pair 的標記在 T27 視需要擴充。
- 複掃另報「誤判已修補」（仍存在卻 not_observed）；inconclusive 不算驗證修補。

### 7.5 人工工作量（可選）

讓 3–5 名具基礎開發背景者對相同輸出，完成辨識獨立議題、定位證據與指出未完成引擎的任務。比較未整合與整合呈現的時間/正確率，交錯先後順序降低學習效應。樣本小，只當探索性可用性結果，不宣稱代表全產業。

## 8. 資料保存與公開

每次實驗記錄 run_manifest、程式 commit、映像 digest、模板/spec hash、靶場 snapshot、seed、時間、預算、實際請求、狀態與標記表。原始資料只存隔離受限環境，加密且設定留存；公開附件以遮罩且去識別化資料為限。

T31 的 manifest（`DECISIONS.md` §29.3）記錄規格的 sha256、種子與實際順序、每個 scan 的預算、子預算、分到的配額、guard 計數與狀態、比較快照、每個檔案的 sha256 與 session 是否完整；API 拿不到的身分（commit、本機映像 ID、fixture 原始碼的雜湊、strict-1）由 harness 記下並標明來源。結果目錄只保存 scan、finding 與比較快照的 JSON，不保存觀察的 evidence，目錄 0700、檔案 0600、寫入前檢查秘密；**T23a 起以本機的 bench 金鑰加密**（`DECISIONS.md` §30.7；金鑰檔在 repo 之外、遺失就無法復原），沒有自動的留存期限（T28 的研究資料，由使用者自行處理）。

建議遮罩 fixture 至少含一組可檢查的 synthetic secret，CI 搜尋它是否出現在不允許的輸出。不能只測 Authorization header，還需測 Cookie、query、body、stack trace、重現命令。

**平台的資料保護（T23a，`DECISIONS.md` §30）**：

| 資料 | 加密 | 金鑰（持有的容器） | 明文期間 | 保留期限 |
|---|---|---|---|---|
| runs volume 的原始證據 | run 結束（解析完成、失敗或逾期）、容器確認刪除之後的下一輪 | EVIDENCE（runner） | 執行、收集與等待解析；worker 異常時最多再加 60 分鐘 | 加密後 7 天 |
| 報告內容 | worker 寫入之前 | CONTENT（api、worker） | 只在 worker 渲染與 API 下載時的記憶體中 | 完成後 30 天 |
| 人工複測摘錄 | API 寫入之前 | CONTENT（api、worker） | 只在 API 的記憶體中 | 建立後 30 天 |
| `benchmarks/results` | 寫入之前 | 本機的 bench 金鑰檔 | 只在 harness 的記憶體中 | 不自動清除 |

清除只刪除內容：metadata、sha256、遮罩過的觀察、finding 與比較快照都保留。`secscan-admin retention-status` 列出各狀態的數量。

**隔離目錄的機密性隔離（`DECISIONS.md` §30.13）**：離線實作完成（EVID-10–12；審查的四個反例：搬回 `active/` 之後當機、搬移之前還有一次性掃描容器、搬移時目的地突然出現同名的非空目錄、`runs-init` 看到 `.layout` 但根目錄仍有 UUID 目錄，都有測試）。Docker 的實際驗證已在獨立的測試環境通過（2026-11-11），發現的 F1–F3 已修正（2026-11-12）：F1 是 `config runs-init` 的輸出含有 `DB_PASSWORD`，回歸測試 `test_compose_secrets`。**Live 在 2026-11-12 通過**：
- **證據**：
  - 兩項 Live 的證據斷言；
  - Live 期間 worker 的獨立檢查：subpath `active` 唯讀，`held/` 的四種路徑都是 ENOENT。
- **限制**：兩項 Live 的 `held/` 都是空的。非空 `held/` 的負向存取，以 2026-11-11 Docker 驗證的紀錄為證據，兩者互補（`DECISIONS.md` §30.13、§30.14）。
- **狀態**：T23a 完成，SEC-14 仍不標完成。

剩餘風險：
- **open FD（LOW，增量）**：被攻陷的 worker 在隔離之前開啟並保留的檔案 FD 或目錄 FD 無法自動撤銷，rename 之後仍讀得到明文。目錄 FD 也看得到隔離之後新增的檔案（目前只有加密檔）。同一個 worker 容器內同 uid 的程序，可以經由 `/proc/<pid>/fd` 借用。`..` 的逃逸被核心擋下。目前只能重啟 worker；完整的 FD 撤銷與驗收標準見 T23b-b3（不可省略，`DECISIONS.md` §30.14）。
- 其他：所有服務共用 uid 10001（uid 分離也在 T23b-b3，不可省略）；隔離之前約 1 分鐘、以及搬移持續失敗時，明文在 `active/`、worker 讀得到（看得見，15 分鐘後升級為緊急狀態，主動告警留待 T35；搬移持續失敗的處置程序與接受標準是提議，在 T23c 驗證，見 §30.14）；`held/` 不被覆寫依賴只有 runner 寫入；主機的容器檢查與搬移之間不是原子的，volume 的身分依賴 compose 的標籤。

**SEC-14 的剩餘風險（T23a 之後；`DECISIONS.md` §30.9）**：
1. **不是全程靜態加密**：run 執行、收集、等待解析期間是明文；runner 停機或 Docker 無法確認容器已刪除時持續到恢復為止。原因是 ZAP 與 Nuclei 只能寫一般檔案，runner 要在容器結束之後讀取並遮罩、worker 再讀取解析。改善方向：主機全碟加密（FileVault／LUKS，T23b 的部署要求）；未來以每個 run 的 tmpfs `out/` 加輔助容器加密、加密的 sidecar，或讓 worker 讀加密檔（和目前的最小權限分配衝突）。
2. **刪除只是 unlink**：磁碟的資料區塊、DB 的 dead tuple、WAL 與備份會保留舊資料，直到 VACUUM 或備份輪替。
3. **權限隔離有限**：所有服務都是 uid 10001、隔離只靠掛載；DB 只有一個角色、可以停用 trigger；金鑰以 compose 的環境變數傳入（T23b）。
4. **掃描容器的 json-file log** 在容器刪除之前可能保留 Nuclei 沒有遮罩的 stdout（T23b）。
5. **保持現狀的明文**：`observations` 中遮罩過的證據（含 Nuclei 擷取的 email 與卡號）、guard telemetry 的路徑（tmpfs、6 小時）、摘錄沒有加 salt 的雜湊；報告與摘錄下載的回應是明文（TLS 由部署負責）。
6. **本機研究資料**：`recordings/` 與 `runs/spike-t03/work/` 交給 T34。
7. **超過上限的單一目錄**（使用者決定方案 B，`DECISIONS.md` §30.12）：深度、條目數或路徑總長度超過上限時，keeper 連續 3 次失敗之後隔離這個目錄、改成需要人工處理，其他 run 恢復認領。剩下的風險：隔離的目錄保留明文直到有人以 `retry-evidence` 處理，掛載範圍的隔離已驗收（`DECISIONS.md` §30.13），但搬到 `held/` 之前（隔離中約 1 分鐘，或搬移持續失敗時）worker 仍讀得到；不做全域熔斷，告警在 T35；計數只在記憶體中（重啟會重新計數，`runner --once` 不會隔離）；超過深度 64、條目 50,000 或路徑總長度 16M 字元的樹不在系統內處理；孤兒目錄的解除 DB 無法確認已加密；runs volume 的目錄數量超過上限、清除失敗與其他種類的加密失敗仍然全域 fail closed。
8. **runner 指到可寫、但不是 runs volume 的目錄**時，找不到目錄的 run 仍會被記成 none（DB 分不出「從來沒有目錄」與「目錄不見了」）。
9. **金鑰在主機上**：`.env`（600）與家目錄中的 bench 金鑰檔；遺失之後尚未清除的資料都無法復原，備份由使用者負責。

## 9. 發布前 Gate

Gate A：兩個真實 Adapter 通過 live e2e。

Gate B：SEC-01 至 SEC-20 適用測試有結果；未支援能力明確關閉。所有已啟用功能的必測安全案例通過。

Gate C：取消/故障/重送/partial 狀態測試通過。

Gate D：去重與複掃的反例測試通過，報告無未驗證誇大敘述。（T20：去重反例已通過，§4.3 的 DEDUP 表；T22：RESCAN 離線反例與三次 live 校準＋最終執行已通過，§4.4；T21：報告的離線與 DB 測試已實作（§4.3 的 TRIAGE／REPORT 表），兩次 `make test-live-fixture-rescan` 的報告核對已通過（`DECISIONS.md` §28.15）；使用者審閱樣本報告的結論是核心安全語意通過、有條件通過，兩個措辭已修正（§28.17）。**通過（2026-11-08，接受有文件記錄的替代證據，`DECISIONS.md` §28.17）**：partially_completed 與 timed_out 由兩次 Live rescan 驗證；fixture 的 Live 不會產生 completed 的 scan，completed 改以 DB 整合測試驗證，走真實的 API、worker、渲染與下載流程，並直接套用 Live 的報告核對（§4.3 的 REPORT-03）。這個替代方案只適用於 Gate D 的報告正確性與措辭驗收，不宣稱已完成 completed 的 Live 端到端驗證。Gate D 通過不代表 M5 完成：SEC-14（T23a 已在 2026-11-12 完成，SEC-14 仍不標完成）、權限與速率限制（T23b）、Gate E（T23d）與 T23 的 DoD 仍未完成，Gate A–C 尚未正式判定。）

Gate E：以乾淨環境（新 clone、新 volume）重建 smoke test，版本/輸出可追溯；可能的話，請同學依文件獨立重建一次。

未達 Gate 時，降低功能範圍或如實標記限制，不為準時展示而關閉保護或偽造數據。
