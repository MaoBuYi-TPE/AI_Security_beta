# 一手技術來源

查核日期：2026-10-15。以下為選型與設計的參考，不代表已在本專題環境驗證過相容性或效能。官方 stable 文件可能變動，實作時需同時記錄已安裝版本、CLI help 與 Parser fixture。

| ID | 文件與網址 | 本計畫引用的要點 |
|---|---|---|
| S01 | [Claude Code — How Claude remembers your project](https://code.claude.com/docs/en/memory) | 專案根目錄 CLAUDE.md；建議保持精簡；指示文件不是強制安全設定 |
| S02 | [ZAP — Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) | 以 YAML 編排掃描工作、context、active scan 等 |
| S03 | [ZAP — Docker API Scan](https://www.zaproxy.org/docs/docker/api-scan/) | 匯入 OpenAPI/SOAP/GraphQL 後進行 API 調校的 active scan |
| S04 | [ZAP — Docker Documentation](https://www.zaproxy.org/docs/docker/) | Baseline、Full、API 掃描模式之區別 |
| S05 | [ZAP — OpenAPI Support](https://www.zaproxy.org/docs/desktop/addons/openapi-support/) | OpenAPI 規格匯入；需留意實際版本與格式限制 |
| S06 | [ProjectDiscovery — Running Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running) | 模板選擇、HTTP/其他協定、JSONL、redirect、rate-limit、輸出與認證設定 |
| S07 | [Schemathesis — CLI Options](https://schemathesis.readthedocs.io/en/stable/reference/cli/) | 依 schema 動態測試；JSON/NDJSON/JUnit/HAR；seed、案例量與格式限制 |
| S08 | [Schemathesis — Checks](https://schemathesis.readthedocs.io/en/stable/reference/checks/) | 規格/健壯性檢查；停用 unsupported_method 告警不會自動停止發送該請求 |
| S09 | [Schemathesis — API Authentication](https://schemathesis.readthedocs.io/en/stable/guides/auth/) | 與 securitySchemes 對應的 API key、Bearer、Basic 等認證配置 |
| S10 | [FastAPI — Background Tasks](https://fastapi.tiangolo.com/tutorial/background-tasks/) | 較重且不需同程序的工作可使用 Celery 等工作佇列 |
| S11 | [Celery — Tasks](https://docs.celeryq.dev/en/stable/userguide/tasks.html) | idempotency、acknowledgment、重新派送、timeout 的注意事項 |
| S12 | [Docker — Engine security](https://docs.docker.com/engine/security/) | Docker daemon 的高權限、API/掛載風險、容器資源與 capability 限制 |
| S13 | [OWASP — SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | allowlist、redirect、DNS 與網路層出站限制 |
| S14 | [OWASP — API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | 物件層授權依賴使用者與資源存取關係，不是只有 endpoint 可否呼叫 |
| S15 | [OWASP — API Security Top 10, 2023 edition](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) | 本專題可採用的固定分類版本，不聲稱此清單是完整測試規格 |
| S16 | [OWASP — Juice Shop](https://owasp.org/projects/juice-shop) | 可部署的故意脆弱 Web 教學靶場，僅掃自己的副本 |
| S17 | [OWASP — crAPI](https://owasp.org/projects/crapi) | 可選 API 故意脆弱靶場，非 MVP 必備 |
| S18 | [mitmproxy — Addons overview](https://docs.mitmproxy.org/stable/addons/overview/) | 以事件 hook 整合 request/response 控制與觀察 |
| S19 | [mitmproxy — Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/) | HTTPS 檢視需 client 信任 CA；upstream certificate sniffing 的連線行為 |

## 需要在 M0/M1 實際確認的事項

1. 三個引擎的具體映像版本、digest、目標 CPU 架構與授權條款。
2. ZAP 引擎及 add-on 版本、report job/JSON 報告欄位與退出碼契約。
3. Nuclei engine 與 templates commit、allowlist、proxy/redirect 的實際行為。
4. Schemathesis 鎖定版本的 CLI、報告格式、seed 與 generation phase 行為。
5. HTTPS 經 egress proxy 後的 CA 信任、上游憑證驗證及流量完整性。
6. 各映像的非 root/唯讀 rootfs/必要可寫目錄相容性。

## 來源與推論的界線

工具支援哪些功能取自上述官方文件。選用哪一套後端框架、工期、人數、預算、驗收指標、去重設計與專題定位，均是本計畫提出的工程方案或待驗證假設，不是官方保證，也不是市場調查結果。
