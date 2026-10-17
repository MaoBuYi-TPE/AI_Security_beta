# Web 與 API 多引擎動態安全檢測後端｜畢業專題規劃包

- 文件日期：2026-10-16（整合版）
- 專題代號：`webapi-security-backend`（暫名；Python 套件名暫定 `secscan`）
- 文件狀態：**設計與開發規格，不是已完成或已實測的後端程式。**
- 已確認的條件：
  - 範圍：Web 應用與 API 安全檢測，整合 3 個動態工具，只做後端。
  - 人力與時程：1 人開發，2026/10/16 – 2027/06/30（約 37 週）。

## 建議題目

**Web 與 API 多引擎動態安全檢測暨結果整合後端系統之設計與實作**

P0 先完成 ZAP + Nuclei。兩引擎通過 P0 Gate 後，M6 再接第三引擎 Schemathesis。專題貢獻聚焦於授權範圍控管、強制出站邊界、可靠的掃描編排、證據保留、保守去重、覆蓋率與複掃比較，而不是宣稱自行發明弱點掃描器。

## 規劃來源

本包整合了兩份規劃：

- **ChatGPT 版原稿**：本儲存庫第一個 commit，可用 `git show 86d7b2b` 查看。
- **Claude 版**：在 Claude Code 規劃模式中產出。

逐項比較與取捨理由見 `docs/DECISIONS.md`。

## 文件索引

| 檔案 | 用途 |
|---|---|
| `CLAUDE.md` | 放在專案根目錄的 Claude Code 開發規則 |
| `docs/REQUIREMENTS.md` | 已凍結的需求摘要：題目、相對於手動使用工具的增益、P0/P1/不做、研究問題與待驗證假設 |
| `docs/TOOLS.md` | T03 工具 spike 結果：映像相容性表、digest、授權、網路隔離與各引擎 proxy/auth/output 的實測 |
| `docs/PROJECT_PLAN.md` | 背景、需求、工具選型、功能範圍、時程與交付成果 |
| `docs/ARCHITECTURE.md` | 元件、信任邊界、egress guard、資料模型、Adapter/Runner 與狀態機 |
| `docs/API_CONTRACT.md` | 預計實作的 REST API、權限、資料格式與錯誤語意 |
| `docs/SECURITY_AND_TESTING.md` | 平台自身的安全要求、測試矩陣與實驗設計 |
| `docs/TASKS.md` | 依里程碑排列的工作、依賴、驗收條件與降階方案 |
| `docs/START_HERE.md` | 開發順序，以及給 Claude Code 的第一段任務提示 |
| `docs/DECISIONS.md` | 兩份規劃的比較與設計取捨，可作為報告素材 |
| `docs/SOURCES.md` | 已查核的一手技術文件與引用對照 |

## 使用方式

先閱讀 `docs/START_HERE.md`，再依 `docs/TASKS.md` 的順序開發。根目錄使用大寫檔名 **`CLAUDE.md`**。[S01]

目前完成到 M0 的 T02、T03：一個只有 `GET /health/live` 的 FastAPI 應用與品質命令（T02），以及隔離 lab（`compose.lab.yaml` + `make lab-up`）與三個掃描器經 proxy 的工具 spike（T03，結果見 `docs/TOOLS.md`）。還沒有資料庫、migration、runner 或正式的 Adapter／egress guard（M1 起）。其他文件中的指令與 API 仍是**待實作的契約**；`tests/fixtures/` 的真實輸出是給未來 Parser 開發用的樣本，不代表平台已能端到端掃描，也不能把 Mock 當成真實掃描成功的證明。

### 開發環境

需要 Homebrew 與 uv；專案固定使用 Python 3.12（見 `.python-version`）。

```bash
brew install uv   # 依賴管理工具
make bootstrap    # 依 uv.lock 安裝依賴，並啟用 pre-commit hook
make test         # 離線測試（封鎖 TCP/UDP 與 DNS）與 coverage 門檻 80%
make lint         # ruff 與 import-linter
make typecheck    # mypy strict
make dev          # 只綁 127.0.0.1:8000；/docs 只在 dev 開啟
```

`make dev` 啟動後，`curl http://127.0.0.1:8000/health/live` 會回傳 `{"success": true, "data": {"status": "ok"}, "error": null, "meta": null}`。

TDD 時可以只跑單一測試檔：`uv run pytest tests/unit/core/test_config.py`，這樣不會檢查 coverage 門檻；提交前仍以 `make test` 為準。

#### 隔離 lab 靶場（T03）

需要先啟動 OrbStack（`orb start`）。lab 只接 internal network、不發布任何 port：

```bash
make lab-up                     # 啟動 Juice Shop 與 VAmPI（vulnerable/secure）
make lab-up LAB_PROFILES=vampi  # 只啟動部分（profile：juice-shop、vampi）
make lab-down                   # 停止並移除（若 spike 仍接在 lab_net 上，需先停 spike）
```

工具 spike 的腳本與重現步驟見 `spikes/t03/README.md`，結論見 `docs/TOOLS.md`。只掃 lab，不對外。

#### venv

`make bootstrap` 建立的 `.venv` 是標準的 Python venv，也可以用一般的 venv 方式操作：

```bash
source .venv/bin/activate   # 啟用後可直接執行 python、pytest、mypy
deactivate                  # 離開
```

依賴一律以 `uv add`／`uv remove` 修改，`uv.lock` 會同步更新。`.venv` 裡沒有 pip，請不要用 pip 直接安裝套件，否則環境會和 `uv.lock` 不一致。VS Code 請選用 `.venv/bin/python` 作為直譯器。

## 範圍界線

- **掃描對象**：僅限自有或已獲明確授權的隔離靶場。預設 `LAB_ONLY`，不能因為輸入了一個 URL 或勾選聲明，就取得掃描該網站的授權。
- **展示方式**：沒有前端開發工作，使用 REST API、內建 API 文件、HTTP client 與 JSON/Markdown 報告展示。
- **不列入第一版**：AI 判讀、RAG、白箱原始碼分析、行動 App、全網資產發現、多租戶商用 SaaS、任意工具/模板上傳、自動修補、正式站台掃描。

## 法律提醒

未經授權掃描他人系統，可能觸犯刑法第 36 章妨害電腦使用罪（§358–363）[S30]。

- 只掃描 lab 靶機，或已取得書面授權的目標。
- 不要掃描校園或第三方的系統。
- 不確定時，先請指導教授確認。

## 來源

本文的 `[Sxx]` 對照見 `docs/SOURCES.md`。所有硬體、工期、資料量與驗收門檻都是規劃值，不是已量測結果。
