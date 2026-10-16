# Web 與 API 多引擎動態安全檢測後端｜畢業專題規劃包

- 文件日期：2026-10-15
- 專題代號：`webapi-security-backend`（暫名）
- 文件狀態：**設計與開發規格，不是已完成或已實測的後端程式。**
- 使用者已確認的範圍：Web 應用、API 安全檢測、整合 2–3 個動態工具、只製作後端。
- 規劃假設：3 人、16 週；人數與實際期限尚未確認，時程可依情況調整。

## 建議題目

**Web 與 API 多引擎動態安全檢測暨結果整合後端系統之設計與實作**

第一版完成 ZAP + Nuclei；Schemathesis 為第二階段的第三引擎。專題貢獻聚焦於授權範圍控管、可靠掃描編排、證據保留、保守去重、覆蓋率與複掃比較，而不是宣稱自行發明弱點掃描器。

## 文件索引

| 檔案 | 用途 |
|---|---|
| `CLAUDE.md` | 放在程式專案根目錄的 Claude Code 開發規則 |
| `docs/PROJECT_PLAN.md` | 背景、需求、工具選型、功能範圍、時程與交付成果 |
| `docs/ARCHITECTURE.md` | 後端模組、資料模型、Adapter、狀態機與部署設計 |
| `docs/API_CONTRACT.md` | 預計實作的 REST API、權限、資料格式與錯誤語意 |
| `docs/SECURITY_AND_TESTING.md` | 掃描平台自身的安全要求、測試矩陣與實驗設計 |
| `docs/TASKS.md` | 可逐項執行的工作拆解、依賴、驗收條件與降階方案 |
| `docs/START_HERE.md` | 開發順序、給 Claude Code 的第一段任務提示 |
| `docs/SOURCES.md` | 已查核的一手技術文件與引用對照 |

## 使用方式

將本包中的 `CLAUDE.md` 和 `docs/` 複製到程式專案根目錄。先閱讀 `docs/START_HERE.md`，再依 `docs/TASKS.md` 從 M0 開始。根目錄使用大寫檔名 **`CLAUDE.md`**。[S01]

這個包沒有 `app/`、Docker Compose、migration 或已安裝的掃描器。文件中的指令與 API 為**待實作契約**；不能把寫好的文件、Mock 測試或示意資料當成真實掃描成功的證明。

## 範圍界線

僅針對自有或已獲明確授權的隔離靶場；預設 `LAB_ONLY`，不能因為輸入了一個 URL 或勾選聲明，就取得掃描該網站的授權。沒有前端開發工作，使用 REST API、內建 API 文件、HTTP client 與 JSON/Markdown 報告展示。

AI 判讀、RAG、白箱原始碼分析、行動 App、全網資產發現、多租戶商用 SaaS、任意工具/模板上傳、自動修補與正式站台掃描都不列入第一版。

## 來源

本文的 `[Sxx]` 對照見 `docs/SOURCES.md`。所有硬體、工期、資料量與驗收門檻都是規劃值，不是已量測結果。
