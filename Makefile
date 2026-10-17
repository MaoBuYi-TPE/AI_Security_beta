# 開發命令，依 docs/START_HERE.md §7 的約定建立。
# 一律使用 uv.lock 鎖定的依賴（--locked）；lock 與 pyproject.toml 不一致時直接失敗，不會默默更新。
UV_RUN := uv run --locked

.PHONY: bootstrap dev test lint typecheck

# 安裝鎖定的依賴（含開發工具）並啟用 pre-commit hook。
bootstrap:
	uv sync --locked
	$(UV_RUN) pre-commit install

# 啟動 API 開發程序：只綁 127.0.0.1，APP_ENV=dev 才開啟 API 文件。
dev:
	APP_ENV=dev $(UV_RUN) uvicorn --factory secscan.main:create_app \
		--host 127.0.0.1 --port 8000 --reload --reload-dir src

# 離線測試（封鎖 TCP/UDP 與 DNS）與 coverage 門檻（分支覆蓋），不做 live scan。
test:
	$(UV_RUN) pytest --cov=secscan --cov-report=term-missing --cov-fail-under=80

# ruff lint、format 檢查與 import-linter 依賴方向檢查。
lint:
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .
	$(UV_RUN) lint-imports

# mypy strict。
typecheck:
	$(UV_RUN) mypy
