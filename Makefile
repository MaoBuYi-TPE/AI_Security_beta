# 開發命令，依 docs/START_HERE.md §7 的約定建立。
# 一律使用 uv.lock 鎖定的依賴（--locked）；lock 與 pyproject.toml 不一致時直接失敗，不會默默更新。
UV_RUN := uv run --locked

# OrbStack 目前沒有 compose 外掛，`docker compose` 不可用時改用 docker-compose。
# 用遞延指派（=）：只有 lab 目標才會求值，避免每次 make test/lint 都 fork docker。
COMPOSE = $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
LAB_FILE := compose.lab.yaml
LAB_PROJECT := secscan-lab
LAB_NET := secscan_lab_net
# 預設啟動全部靶機；可用 `make lab-up LAB_PROFILES="vampi"` 只啟動部分。
LAB_PROFILES ?= juice-shop vampi
LAB_PROFILE_ARGS := $(foreach p,$(LAB_PROFILES),--profile $(p))

.PHONY: bootstrap dev test lint typecheck lab-up lab-down lab-verify

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

# 啟動隔離 lab 靶場（只接 internal network，不發布 port）。
lab-up:
	@docker version >/dev/null 2>&1 || { echo "Docker daemon 未執行，請先啟動 OrbStack（orb start）"; exit 1; }
	@# up 之前先擋掉對外 port 與 host 網路的設定
	@if $(COMPOSE) -f $(LAB_FILE) $(LAB_PROFILE_ARGS) config | grep -qE '^[[:space:]]*(published|network_mode):'; then \
		echo "錯誤：compose 含對外 port 或 network_mode，lab 必須完全隔離"; exit 1; fi
	$(COMPOSE) -f $(LAB_FILE) $(LAB_PROFILE_ARGS) up -d --wait
	@$(MAKE) --no-print-directory lab-verify \
		|| { echo "隔離檢查失敗，收回 lab"; $(COMPOSE) -f $(LAB_FILE) --profile juice-shop --profile vampi down; exit 1; }
	@echo "lab 已啟動（profiles：$(LAB_PROFILES)）；關閉用 make lab-down"

# 驗證 lab 真的隔離：internal、isolated gateway、無對外 port（M2 live 測試前置可共用）。
lab-verify:
	@n=$$(docker ps -q --filter "label=com.docker.compose.project=$(LAB_PROJECT)" | wc -l | tr -d ' '); \
		[ "$$n" -gt 0 ] || { echo "錯誤：找不到 lab 容器"; exit 1; }
	@docker network inspect $(LAB_NET) --format '{{.Internal}}' | grep -qx true \
		|| { echo "錯誤：$(LAB_NET) 不是 internal network"; exit 1; }
	@test "$$(docker network inspect $(LAB_NET) --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}')" = isolated \
		|| { echo "錯誤：$(LAB_NET) 不是 isolated gateway（舊 Engine 可能不支援）"; exit 1; }
	@ports=$$(docker ps --filter "label=com.docker.compose.project=$(LAB_PROJECT)" --format '{{.Ports}}'); \
		echo "$$ports" | grep -qF -- '->' && { echo "錯誤：偵測到對外發布的 port"; exit 1; } || true
	@echo "lab 隔離檢查通過（internal + isolated + 無對外 port）"

# 停止並移除 lab。注意：spike（spikes/t03）若仍接在 $(LAB_NET) 上，網路會刪不掉，需先停 spike。
lab-down:
	$(COMPOSE) -f $(LAB_FILE) --profile juice-shop --profile vampi down --remove-orphans
