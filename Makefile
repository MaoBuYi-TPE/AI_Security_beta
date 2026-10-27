# 開發命令，依 docs/START_HERE.md §7 的約定建立。
# 一律使用 uv.lock 鎖定的依賴（--locked）；lock 與 pyproject.toml 不一致時直接失敗，不會默默更新。
UV_RUN := uv run --locked

# OrbStack 目前沒有 compose 外掛，`docker compose` 不可用時改用 docker-compose。
# 用遞延指派（=）：只有 lab 目標才會求值，避免每次 make test/lint 都 fork docker。
COMPOSE = $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
DB_FILE := compose.yaml
LAB_FILE := compose.lab.yaml
LAB_PROJECT := secscan-lab
LAB_NET := secscan_lab_net
# 預設啟動全部靶機；可用 `make lab-up LAB_PROFILES="vampi"` 只啟動部分。
LAB_PROFILES ?= juice-shop vampi
LAB_PROFILE_ARGS := $(foreach p,$(LAB_PROFILES),--profile $(p))
# make env 會補齊的本機秘密（隨機 hex，只寫進不進 git 的 .env）。
LOCAL_SECRET_KEYS := DB_PASSWORD DB_ADMIN_PASSWORD TEST_DB_PASSWORD
# 加密目標 secret 的金鑰（docs/DECISIONS.md §12.1）：Fernet 金鑰，url-safe base64 的 32 bytes（44 個字元）。
ENCRYPTION_KEYS_VAR := SECRET_ENCRYPTION_KEYS
# .env 中一行的開頭：dotenv 也接受 `export ` 前綴與等號前後的空白，比對時要一樣寬，
# 否則會再附加一行，而後面的那一行會默默取代原本的值（對加密金鑰而言，舊的 secret 就解不開了）。
ENV_LINE := ^[[:space:]]*(export[[:space:]]+)?

.PHONY: bootstrap dev test lint typecheck env docker-check db-up db-down test-db-up migrate \
	lab-up lab-down lab-verify

# 安裝鎖定的依賴（含開發工具）並啟用 pre-commit hook。
bootstrap:
	uv sync --locked
	$(UV_RUN) pre-commit install

# 啟動 API 開發程序：只綁 127.0.0.1，APP_ENV=dev 才開啟 API 文件。API 需要 .env 中的加密金鑰，
# 所以先執行 make env（只補上缺少的值）。
dev: env
	APP_ENV=dev $(UV_RUN) uvicorn --factory secscan.main:create_app \
		--host 127.0.0.1 --port 8000 --reload --reload-dir src

# unit/contract/integration 測試與 coverage 門檻（分支覆蓋），不做 live scan。
# 測試程序本身不連網、也不碰 Docker；整合測試用的 db-test 由這裡先啟動。
test: test-db-up
	$(UV_RUN) pytest -m "not live" --cov --cov-report=term-missing --cov-fail-under=80

# ruff lint、format 檢查與 import-linter 依賴方向檢查。
lint:
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .
	$(UV_RUN) lint-imports

# mypy strict。
typecheck:
	$(UV_RUN) mypy

# 建立或補齊本機 .env（權限 600）：只新增缺少的秘密，不修改既有的值。
env:
	@umask 077; touch .env; chmod 600 .env
	@for key in $(LOCAL_SECRET_KEYS); do \
		if grep -Eq "$(ENV_LINE)$$key[[:space:]]*=[[:space:]]*$$" .env; then \
			echo "錯誤：.env 的 $$key 是空值；請刪除那一行再執行 make env（不會覆寫既有的值）"; exit 1; \
		fi; \
		if ! grep -Eq "$(ENV_LINE)$$key[[:space:]]*=" .env; then \
			secret=$$(openssl rand -hex 24) || exit 1; \
			[ "$${#secret}" -eq 48 ] || { echo "錯誤：openssl 沒有產生有效的隨機值"; exit 1; }; \
			if [ -s .env ] && [ -n "$$(tail -c1 .env)" ]; then echo >> .env; fi; \
			echo "$$key=$$secret" >> .env; \
			echo "已在 .env 產生 $$key（隨機值，只供本機使用）"; \
		fi; \
	done
	@if grep -Eq "$(ENV_LINE)$(ENCRYPTION_KEYS_VAR)[[:space:]]*=[[:space:]]*$$" .env; then \
		echo "錯誤：.env 的 $(ENCRYPTION_KEYS_VAR) 是空值；請刪除那一行再執行 make env（不會覆寫既有的值）"; exit 1; \
	fi
	@if ! grep -Eq "$(ENV_LINE)$(ENCRYPTION_KEYS_VAR)[[:space:]]*=" .env; then \
		key=$$(openssl rand -base64 32 | tr '+/' '-_') || exit 1; \
		[ "$${#key}" -eq 44 ] || { echo "錯誤：openssl 沒有產生有效的金鑰"; exit 1; }; \
		if [ -s .env ] && [ -n "$$(tail -c1 .env)" ]; then echo >> .env; fi; \
		echo "$(ENCRYPTION_KEYS_VAR)=$$key" >> .env; \
		echo "已在 .env 產生 $(ENCRYPTION_KEYS_VAR)（加密目標 secret 的金鑰；遺失後已保存的 secret 都解不開，請備份這一行）"; \
	fi

docker-check:
	@docker version >/dev/null 2>&1 || { echo "Docker daemon 未執行，請先啟動 OrbStack（orb start）"; exit 1; }

# 開發用 PostgreSQL（只綁 127.0.0.1，預設 port 55432）。
db-up: env docker-check
	$(COMPOSE) -f $(DB_FILE) up -d --wait db

# 整合測試用 PostgreSQL（tmpfs，只綁 127.0.0.1，預設 port 55433）。
test-db-up: env docker-check
	$(COMPOSE) -f $(DB_FILE) --profile test up -d --wait db-test

# 停止 db 與 db-test；開發資料保存在 volume，不會刪除。
db-down:
	$(COMPOSE) -f $(DB_FILE) --profile test down

# 把開發資料庫升級到最新 schema（Alembic upgrade head）；不做任何破壞性重置。
# 最後印出目前版本（例如 0001 (head)），確認實際升級到哪裡。
migrate:
	$(UV_RUN) alembic upgrade head
	@$(UV_RUN) alembic current

# 啟動隔離 lab 靶場（只接 internal network，不發布 port）。
lab-up: docker-check
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
