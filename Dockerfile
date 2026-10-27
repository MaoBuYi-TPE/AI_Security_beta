# secscan 的應用程式映像（docs/DECISIONS.md §14.8）：api、runner、worker 共用，以不同的 command 執行。
# 依賴只來自 uv.lock（--locked）；基底映像以 digest 鎖定。執行時是非 root（10001）、可用唯讀 rootfs。
#   make build   建立 secscan:dev

FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3.12 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# 先只裝第三方依賴（這一層在程式改動時可以重用），再裝專案本身（不可編輯的安裝）。
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
# runner 的兩個 volume 掛在 /runs、/run-secrets：第一次掛載空的 named volume 時，Docker 會沿用這裡的
# 擁有者與權限（10001、0700），runner 才能建立每個 run 的目錄。
RUN groupadd --system --gid 10001 secscan \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin secscan \
    && install -d -o 10001 -g 10001 -m 0700 /runs /run-secrets
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /tmp
CMD ["secscan-admin", "--help"]
