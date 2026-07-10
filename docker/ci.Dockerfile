FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    CI=1

WORKDIR /workspace

COPY pyproject.toml uv.lock .python-version ./
COPY libs libs
COPY tools tools
COPY packages packages
COPY apps apps
COPY proto proto
COPY tests tests
COPY docs docs
COPY scripts scripts
COPY .pre-commit-config.yaml .pre-commit-config.yaml

RUN uv sync --all-groups --frozen

CMD ["uv", "run", "reveng-validate", "--json"]
