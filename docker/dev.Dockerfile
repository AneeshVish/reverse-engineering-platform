FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PATH="/workspace/.venv/bin:$PATH"

WORKDIR /workspace

# Proto toolchain placeholder versions for later phases (buf/protoc not required until schemas exist)
RUN python -c "import sys; assert sys.version_info[:2] == (3, 12)"

CMD ["bash"]
