FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-editable

COPY src/ src/

FROM python:3.12-slim

RUN groupadd -r seraph && useradd -r -g seraph -d /app seraph
WORKDIR /app

COPY --from=builder /app/.venv .venv/
COPY --from=builder /app/src src/

ENV PATH="/app/.venv/bin:$PATH"
USER seraph

ENTRYPOINT ["skillseraph"]
CMD ["--help"]
