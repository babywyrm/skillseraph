FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.9.17@sha256:5cb6b54d2bc3fe2eb9a8483db958a0b9eebf9edff68adedb369df8e7b98711a2 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# Debian security fixes land before the python image is rebuilt, and the app
# runs from the uv venv, so the system pip is only attack surface.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall -y pip \
    && groupadd -r seraph && useradd -r -g seraph -d /app seraph
WORKDIR /app

COPY --from=builder /app/.venv .venv/
COPY --from=builder /app/src src/

ENV PATH="/app/.venv/bin:$PATH"
USER seraph

ENTRYPOINT ["skillseraph"]
CMD ["--help"]
