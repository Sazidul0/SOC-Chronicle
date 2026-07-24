FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

FROM base AS dev
RUN pip install --no-cache-dir ".[dev]"
COPY tests/ ./tests/
COPY examples/ ./examples/

ENTRYPOINT ["chronicle"]
CMD ["--help"]
