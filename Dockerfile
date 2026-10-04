FROM node:24.9.0-bookworm-slim@sha256:3e69116c924bfcba6c6979aff60d966c37aef56d488ce091c69d442ebec9f103 AS frontend
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build
FROM frontend AS frontend-tests
CMD ["npm", "test"]
FROM ghcr.io/astral-sh/uv:0.8.22@sha256:9874eb7afe5ca16c363fe80b294fe700e460df29a55532bbfea234a0f12eddb1 AS uv
FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS app
COPY --from=uv /uv /uvx /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends git subversion php-cli && rm -rf /var/lib/apt/lists/* && groupadd -g 10001 numen && useradd -m -u 10001 -g numen numen && mkdir -p /data/artifacts && chown -R numen:numen /data
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY backend/ ./
RUN uv sync --locked --no-dev
COPY --from=frontend /build/frontend/dist /app/frontend/dist
COPY runner/plugins.lock.json /app/runner/plugins.lock.json
COPY runner/resources/trailofbits /app/runner/resources/trailofbits
ENV PATH="/app/backend/.venv/bin:/usr/local/bin:/usr/bin:/bin" NUMEN_FRONTEND_ROOT=/app/frontend/dist NUMEN_ARTIFACT_ROOT=/data/artifacts NUMEN_SKILL_ROOT=/app/runner/resources/trailofbits/skills/audit-context-building
USER 10001:10001
CMD ["uvicorn", "numen.api:app", "--host", "0.0.0.0", "--port", "8080"]
FROM app AS test
USER root
RUN uv sync --locked --extra dev
USER 10001:10001
CMD ["pytest", "-q", "-p", "no:cacheprovider"]
