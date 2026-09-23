# syntax=docker/dockerfile:1
#
# Multi-stage build.
#
# The builder compiles wheels; the runtime carries none of the build tooling.
# The result is a smaller image with a smaller attack surface, which is the
# point of the split rather than the size saving on its own.

# ---------------------------------------------------------------- builder ---
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update \
 && apt-get install --no-install-recommends -y build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build a wheel, then resolve it into a self-contained prefix that the runtime
# stage copies wholesale. No compiler reaches the final image.
RUN python -m pip install --upgrade pip build \
 && python -m build --wheel --outdir /wheels \
 && python -m pip install --prefix=/install /wheels/*.whl

# ---------------------------------------------------------------- runtime ---
FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="PhishGuard" \
      org.opencontainers.image.description="Adversarially Robust Phishing Defense using Email, URL and Behavioral Features" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/your-org/phishguard"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    PG_ARTIFACTS_DIR=/data \
    PG_ENVIRONMENT=prod \
    PG_LOG_FORMAT=json \
    PATH="/install/bin:$PATH" \
    PYTHONPATH="/install/lib/python3.11/site-packages"

# curl is the only addition: the container healthcheck uses it, and adding one
# small package is preferable to shipping a Python healthcheck script that
# would import the whole application on every probe.
RUN apt-get update \
 && apt-get install --no-install-recommends -y curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin phishguard

# The analyst console ships inside the wheel as package data, so there is
# nothing to copy separately and no path for it to be missing from.
COPY --from=builder /install /install
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# /data holds the model registry and the audit database, and is the only
# writable path the service needs; declaring it lets the filesystem be mounted
# read-only in hardened deployments.
RUN mkdir -p /data /app \
 && chown -R phishguard:phishguard /data /app \
 && chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /app
USER phishguard
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=4s --start-period=40s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
