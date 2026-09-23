#!/bin/sh
# Container entrypoint.
#
# `serve` is the default. It trains a model first if the registry is empty, so
# that `docker compose up` on a clean machine produces a working system in one
# command rather than a service that starts and immediately reports "not ready".
#
# Any other argument is passed straight through to the CLI, which is what makes
# `docker compose run --rm api evaluate --defense-ablation` work.

set -eu

ARTIFACTS="${PG_ARTIFACTS_DIR:-/data}"
BOOTSTRAP_N="${PG_BOOTSTRAP_N:-12000}"
# Cloud hosts (Render, Railway, Hugging Face Spaces, Fly) tell the container
# which port to listen on through PORT; honour it unless PG_API_PORT is set.
PORT_TO_USE="${PG_API_PORT:-${PORT:-8000}}"

log() { printf '{"ts":"%s","level":"INFO","logger":"entrypoint","message":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1"; }

if [ "${1:-serve}" = "serve" ]; then
    mkdir -p "${ARTIFACTS}" 2>/dev/null || true
    if [ ! -f "${ARTIFACTS}/models/current" ]; then
        if [ "${PG_BOOTSTRAP_TRAIN:-1}" = "1" ]; then
            log "no model in the registry - training one (n=${BOOTSTRAP_N}, a few minutes)"
            phishguard train --n "${BOOTSTRAP_N}" --save
            log "bootstrap training complete"
        else
            log "no model in the registry and bootstrap training is disabled; /readyz will report not ready"
        fi
    else
        log "using the model registered at ${ARTIFACTS}/models/current"
    fi

    log "starting API on ${PG_API_HOST:-0.0.0.0}:${PORT_TO_USE} with ${PG_API_WORKERS:-1} worker process(es)"
    exec phishguard serve --host "${PG_API_HOST:-0.0.0.0}" --port "${PORT_TO_USE}" \
        --workers "${PG_API_WORKERS:-1}"
fi

exec phishguard "$@"
