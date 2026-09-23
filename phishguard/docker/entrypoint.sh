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

log() { printf '{"ts":"%s","level":"INFO","logger":"entrypoint","message":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1"; }

if [ "${1:-serve}" = "serve" ]; then
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

    log "starting API on ${PG_API_HOST:-0.0.0.0}:${PG_API_PORT:-8000}"
    exec phishguard serve --host "${PG_API_HOST:-0.0.0.0}" --port "${PG_API_PORT:-8000}"
fi

exec phishguard "$@"
