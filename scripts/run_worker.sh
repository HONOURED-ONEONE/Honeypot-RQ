#!/usr/bin/env bash
set -e
# Uses REDIS_URL and RQ_QUEUE_NAME from .env if exported; otherwise defaults.
REDIS_URL=${REDIS_URL:-redis://localhost:6379/0}
RQ_QUEUE_NAME=${RQ_QUEUE_NAME:-callback}
rq worker "$RQ_QUEUE_NAME" --url "$REDIS_URL"
