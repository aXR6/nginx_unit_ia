#!/bin/sh
set -e

# Aguarda o banco ficar disponível
if [ -n "$POSTGRES_HOST" ]; then
  until pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER"; do
    echo "Aguardando banco..."
    sleep 2
  done
fi

# Wait for Elasticsearch if configured
if [ -n "$ES_HOST" ]; then
  until curl -s "$ES_HOST" >/dev/null 2>&1; do
    echo "Aguardando Elasticsearch..."
    sleep 2
  done
fi

python -m app.menu
