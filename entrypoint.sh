#!/bin/bash
set -e

echo "Starting DecryptTrace backend..."

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

echo "Starting application server..."
exec uvicorn app.api.app:app --host 0.0.0.0 --port 8000 --workers 4
