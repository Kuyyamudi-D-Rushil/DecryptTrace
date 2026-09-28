# Stage 1: Build
FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DT_AIR_GAP=true

WORKDIR /app

# Run as non-root user
RUN addgroup --system decrypttrace && adduser --system --group decrypttrace
USER decrypttrace

COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache /wheels/*

COPY --chown=decrypttrace:decrypttrace . .
RUN chmod +x entrypoint.sh

EXPOSE 8000

# Use a non-root port and strict uvicorn workers
CMD ["./entrypoint.sh"]
