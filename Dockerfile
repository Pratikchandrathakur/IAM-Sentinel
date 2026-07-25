# IAM Sentinel — CPU-only, tiny image. The deterministic engine needs no GPU/ML libs.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/app/data

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

# Non-root; owns the writable data dir (audit DB).
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8080/api/readyz || exit 1

CMD ["python", "app.py"]
