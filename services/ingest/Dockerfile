# Build from the repository root:
#   docker build -f services/ingest/Dockerfile -t ot-ingest .
# The service is deliberately unprivileged and shell-free at runtime.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 app

WORKDIR /app
COPY services/ingest/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# The service validates against the repository's telemetry contract.
COPY metadata/telemetry.schema.json /app/metadata/telemetry.schema.json
COPY services /app/services

USER app
EXPOSE 8080

# No --reload, no debug, no access log (the structured audit log is separate).
CMD ["uvicorn", "services.ingest.app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
