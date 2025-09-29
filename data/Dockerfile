FROM python:3.12-slim

WORKDIR /app

# Install minimal system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the log exporter script into the image
COPY log-exporter.py .

# Install runtime Python dependency
RUN pip install --no-cache-dir aiohttp

# Ensure /data exists and is writable (mounted from host in compose)
RUN mkdir -p /data && chmod 777 /data

EXPOSE 8081

ENV PYTHONUNBUFFERED=1

CMD ["python", "log-exporter.py"]

