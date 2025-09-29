# Dockerfile
FROM python:3.11-slim

# Create non-root user to avoid running as root
RUN useradd --create-home --shell /bin/bash honeypot

WORKDIR /app

# Copy app files
COPY httpot.py /app/httpot.py
COPY entrypoint.sh /app/entrypoint.sh

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Install nothing extra (stdlib only). Set a small healthcheck dependency (none required).
USER honeypot

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--host", "0.0.0.0", "--port", "10134", "--log", "/app/logs/http-honeypot.log"]
