# Start with a slim Python base image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies (curl for outbound requests, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and keys
COPY pyproject.toml .
COPY app.py ./ssh_honeypot/
COPY server.key server.key.pub ./

# Install dependencies and project in editable mode
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -e .

# Create a data directory and make it writable
RUN mkdir -p /data && chmod 777 /data
RUN chmod 644 /app/server.key /app/server.key.pub


# Expose SSH honeypot port
EXPOSE 2222

# Set environment variables if needed
ENV PYTHONUNBUFFERED=1

# Default command to run the honeypot
CMD ["ssh-honeypot"]
