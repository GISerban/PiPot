# ssh_honeypot/Dockerfile
FROM python:3.12-slim

WORKDIR /app

# install build dependencies for cryptography if wheel not available
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential libffi-dev libssl-dev python3-dev git ca-certificates && \
    python3 -m pip install --upgrade pip setuptools wheel

# install paramiko (and its deps)
RUN pip install --no-cache-dir paramiko

# copy app
COPY app.py /app/

# create non-root user and data dir (uid 1000)
RUN adduser --disabled-login --uid 1000 honeypot \
    && mkdir -p /data /data/meta /data/raws /data/logs /data/pcaps /data/attachments \
    && chown -R 1000:1000 /data

USER 1000
EXPOSE 2222
CMD ["python", "app.py"]

