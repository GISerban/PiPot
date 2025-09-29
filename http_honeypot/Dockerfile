FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/
RUN pip install --no-cache-dir flask httpx
RUN adduser --disabled-login --uid 1000 honeypot && mkdir -p /data && chown -R 1000:1000 /data
USER 1000
EXPOSE 80
CMD ["python","app.py"]

