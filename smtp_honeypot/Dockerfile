FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/
RUN adduser --disabled-login --uid 1000 honeypot && mkdir -p /data && chown -R 1000:1000 /data
USER 1000
EXPOSE 1883
CMD ["python","app.py"]
