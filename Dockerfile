FROM python:3.13-slim

LABEL org.opencontainers.image.title="mailrelay" \
      org.opencontainers.image.description="SMTP relay to an authenticated upstream server with logging and web overview"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MAILRELAY_CONFIG=/app/config.toml \
    MAILRELAY_LOG_DB=/app/data/mailrelay.db \
    MAILRELAY_LOG_FILE=/app/data/smtp_log.jsonl \
    MAILRELAY_QUEUE_DIR=/app/data/queue \
    TZ=UTC

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --system --uid 1000 --home /app app \
 && mkdir -p /app/data && chown app:app /app/data
# The source files sit at the repo root; inside the image they must form the "mailrelay" package
# (relative imports + dashboard.html are loaded from it, and ENTRYPOINT runs `python -m mailrelay`).
COPY --chown=app:app *.py dashboard.html ./mailrelay/

USER app
VOLUME ["/app/data"]
# 2525 = SMTP relay (publish as 25/587 on the host), 8080 = web overview + API
EXPOSE 2525 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import socket,urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3); s=socket.create_connection(('127.0.0.1',2525),3); sys.exit(0 if s.recv(64).startswith(b'220') else 1)"]

ENTRYPOINT ["python", "-m", "mailrelay"]
CMD ["serve"]
