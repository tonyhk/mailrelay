FROM --platform=$BUILDPLATFORM golang:1-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go dashboard.html ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/mailrelay .
# the data volume must be writable by UID 1000 (same as the Python image) even when it is empty
RUN mkdir -p /out/data && chown 1000:1000 /out/data

FROM gcr.io/distroless/static-debian12

LABEL org.opencontainers.image.title="mailrelay" \
      org.opencontainers.image.description="SMTP relay to an authenticated upstream server with logging and web overview"

ENV MAILRELAY_CONFIG=/app/config.toml \
    MAILRELAY_LOG_DB=/app/data/mailrelay.db \
    MAILRELAY_LOG_FILE=/app/data/smtp_log.jsonl \
    MAILRELAY_QUEUE_DIR=/app/data/queue \
    TZ=UTC

WORKDIR /app
COPY --from=build /out/mailrelay /usr/local/bin/mailrelay
COPY --from=build --chown=1000:1000 /out/data /app/data

USER 1000:1000
VOLUME ["/app/data"]
# 2525 = SMTP relay (publish as 25/587 on the host), 8080 = web overview + API
EXPOSE 2525 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/mailrelay", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/mailrelay"]
CMD ["serve"]
