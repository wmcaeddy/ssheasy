FROM golang:1.20.1-alpine AS builder

WORKDIR /go/src/proxy

# When built from repo root with RAILWAY_DOCKERFILE_PATH, copy only proxy folder
COPY ./proxy/ .

RUN go build .

FROM alpine:3.17

COPY --from=builder /go/src/proxy/proxy .

# Environment variables for Railway deployment
# Railway sets PORT automatically, proxy uses it for public listener
ENV PORT=5555
ENV ADMIN_PORT=6666
# ADMIN_KEY should be set at runtime via Railway environment variables
ENV AUDIT_LOG="/tmp/connections.log"

EXPOSE ${PORT}

CMD ["./proxy"]