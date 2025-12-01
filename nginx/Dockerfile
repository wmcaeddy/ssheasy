FROM golang:1.23.3-alpine AS builder

WORKDIR /go/src/web

COPY ./web .

RUN GOOS=js GOARCH=wasm go build -o main.wasm


FROM nginx:1.23.3

# Install envsubst for config templating
RUN apt-get update && apt-get install -y gettext-base && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/go/misc/wasm/wasm_exec.js /usr/share/nginx/html/

# Add nginx configuration template and entrypoint
COPY ./nginx/nginx.conf.template /etc/nginx/nginx.conf.template
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf
COPY ./nginx/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Copy over static assets from the client application
COPY ./web/html /usr/share/nginx/html
COPY --from=builder /go/src/web/main.wasm /usr/share/nginx/html/

# Environment variables for Railway deployment
ENV PORT=80
ENV PROXY_HOST=proxy
ENV PROXY_PORT=5555

EXPOSE ${PORT}

ENTRYPOINT ["/docker-entrypoint.sh"]