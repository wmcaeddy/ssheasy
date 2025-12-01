#!/bin/sh
set -e

# Set defaults for Railway deployment
export PORT="${PORT:-80}"
export PROXY_HOST="${PROXY_HOST:-proxy}"
export PROXY_PORT="${PROXY_PORT:-5555}"
export PROXY_SCHEME="${PROXY_SCHEME:-http}"

echo "Generating nginx config..."
echo "PORT=${PORT}, PROXY_HOST=${PROXY_HOST}, PROXY_PORT=${PROXY_PORT}, PROXY_SCHEME=${PROXY_SCHEME}"

# Generate nginx config from template
# Note: We only substitute our custom variables, preserving nginx's own $ variables
envsubst '${PORT} ${PROXY_HOST} ${PROXY_PORT} ${PROXY_SCHEME}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

echo "Testing nginx config..."
nginx -t

echo "Starting nginx on port ${PORT}, proxying to ${PROXY_HOST}:${PROXY_PORT}"

# Execute nginx
exec nginx -g 'daemon off;'
