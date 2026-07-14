FROM node:22-alpine AS builder

WORKDIR /app
COPY server/package.json server/package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

FROM nginx:1.27-alpine

# Install Node.js runtime for the backend
RUN apk add --no-cache nodejs

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy static files (gate = index.html)
COPY index.html /usr/share/nginx/html/index.html

# Copy protected files (NOT served directly by nginx — served via Node API)
COPY reader.html dark_transcendence.epub /app/

# Copy backend
COPY --from=builder /app/node_modules /app/node_modules
COPY server/server.js /app/server.js
COPY server/package.json /app/package.json

# Start script: run both nginx and node
RUN printf '#!/bin/sh\nset -e\nnginx\ncd /app && exec node server.js\n' > /start.sh && chmod +x /start.sh

EXPOSE 8080
CMD ["/start.sh"]
