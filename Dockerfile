FROM node:22-alpine AS builder

WORKDIR /app
COPY server/package.json server/package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

FROM nginx:1.27-alpine

# Install Node.js runtime for the backend
RUN apk add --no-cache nodejs

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Only the public gate is served by nginx. The reader stays behind Node auth.
COPY index.html /usr/share/nginx/html/
COPY icon-192x192.png site.webmanifest /usr/share/nginx/html/
COPY reader.html /app/private/reader.html

# EPUB is now embedded encrypted in reader.html — no separate file needed
# COPY dark_transcendence.epub /app/

# Copy backend
COPY --from=builder /app/node_modules /app/node_modules
COPY server/server.js /app/server.js
COPY server/package.json /app/package.json

# Start script: run both nginx and node
RUN printf '#!/bin/sh\nset -e\nnginx\ncd /app && exec node server.js\n' > /start.sh && chmod +x /start.sh

EXPOSE 8080
CMD ["/start.sh"]
