FROM node:22-bookworm-slim AS dependencies

ENV PUPPETEER_SKIP_DOWNLOAD=true
WORKDIR /app

COPY worker/package.json worker/package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    WORKER_HOST=0.0.0.0 \
    WORKER_PORT=8080

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        chromium \
        chromium-sandbox \
        dumb-init \
        fonts-liberation \
    && chmod 4755 /usr/lib/chromium/chrome-sandbox \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=dependencies /app/node_modules ./node_modules
COPY worker/package.json ./
COPY worker/src ./src
COPY proxy/src/lib/policy.js /proxy/src/lib/policy.js
RUN ln -s /app/node_modules /proxy/node_modules

USER node

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:8080/health/live').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/index.js"]
