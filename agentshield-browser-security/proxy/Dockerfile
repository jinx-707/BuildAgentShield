FROM node:22-bookworm-slim AS dependencies

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    PROXY_HOST=0.0.0.0 \
    PROXY_PORT=3128 \
    PROXY_HEALTH_HOST=0.0.0.0 \
    PROXY_HEALTH_PORT=9090

WORKDIR /app

COPY --from=dependencies /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src

USER node

EXPOSE 3128 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:9090/health/ready').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]

CMD ["node", "src/index.js"]
