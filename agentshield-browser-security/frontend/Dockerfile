FROM node:22-alpine

ENV NODE_ENV=production

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --create-home app

COPY package.json package-lock.json* ./
RUN npm ci --no-cache

COPY . .

RUN npm run build

USER app

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "--spider", "http://127.0.0.1:3000/", "||", "exit", "1"]

CMD ["npm", "start"]
