# ---------- CVV Calculator API ----------
FROM node:20-alpine

WORKDIR /app

# Dependencias (capa cacheada)
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

# Código
COPY server.js ./

ENV NODE_ENV=production \
    PORT=3000

EXPOSE 3000

# Healthcheck nativo (Northflank lo detecta)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${PORT}/health" >/dev/null || exit 1

CMD ["node", "server.js"]