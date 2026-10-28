FROM node:22-bookworm-slim

# Install Python 3 for native Python AST parsing alongside Node/TypeScript & Z3 WASM
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    git \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Build frontend Vite bundle and verify TypeScript server
RUN npm run build

ENV NODE_ENV=production
ENV PORT=3001
# The server refuses to start on 0.0.0.0 unless LEXCOMPILER_API_TOKEN is provided at runtime.
ENV HOST=0.0.0.0

EXPOSE 3001

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3001/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["npm", "start"]
