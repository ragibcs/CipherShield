# CipherShield AI web
FROM node:22-alpine AS deps
WORKDIR /srv/ciphershield-web
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine AS builder
WORKDIR /srv/ciphershield-web
COPY --from=deps /srv/ciphershield-web/node_modules ./node_modules
COPY . .
# Inlined into the bundle at build time: the browser talks to the API directly.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /srv/ciphershield-web
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S nextjs -g 1001 && adduser -S nextjs -G nextjs -u 1001

COPY --from=builder --chown=nextjs:nextjs /srv/ciphershield-web/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /srv/ciphershield-web/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nextjs /srv/ciphershield-web/public ./public

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
