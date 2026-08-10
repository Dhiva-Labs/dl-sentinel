# DL Sentinel self-hosted server image.
# Build:  docker build -t dl-sentinel .
# Run:    docker run -p 8752:8752 -e SENTINEL_API_TOKEN=... \
#           -v sentinel-data:/data -v /path/to/repos:/scans:ro dl-sentinel
# The image passes DL Sentinel's own infra scanner: non-root user, pinned base
# tag, no ADD, no piped installs, no secrets.

FROM node:20-alpine AS build
WORKDIR /app
COPY . .
RUN npm ci && npm run build

# Reinstall with only production dependencies for the runtime layer.
FROM node:20-alpine AS proddeps
WORKDIR /app
COPY . .
RUN npm ci --omit=dev

FROM node:20-alpine
ENV NODE_ENV=production \
    SENTINEL_DATA_DIR=/data \
    SENTINEL_SCAN_ROOT=/scans \
    PORT=8752
WORKDIR /app
COPY --from=proddeps /app/node_modules ./node_modules
COPY --from=proddeps /app/package.json ./package.json
COPY --from=build /app/packages ./packages
COPY --from=build /app/scanners ./scanners
COPY --from=build /app/apps ./apps
RUN mkdir -p /data /scans && chown -R node:node /data /scans
USER node
VOLUME ["/data"]
EXPOSE 8752
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8752)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "apps/api/dist/main.js"]
