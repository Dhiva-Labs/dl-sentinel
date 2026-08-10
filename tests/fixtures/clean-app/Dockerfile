# Fixture Dockerfile with no known insecure patterns; a negative control for
# DL Sentinel scanner tests. Not built or run by anything.

FROM node:20.11.1-bookworm-slim@sha256:9aa972b3fb8f3cafe155e6064b0813fa3069033eb6c22830043692be2836aeb3

WORKDIR /app
COPY --chown=node:node . .
RUN npm ci --omit=dev

USER node

CMD ["node", "index.js"]
