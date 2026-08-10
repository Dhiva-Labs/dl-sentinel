# I001 positive: last USER instruction switches back to root.
FROM node:20.11.1-bookworm-slim@sha256:9aa972b3fb8f3cafe155e6064b0813fa3069033eb6c22830043692be2836aeb3

WORKDIR /app
COPY . .
RUN npm ci --omit=dev

USER node
USER root

CMD ["node", "index.js"]
