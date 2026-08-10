# I001 positive: the *builder* stage drops to a non-root user, but the final
# stage (the one actually shipped) never sets USER, so it still runs as root.
FROM node:20.11.1-bookworm-slim@sha256:9aa972b3fb8f3cafe155e6064b0813fa3069033eb6c22830043692be2836aeb3 AS build
WORKDIR /src
COPY . .
USER node
RUN npm run build

FROM node:20.11.1-bookworm-slim@sha256:9aa972b3fb8f3cafe155e6064b0813fa3069033eb6c22830043692be2836aeb3
WORKDIR /app
COPY --from=build /src/dist ./dist
CMD ["node", "dist/index.js"]
