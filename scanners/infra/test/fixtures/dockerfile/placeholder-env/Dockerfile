# I004 negative: placeholder/reference values and non-secret-shaped names
# must not be flagged.
FROM node:20.11.1-bookworm-slim@sha256:9aa972b3fb8f3cafe155e6064b0813fa3069033eb6c22830043692be2836aeb3

ARG BUILD_TOKEN
ENV API_KEY=${API_KEY}
ENV APP_SECRET=changeme
ENV DESCRIPTION=this-is-not-a-credential

USER node
