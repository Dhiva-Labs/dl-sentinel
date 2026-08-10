# I005 positive: remote script piped directly into a shell.
FROM node:20.11.1-bookworm-slim@sha256:9aa972b3fb8f3cafe155e6064b0813fa3069033eb6c22830043692be2836aeb3

RUN curl -fsSL https://example.invalid/install.sh | bash

USER node
