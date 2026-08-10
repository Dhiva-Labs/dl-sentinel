# I003 negative: the second FROM references an earlier stage's name (an
# alias), not a real registry image, and must not be flagged even though
# "build" has no tag of its own.
FROM node:20.11.1-bookworm-slim@sha256:9aa972b3fb8f3cafe155e6064b0813fa3069033eb6c22830043692be2836aeb3 AS build
RUN true

FROM build AS test
RUN true

USER node
