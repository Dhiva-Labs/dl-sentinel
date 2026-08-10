# Deliberately insecure fixture Dockerfile for DL Sentinel scanner tests.
# Not built or run by anything; a pattern target only.

FROM node:latest

ADD https://example.invalid/bootstrap.sh /bootstrap.sh

ENV NPM_TOKEN=npm_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE00

WORKDIR /app
COPY . .
RUN npm install

USER root

CMD ["node", "index.js"]
