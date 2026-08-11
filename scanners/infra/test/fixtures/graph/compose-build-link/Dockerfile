# Graph fixture: unpinned base image plus an EXPOSEd port, to verify the
# Dockerfile contributes its own image/port nodes and links to the compose
# service (in the sibling docker-compose.yml) that builds it.
FROM node:latest

EXPOSE 3000

USER node
