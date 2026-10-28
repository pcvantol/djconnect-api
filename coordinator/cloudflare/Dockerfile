# Official Node Linux/amd64 manifest; registry metadata read 2026-10-28.
# This pins the BASE, not an unbuilt application image or qualified Container.
FROM docker.io/library/node@sha256:84f8a721625927ef3ccdf94509ecaea463a266d23f1b01a184061e84d3a6574d
WORKDIR /app
COPY --chown=node:node source-container.mjs /app/source-container.mjs
USER node
# Production factory deliberately exits unavailable; no listener or provider.
CMD ["node", "/app/source-container.mjs"]
