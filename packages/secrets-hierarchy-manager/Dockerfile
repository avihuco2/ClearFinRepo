# ---- Build Stage ----
FROM node:22-alpine AS build

WORKDIR /app

# Copy root workspace files
COPY package.json package-lock.json tsconfig.json ./

# Copy shared package (dependency)
COPY packages/shared/package.json packages/shared/tsconfig.json packages/shared/
COPY packages/shared/src/ packages/shared/src/

# Copy secrets-hierarchy-manager package
COPY packages/secrets-hierarchy-manager/package.json packages/secrets-hierarchy-manager/tsconfig.json packages/secrets-hierarchy-manager/
COPY packages/secrets-hierarchy-manager/src/ packages/secrets-hierarchy-manager/src/

# Install all dependencies (including devDependencies for build)
RUN npm ci --ignore-scripts

# Build TypeScript
RUN npm run build --workspace=packages/shared
RUN npm run build --workspace=packages/secrets-hierarchy-manager

# ---- Production Stage ----
FROM node:22-alpine AS production

ENV NODE_ENV=production
WORKDIR /app

# Copy root workspace files for production install
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/secrets-hierarchy-manager/package.json packages/secrets-hierarchy-manager/

# Install production dependencies only
RUN npm ci --omit=dev --ignore-scripts

# Copy compiled output from build stage
COPY --from=build /app/packages/shared/dist/ packages/shared/dist/
COPY --from=build /app/packages/secrets-hierarchy-manager/dist/ packages/secrets-hierarchy-manager/dist/

# Use existing non-root node user (UID 1000)
USER node

EXPOSE 3002

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3002/health || exit 1

CMD ["node", "packages/secrets-hierarchy-manager/dist/index.js"]
