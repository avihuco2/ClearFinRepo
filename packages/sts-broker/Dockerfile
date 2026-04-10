# ---- Build Stage ----
FROM node:22-alpine AS build

WORKDIR /app

# Copy root workspace files
COPY package.json package-lock.json tsconfig.json ./

# Copy shared package (dependency)
COPY packages/shared/package.json packages/shared/tsconfig.json packages/shared/
COPY packages/shared/src/ packages/shared/src/

# Copy sts-broker package
COPY packages/sts-broker/package.json packages/sts-broker/tsconfig.json packages/sts-broker/
COPY packages/sts-broker/src/ packages/sts-broker/src/

# Install all dependencies (including devDependencies for build)
RUN npm ci --ignore-scripts

# Build TypeScript
RUN npm run build --workspace=packages/shared
RUN npm run build --workspace=packages/sts-broker

# ---- Production Stage ----
FROM node:22-alpine AS production

ENV NODE_ENV=production
WORKDIR /app

# Copy root workspace files for production install
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/sts-broker/package.json packages/sts-broker/

# Install production dependencies only
RUN npm ci --omit=dev --ignore-scripts

# Copy compiled output from build stage
COPY --from=build /app/packages/shared/dist/ packages/shared/dist/
COPY --from=build /app/packages/sts-broker/dist/ packages/sts-broker/dist/

# Create non-root user and switch to it
RUN addgroup -g 1000 appgroup && adduser -u 1000 -G appgroup -D appuser
USER appuser

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["node", "packages/sts-broker/dist/index.js"]
