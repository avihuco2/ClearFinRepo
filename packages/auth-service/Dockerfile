# ---- Build Stage ----
FROM node:22-alpine AS build

WORKDIR /app

# Copy root workspace files
COPY package.json package-lock.json tsconfig.json ./

# Copy shared package (dependency)
COPY packages/shared/package.json packages/shared/tsconfig.json packages/shared/
COPY packages/shared/src/ packages/shared/src/

# Copy auth-service package
COPY packages/auth-service/package.json packages/auth-service/tsconfig.json packages/auth-service/
COPY packages/auth-service/src/ packages/auth-service/src/

# Install all dependencies (including devDependencies for build)
RUN npm ci --ignore-scripts

# Build TypeScript
RUN npm run build --workspace=packages/shared
RUN npm run build --workspace=packages/auth-service

# ---- Production Stage ----
FROM node:22-alpine AS production

ENV NODE_ENV=production
WORKDIR /app

# Copy root workspace files for production install
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/auth-service/package.json packages/auth-service/

# Install production dependencies only
RUN npm ci --omit=dev --ignore-scripts

# Copy compiled output from build stage
COPY --from=build /app/packages/shared/dist/ packages/shared/dist/
COPY --from=build /app/packages/auth-service/dist/ packages/auth-service/dist/

# Create non-root user and switch to it
RUN addgroup -g 1000 appgroup && adduser -u 1000 -G appgroup -D appuser
USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "packages/auth-service/dist/index.js"]
