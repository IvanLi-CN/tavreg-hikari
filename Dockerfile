# syntax=docker/dockerfile:1.7

FROM oven/bun:1 AS bun-bin

FROM mcr.microsoft.com/playwright:v1.58.2-noble AS deps
WORKDIR /app
COPY --from=bun-bin /usr/local/bin/bun /usr/local/bin/bun
COPY package.json bun.lock ./
COPY scripts/install-hooks.sh ./scripts/install-hooks.sh
RUN bun install --frozen-lockfile

FROM deps AS build
COPY . .
RUN bun run web:build

FROM mcr.microsoft.com/playwright:v1.58.2-noble AS runtime
WORKDIR /app
ARG APP_EFFECTIVE_VERSION=dev
ENV NODE_ENV=production \
    APP_EFFECTIVE_VERSION=${APP_EFFECTIVE_VERSION}
COPY --from=bun-bin /usr/local/bin/bun /usr/local/bin/bun
COPY package.json bun.lock ./
COPY scripts/install-hooks.sh ./scripts/install-hooks.sh
RUN bun install --frozen-lockfile --production
COPY --from=build /app/src ./src
COPY --from=build /app/web/dist ./web/dist
COPY --from=build /app/tsconfig.json ./tsconfig.json
COPY --from=build /app/.env.example ./.env.example
EXPOSE 3717
CMD ["bun", "run", "src/server/main.ts"]
