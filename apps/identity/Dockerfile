FROM node:22-alpine AS build
WORKDIR /workspace
RUN npm install -g pnpm@10.6.3
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/identity/package.json apps/identity/package.json
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile
COPY apps/identity apps/identity
RUN pnpm --filter @zeroshare/identity build

FROM node:22-alpine AS runtime
WORKDIR /workspace
ENV NODE_ENV=production
RUN addgroup -S zeroshare && adduser -S zeroshare -G zeroshare
COPY --from=build --chown=zeroshare:zeroshare /workspace/node_modules ./node_modules
COPY --from=build --chown=zeroshare:zeroshare /workspace/apps/identity ./apps/identity
USER zeroshare
EXPOSE 4001
CMD ["node", "apps/identity/dist/server.js"]
