FROM node:22-alpine AS build
WORKDIR /workspace
RUN npm install -g pnpm@10.6.3
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/identity/package.json apps/identity/package.json
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile
COPY apps/api apps/api
RUN pnpm --filter @zeroshare/api build

FROM node:22-alpine AS runtime
WORKDIR /workspace
ENV NODE_ENV=production
RUN addgroup -S zeroshare && adduser -S zeroshare -G zeroshare
COPY --from=build --chown=zeroshare:zeroshare /workspace/node_modules ./node_modules
COPY --from=build --chown=zeroshare:zeroshare /workspace/apps/api ./apps/api
USER zeroshare
EXPOSE 4000
CMD ["node", "apps/api/dist/server.js"]
