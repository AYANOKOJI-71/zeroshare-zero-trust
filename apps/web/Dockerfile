FROM node:22-alpine AS build
WORKDIR /workspace
RUN npm install -g pnpm@10.6.3
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/identity/package.json apps/identity/package.json
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile
COPY apps/web apps/web
ARG VITE_IDENTITY_ISSUER=http://localhost:4001
ENV VITE_IDENTITY_ISSUER=$VITE_IDENTITY_ISSUER
RUN pnpm --filter @zeroshare/web build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/apps/web/dist /usr/share/nginx/html
EXPOSE 8080
