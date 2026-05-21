FROM node:22-slim

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

WORKDIR /app
COPY . .

RUN pnpm install --frozen-lockfile --dangerously-allow-all-builds
RUN pnpm run build
RUN pnpm prune --prod

EXPOSE 3000
CMD ["node", "dist/main"]
