# syntax=docker/dockerfile:1.7
FROM node:22-bookworm-slim AS web
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY web/package.json web/package.json
COPY sdk/typescript/sdk/package.json sdk/typescript/sdk/package.json
COPY sdk/typescript/auth/package.json sdk/typescript/auth/package.json
COPY sdk/typescript/react/package.json sdk/typescript/react/package.json
COPY sdk/typescript/server/package.json sdk/typescript/server/package.json
COPY sdk/typescript/events/package.json sdk/typescript/events/package.json
RUN pnpm install --frozen-lockfile
COPY web web
COPY sdk/typescript sdk/typescript
RUN pnpm build

FROM golang:1.25-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
COPY migrations migrations
COPY sdk/go sdk/go
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/supaapps/platform93/internal/buildinfo.Version=${VERSION} -X github.com/supaapps/platform93/internal/buildinfo.Commit=${COMMIT} -X github.com/supaapps/platform93/internal/buildinfo.Date=${BUILD_DATE}" -o /out/platform93 ./cmd/platform93

FROM alpine:3.22
RUN apk add --no-cache ca-certificates postgresql16-client \
    && addgroup -g 65532 -S nonroot \
    && adduser -u 65532 -S nonroot -G nonroot
WORKDIR /app
COPY --from=backend /out/platform93 /app/platform93
COPY --from=web /src/web/out /app/admin
ENV PLATFORM93_ADMIN_ASSETS=/app/admin
EXPOSE 8093
USER 65532:65532
ENTRYPOINT ["/app/platform93"]
CMD ["serve"]
