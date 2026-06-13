FROM golang:1.24-alpine AS build

WORKDIR /src

# go.mod requires go 1.26 — let the toolchain auto-download it
ENV GOTOOLCHAIN=auto

# copy go.mod/go.sum for dependency caching
COPY packages/dfos-protocol-go/go.mod packages/dfos-protocol-go/go.sum packages/dfos-protocol-go/
COPY packages/dfos-web-relay-go/go.mod packages/dfos-web-relay-go/go.sum packages/dfos-web-relay-go/
COPY packages/dfos-cli/go.mod packages/dfos-cli/go.sum packages/dfos-cli/
RUN cd packages/dfos-cli && go mod download

# copy source
COPY packages/dfos-protocol-go packages/dfos-protocol-go
COPY packages/dfos-web-relay-go packages/dfos-web-relay-go
COPY packages/dfos-cli packages/dfos-cli

# build static binary (modernc.org/sqlite is pure Go — no CGO needed)
RUN cd packages/dfos-cli && \
    CGO_ENABLED=0 go build -o /dfos ./cmd/dfos

# ---------------------------------------------------------------------------

# alpine:3.22 pinned by multi-arch index digest (reproducible, supply-chain safe)
FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601

RUN apk add --no-cache ca-certificates

COPY --from=build /dfos /usr/local/bin/dfos

VOLUME /data
ENV SQLITE_PATH=/data/relay.db

EXPOSE 8080

ENTRYPOINT ["dfos", "serve"]
CMD ["--port", "8080"]
