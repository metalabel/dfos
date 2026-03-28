FROM golang:1.24-alpine AS build

WORKDIR /src

# go.mod requires go 1.26 — let the toolchain auto-download it
ENV GOTOOLCHAIN=auto

# copy go.mod/go.sum for dependency caching
COPY packages/dfos-protocol-go/go.mod packages/dfos-protocol-go/go.sum packages/dfos-protocol-go/
COPY packages/dfos-web-relay-go/go.mod packages/dfos-web-relay-go/go.sum packages/dfos-web-relay-go/
RUN cd packages/dfos-web-relay-go && go mod download

# copy source
COPY packages/dfos-protocol-go packages/dfos-protocol-go
COPY packages/dfos-web-relay-go packages/dfos-web-relay-go

# build static binary (modernc.org/sqlite is pure Go — no CGO needed)
RUN cd packages/dfos-web-relay-go && \
    CGO_ENABLED=0 go build -o /relay ./cmd/relay

# ---------------------------------------------------------------------------

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=build /relay /usr/local/bin/relay

VOLUME /data
ENV SQLITE_PATH=/data/relay.db

EXPOSE 8080

ENTRYPOINT ["relay"]
