FROM --platform=$BUILDPLATFORM golang:1.26.4 AS builder

ARG TARGETOS TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-amd64} \
    go build -o envoy-proxy-bouncer

FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /app/envoy-proxy-bouncer /app/

ENTRYPOINT ["/app/envoy-proxy-bouncer"]

CMD ["serve"]
