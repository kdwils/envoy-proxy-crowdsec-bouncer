FROM golang:1.24.4 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o envoy-proxy-bouncer

FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --chown=1000:1000 --from=builder /app/envoy-proxy-bouncer /app/

USER 1000

ENTRYPOINT ["/app/envoy-proxy-bouncer"]
CMD ["serve"]
