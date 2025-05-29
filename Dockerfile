FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o envoy-gateway-bouncer

FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /app/envoy-gateway-bouncer /app/

ENTRYPOINT ["/app/envoy-gateway-bouncer"]

CMD ["serve"]