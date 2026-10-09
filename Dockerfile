FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /graphrelay ./cmd/graphrelay

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && adduser -D -H -u 10001 relay
COPY --from=build /graphrelay /usr/local/bin/graphrelay
USER relay
WORKDIR /app
VOLUME ["/app/data"]
EXPOSE 25 465 587 8443
ENTRYPOINT ["graphrelay", "-config", "/app/config.yaml"]
