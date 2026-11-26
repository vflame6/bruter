# Build
# Must match (or exceed) the go directive in go.mod, otherwise the builder
# silently downloads a second toolchain at image build time.
FROM golang:1.26-alpine AS go_builder
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o bruter .

# Release
FROM alpine:latest
RUN apk upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
RUN adduser -D -u 1000 -s /sbin/nologin app
USER app
COPY --from=go_builder /app/bruter /usr/local/bin

ENTRYPOINT ["bruter"]
