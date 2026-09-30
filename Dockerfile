# Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates tzdata

# Copy dependency definition
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build lightweight binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /paymentgt-server ./cmd/server

# Final Lightweight Runtime Stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
ENV TZ=Asia/Jakarta

WORKDIR /app

# Copy binary from builder
COPY --from=builder /paymentgt-server /app/paymentgt-server

# Default port
EXPOSE 8080

ENTRYPOINT ["/app/paymentgt-server"]
