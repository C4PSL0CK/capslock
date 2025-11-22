# Policy Engine Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY root/ ./root/
COPY templates/ ./templates/
COPY validator/ ./validator/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./root/

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary and templates
COPY --from=builder /app/main .
COPY --from=builder /app/templates ./templates/

# Expose port
EXPOSE 8081

# Run the binary
CMD ["./main"]