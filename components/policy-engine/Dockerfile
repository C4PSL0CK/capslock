# Multi-stage build for EAPE Policy Engine

# Stage 1: Build Go binary
FROM golang:1.21-alpine AS go-builder

WORKDIR /build

# Copy Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/

# Build the CLI binary
RUN CGO_ENABLED=0 GOOS=linux go build -o policy-engine ./cmd/policy-engine

# Stage 2: Python API
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY api/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy Go binary from builder
COPY --from=go-builder /build/policy-engine /app/bin/policy-engine

# Copy Python API
COPY api/main.py ./

# Copy policy templates
COPY policies/ ./policies/

# Expose API port
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/bin:${PATH}"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/')"

# Run the FastAPI server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]