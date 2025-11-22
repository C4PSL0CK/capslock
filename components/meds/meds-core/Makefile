# MEDS Core Makefile

.PHONY: build test clean run docker-build docker-run

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=meds-core
BINARY_UNIX=$(BINARY_NAME)_unix

# Build the binary
build:
	$(GOBUILD) -o $(BINARY_NAME) -v ./src/

# Test the application
test:
	$(GOTEST) -v ./...

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

# Run the application
run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./src/
	./$(BINARY_NAME)

# Cross compilation for Linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v ./src/

# Docker commands
docker-build:
	docker build -t meds-core:latest .

docker-run:
	docker run -p 8080:8080 meds-core:latest

# Development dependencies
deps:
	$(GOGET) github.com/gorilla/mux
	$(GOGET) github.com/sirupsen/logrus

# Helm commands
helm-install:
	helm install meds-core ./charts/

helm-upgrade:
	helm upgrade meds-core ./charts/

helm-uninstall:
	helm uninstall meds-core