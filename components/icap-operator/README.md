# ICAP Operator

## Overview

Kubernetes operator that manages the lifecycle of ICAP services and their configurations.

## Components

- **Cmd**: Main operator entry point and CLI
- **Config**: Configuration files and manifests
- **Controllers**: Custom resource controllers
- **API**: Custom resource definitions and API types
- **Charts**: Helm deployment configurations

## Features

- Automated ICAP service deployment
- Configuration management
- Health monitoring and recovery
- Scaling and resource optimization
- Integration with Kubernetes ecosystem

## Build and Deploy

```bash
# Build the operator
make build

# Deploy using Helm
helm install icap-operator ./charts/
```

## Custom Resources

The operator manages several custom resources:

- IcapService: ICAP service definitions
- IcapPolicy: Policy configurations
- IcapEndpoint: Service endpoint management

## Development

```bash
# Run locally
make run

# Run tests
make test

# Generate manifests
make manifests
```