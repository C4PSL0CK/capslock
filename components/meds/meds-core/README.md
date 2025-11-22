# MEDS Core Component

## Overview

The MEDS (Malware and Endpoint Detection Service) core component is responsible for:
- Content scanning and malware detection
- Integration with antivirus engines
- Real-time threat assessment
- Policy enforcement for content inspection

## Architecture

This component implements the core ICAP service functionality with support for:
- ClamAV integration
- Custom scanning policies
- Performance optimization
- Scalable processing

## Build and Deploy

```bash
# Build the container
docker build -t meds-core:latest .

# Deploy using Helm
helm install meds-core ./charts/
```

## Configuration

Configuration is managed through environment variables and Kubernetes ConfigMaps.
See the `charts/` directory for deployment configurations.

## Testing

Tests are located in the `../tests/` directory and can be run using:
```bash
make test
```