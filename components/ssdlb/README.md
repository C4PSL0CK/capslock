# SSDLB (Service Discovery & Load Balancing)

## Overview

The SSDLB component provides intelligent service discovery and load balancing for optimal traffic distribution across ICAP services.

## Components

- **Src**: Core service discovery and load balancing logic
- **Router**: Traffic routing and distribution algorithms
- **Metrics**: Performance monitoring and health metrics
- **Charts**: Helm deployment configurations

## Features

- Dynamic service discovery
- Multiple load balancing algorithms
- Health checking and failover
- Real-time metrics and monitoring
- Auto-scaling integration

## Build and Deploy

```bash
# Build the container
docker build -t ssdlb:latest .

# Deploy using Helm
helm install ssdlb ./charts/
```

## Configuration

SSDLB supports various load balancing strategies:

- Round Robin
- Least Connections
- Weighted Round Robin
- Health-based routing