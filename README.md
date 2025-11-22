# CapsLock Project

## Overview

CapsLock is a comprehensive ICAP (Internet Content Adaptation Protocol) security platform designed for enterprise-grade content inspection and malware detection. The project implements a cloud-native, microservices-based architecture with advanced policy management, service discovery, and load balancing capabilities.

## Project Structure

```text
capslock/
├── docs/                     # Project documentation
├── manifests/               # Kubernetes manifests and CRDs
├── gitops/                  # GitOps configurations (Kustomize)
├── components/              # Microservice components
│   ├── meds/               # Malware and Endpoint Detection Service
│   ├── policy-engine/      # Policy management and enforcement
│   ├── ssdlb/              # Service Discovery & Load Balancing
│   └── icap-operator/      # Kubernetes operator for ICAP services
├── infrastructure/          # Infrastructure as Code
├── cicd/                   # CI/CD pipelines and automation
└── scripts/                # Utility scripts
```

## Components

### MEDS (Malware and Endpoint Detection Service)

Core security component responsible for malware detection and content inspection using advanced scanning engines.

### Policy Engine

Manages security policies, validation rules, and conflict resolution across the ICAP infrastructure.

### SSDLB (Service Discovery & Load Balancing)

Provides intelligent service discovery and load balancing for optimal traffic distribution.

### ICAP Operator

Kubernetes operator that manages the lifecycle of ICAP services and their configurations.

## Development Environment

The project supports multiple development environments:

- **Minikube**: Local Kubernetes development
- **KIND**: Kubernetes in Docker for testing
- **Istio**: Service mesh for production-ready deployments

## Getting Started

1. Clone the repository
2. Set up your development environment using scripts in `scripts/setup/`
3. Deploy infrastructure components from `infrastructure/`
4. Use GitOps workflows from `gitops/` for application deployment

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- Architecture designs and decisions
- API documentation
- Deployment guides
- Security policies

## Contributing

Please refer to the contribution guidelines in the `docs/` directory before submitting pull requests.

## License

[License information to be added]