# SSDLB Part 3 - Environment Setup (Fresh Machine)

Installed:
- docker.io
- kubectl
- minikube (driver=docker)
- Istio (demo profile)
- Enabled sidecar injection for default namespace
- Installed Istio addons (Prometheus etc.)

Verification commands used:
- docker ps
- kubectl get nodes
- kubectl get pods -A
- kubectl get pods -n istio-system
- kubectl get namespace default --show-labels
