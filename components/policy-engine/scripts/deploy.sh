#!/bin/bash
set -e

echo "CAPSLock EAPE Deployment Script"
echo "================================"

# Configuration
IMAGE_NAME="eape-policy-engine"
IMAGE_TAG="latest"
NAMESPACE="capslock-system"

# Step 1: Build Docker Image
echo ""
echo "Step 1: Building Docker image..."
docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .

# Step 2: Load image into K3s (if using K3s)
echo ""
echo "Step 2: Loading image into K3s..."
if command -v k3s &> /dev/null; then
    docker save ${IMAGE_NAME}:${IMAGE_TAG} | sudo k3s ctr images import -
    echo "Image loaded into K3s"
else
    echo "K3s not found, skipping image import"
    echo "If using minikube: eval \$(minikube docker-env) before building"
fi

# Step 3: Create namespace
echo ""
echo "Step 3: Creating namespace..."
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# Step 4: Deploy EAPE
echo ""
echo "Step 4: Deploying EAPE..."
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Step 5: Wait for deployment
echo ""
echo "Step 5: Waiting for EAPE to be ready..."
kubectl rollout status deployment/eape-deployment -n ${NAMESPACE} --timeout=120s

# Step 6: Verify
echo ""
echo "Step 6: Verifying deployment..."
kubectl get pods -n ${NAMESPACE} -l app=eape
kubectl get svc -n ${NAMESPACE} -l app=eape

# Step 7: Get service endpoint
echo ""
echo "EAPE Service Endpoint:"
echo "  Internal: http://eape-service.${NAMESPACE}:8000"
echo ""
echo "MEDS Configuration:"
echo "  Add to MEDS environment variables:"
echo "  EAPE_API_URL=http://eape-service.${NAMESPACE}:8000"
echo ""
echo "Test connection from another pod:"
echo "  kubectl run curl-test --image=curlimages/curl -i --rm --restart=Never -- \\"
echo "    curl http://eape-service.${NAMESPACE}:8000/"
echo ""
echo "Deployment complete!"