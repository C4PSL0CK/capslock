# EAPE Quick Start for MEDS Integration

## Prerequisites
- K3s/Minikube cluster running
- kubectl configured
- Docker installed

## Deploy EAPE (5 minutes)

### Step 1: Build and Deploy
```bash
cd ~/capslock/components/policy-engine

# Run deployment script
./scripts/deploy.sh
```

### Step 2: Verify EAPE is Running
```bash
# Check pods
kubectl get pods -n capslock-system

# Check service
kubectl get svc -n capslock-system

# Expected output:
# NAME           TYPE        CLUSTER-IP      PORT(S)
# eape-service   ClusterIP   10.43.xxx.xxx   8000/TCP
```

### Step 3: Test from Inside Cluster
```bash
# Run a test pod
kubectl run curl-test --image=curlimages/curl -i --rm --restart=Never -- \
  curl http://eape-service.capslock-system:8000/

# Expected response:
# {"status":"healthy","version":"1.0.0",...}
```

---

## MEDS Integration

### Environment Variables
Add to MEDS deployment:
```yaml
env:
  - name: EAPE_API_URL
    value: "http://eape-service.capslock-system:8000"
```

### API Calls from MEDS

**1. Detect Environment**
```python
import requests

response = requests.get(
    "http://eape-service.capslock-system:8000/api/namespaces/payment-prod/environment"
)
environment_info = response.json()
print(f"Environment: {environment_info['environment']}")
print(f"Confidence: {environment_info['confidence']}")
```

**2. Apply Policy**
```python
response = requests.post(
    "http://eape-service.capslock-system:8000/api/namespaces/payment-prod/apply-policy"
)
result = response.json()
print(f"Compliant: {result['compliance_report']['overall_compliant']}")
print(f"Score: {result['compliance_report']['overall_score']}")
```

**3. Get Compliance Status**
```python
response = requests.get(
    "http://eape-service.capslock-system:8000/api/namespaces/payment-prod/compliance"
)
compliance = response.json()
print(f"Violations: {compliance['total_violations']}")
```

---

## Troubleshooting

### EAPE Pod Not Starting
```bash
# Check logs
kubectl logs -n capslock-system -l app=eape

# Check events
kubectl describe pod -n capslock-system -l app=eape
```

### Cannot Connect from MEDS
```bash
# Test DNS resolution
kubectl run dns-test --image=busybox:1.28 -i --rm --restart=Never -- \
  nslookup eape-service.capslock-system

# Test network connectivity
kubectl run curl-test --image=curlimages/curl -i --rm --restart=Never -- \
  curl -v http://eape-service.capslock-system:8000/
```

---

## Next Steps

1. ✅ Deploy EAPE using `./scripts/deploy.sh`
2. ✅ Verify with test curl commands
3. ✅ Update MEDS with `EAPE_API_URL`
4. ✅ Test MEDS → EAPE integration
5. ✅ Check compliance validation in MEDS workflow

**Questions? See `docs/INTEGRATION.md` for full API documentation.**