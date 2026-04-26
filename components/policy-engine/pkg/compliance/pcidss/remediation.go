package pcidss

import (
	"fmt"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance"
)

// GetRemediation returns detailed remediation guidance for a PCI-DSS requirement
func GetRemediation(requirementID string) (*compliance.RemediationGuidance, error) {
	// Map of all remediation guidance
	remediations := map[string]*compliance.RemediationGuidance{
		"1.2.1": {
			RuleID: "1.2.1",
			Steps: []string{
				"Verify CNI plugin supports NetworkPolicies (Calico, Cilium, Weave, etc.)",
				"Create default deny NetworkPolicy for namespace",
				"Define allowed ingress traffic rules",
				"Define allowed egress traffic rules",
				"Test connectivity to ensure applications work",
				"Document network segmentation strategy",
			},
			ExampleConfig: `# Default deny all traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-traffic
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payment-processor
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: api-gateway
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432`,
			KubectlCommands: []string{
				"kubectl get networkpolicies -n <namespace>",
				"kubectl apply -f default-deny.yaml",
				"kubectl describe networkpolicy default-deny-all -n <namespace>",
			},
			EstimatedTime: "2-3 hours",
			Priority:      "HIGH",
		},

		"2.2.2": {
			RuleID: "2.2.2",
			Steps: []string{
				"Create dedicated ServiceAccounts for each application",
				"Disable automountServiceAccountToken on default SA",
				"Update pod specifications to use dedicated SAs",
				"Remove pods using default ServiceAccount",
			},
			ExampleConfig: `# Disable default SA
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: production
automountServiceAccountToken: false
---
# Create dedicated SA
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-app-sa
  namespace: production
automountServiceAccountToken: false
---
# Use in pod
apiVersion: v1
kind: Pod
metadata:
  name: payment-processor
spec:
  serviceAccountName: payment-app-sa
  automountServiceAccountToken: false`,
			KubectlCommands: []string{
				"kubectl patch serviceaccount default -n <namespace> -p '{\"automountServiceAccountToken\": false}'",
				"kubectl create serviceaccount <app-name>-sa -n <namespace>",
			},
			EstimatedTime: "1-2 hours",
			Priority:      "HIGH",
		},

		"2.2.4": {
			RuleID: "2.2.4",
			Steps: []string{
				"Add Pod Security Standard label to namespace",
				"Review and update pod security contexts",
				"Remove privileged containers",
				"Disable hostNetwork, hostPID, hostIPC",
				"Drop all capabilities and add back only required ones",
				"Test applications with new security settings",
			},
			ExampleConfig: `# Namespace with PSS
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# Secure pod
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL`,
			KubectlCommands: []string{
				"kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=restricted",
				"kubectl get pods -n <namespace> -o jsonpath='{.items[*].spec.securityContext}'",
			},
			EstimatedTime: "3-4 hours",
			Priority:      "IMMEDIATE",
		},

		"3.4.1": {
			RuleID: "3.4.1",
			Steps: []string{
				"Create EncryptionConfiguration for etcd",
				"Configure encryption provider (aescbc or KMS)",
				"Apply encryption configuration to API server",
				"Restart API server",
				"Verify secrets are encrypted",
				"Rotate encryption keys periodically",
			},
			ExampleConfig: `# EncryptionConfiguration
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}`,
			KubectlCommands: []string{
				"kubectl get secrets -n <namespace> -o json | kubectl replace -f -",
				"kubectl get secret <secret-name> -o yaml",
			},
			EstimatedTime: "2-3 hours",
			Priority:      "IMMEDIATE",
		},

		"3.5.1": {
			RuleID: "3.5.1",
			Steps: []string{
				"Choose external secrets manager (Vault, AWS SM, Azure KV, GCP SM)",
				"Install External Secrets Operator",
				"Configure secret store connection",
				"Create SecretStore resources",
				"Migrate existing secrets to external manager",
				"Create ExternalSecret resources",
			},
			ExampleConfig: `# Install ESO
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets-system --create-namespace
---
# SecretStore for Vault
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: production
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "production-role"
---
# ExternalSecret
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: app-secrets
  data:
  - secretKey: db-password
    remoteRef:
      key: production/db
      property: password`,
			KubectlCommands: []string{
				"kubectl get secretstores -n <namespace>",
				"kubectl get externalsecrets -n <namespace>",
				"kubectl describe externalsecret <name> -n <namespace>",
			},
			EstimatedTime: "4-6 hours",
			Priority:      "IMMEDIATE",
		},

		"3.6.1": {
			RuleID: "3.6.1",
			Steps: []string{
				"Identify pods using secrets as environment variables",
				"Update pod specs to use volume mounts",
				"Remove env.valueFrom.secretKeyRef references",
				"Add volumes and volumeMounts",
				"Update application code to read from files",
				"Redeploy applications",
			},
			ExampleConfig: `# BAD - Secret as env var
spec:
  containers:
  - name: app
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: password
---
# GOOD - Secret as volume
spec:
  containers:
  - name: app
    volumeMounts:
    - name: secret-volume
      mountPath: /etc/secrets
      readOnly: true
  volumes:
  - name: secret-volume
    secret:
      secretName: db-secret
      defaultMode: 0400`,
			KubectlCommands: []string{
				"kubectl get pods -n <namespace> -o yaml | grep -A 5 'env:' | grep secretKeyRef",
			},
			EstimatedTime: "2-4 hours",
			Priority:      "MEDIUM",
		},

		"4.2.1": {
			RuleID: "4.2.1",
			Steps: []string{
				"Install service mesh (Istio or Linkerd)",
				"Enable mTLS for all services",
				"Configure TLS for Ingress resources",
				"Install cert-manager for certificate automation",
				"Create Certificate resources",
				"Verify TLS is enforced",
			},
			ExampleConfig: `# Istio strict mTLS
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
---
# Ingress with TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80`,
			KubectlCommands: []string{
				"istioctl install --set profile=production",
				"kubectl label namespace <namespace> istio-injection=enabled",
				"kubectl get certificates -n <namespace>",
			},
			EstimatedTime: "4-8 hours",
			Priority:      "IMMEDIATE",
		},

		"7.1.1": {
			RuleID: "7.1.1",
			Steps: []string{
				"Audit all Roles and RoleBindings",
				"Remove cluster-admin bindings",
				"Eliminate wildcard permissions",
				"Create least-privilege roles",
				"Bind service accounts to minimal roles",
				"Document access control decisions",
			},
			ExampleConfig: `# Least privilege role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["app-db-secret"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: production
subjects:
- kind: ServiceAccount
  name: payment-app-sa
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io`,
			KubectlCommands: []string{
				"kubectl get rolebindings -n <namespace> -o yaml",
				"kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<sa-name>",
			},
			EstimatedTime: "3-5 hours",
			Priority:      "HIGH",
		},

		"10.2.1": {
			RuleID: "10.2.1",
			Steps: []string{
				"Create comprehensive audit policy",
				"Configure API server audit flags",
				"Set audit log path and rotation",
				"Enable audit log backend",
				"Configure log forwarding to SIEM",
				"Test audit log generation",
			},
			ExampleConfig: `# Audit Policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: Metadata
  resources:
  - group: ""
    resources: ["pods", "services"]
- level: Request
  verbs: ["create", "update", "patch", "delete"]`,
			KubectlCommands: []string{
				"kubectl get pods -n kube-system | grep kube-apiserver",
				"kubectl describe pod <apiserver-pod> -n kube-system | grep audit",
			},
			EstimatedTime: "2-3 hours",
			Priority:      "HIGH",
		},
	}

	guidance, exists := remediations[requirementID]
	if !exists {
		return nil, fmt.Errorf("no remediation guidance found for requirement %s", requirementID)
	}

	return guidance, nil
}

// GetAllRemediations returns remediation guidance for all PCI-DSS requirements
func GetAllRemediations() map[string]*compliance.RemediationGuidance {
	remediations := make(map[string]*compliance.RemediationGuidance)

	// Get all requirement IDs
	requirementIDs := []string{
		"1.2.1", "2.2.2", "2.2.4", "3.4.1", "3.5.1", "3.6.1",
		"4.2.1", "5.3.2", "6.3.2", "7.1.1", "7.2.2", "8.2.1",
		"8.6.1", "10.2.1", "10.3.4", "11.4.2",
	}

	for _, reqID := range requirementIDs {
		if guidance, err := GetRemediation(reqID); err == nil {
			remediations[reqID] = guidance
		}
	}

	return remediations
}