from enum import Enum
from typing import Dict, List
from dataclasses import dataclass

class ComplianceFramework(Enum):
    CIS_KUBERNETES = "CIS Kubernetes Benchmark"
    PCI_DSS = "PCI DSS v4.0"
    SOC2 = "SOC 2 Type II"
    ISO27001 = "ISO/IEC 27001:2022"

@dataclass
class PolicyDefinition:
    name: str
    description: str
    category: str
    compliance_mappings: Dict[ComplianceFramework, List[str]]
    severity: str
    required_for: List[str]

POLICY_CATALOG = {
    # ── Network Security ──────────────────────────────────────────────────────
    "network-segmentation": PolicyDefinition(
        name="network-segmentation",
        description="Enforce network segmentation between pods",
        category="Network Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.3.2"],
            ComplianceFramework.PCI_DSS: ["1.2.1"],
        },
        severity="critical",
        required_for=["production"]
    ),
    "network-policy": PolicyDefinition(
        name="network-policy",
        description="Default-deny ingress/egress network policies per namespace",
        category="Network Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.3.1"],
            ComplianceFramework.PCI_DSS: ["1.3.1"],
        },
        severity="critical",
        required_for=["staging", "production"]
    ),
    "tls-enforcement": PolicyDefinition(
        name="tls-enforcement",
        description="Enforce TLS for all service-to-service communication",
        category="Network Security",
        compliance_mappings={
            ComplianceFramework.PCI_DSS: ["4.2.1"],
            ComplianceFramework.SOC2: ["CC6.7"],
        },
        severity="critical",
        required_for=["staging", "production"]
    ),
    "service-mesh-mtls": PolicyDefinition(
        name="service-mesh-mtls",
        description="Require mutual TLS via Istio service mesh for all pods",
        category="Network Security",
        compliance_mappings={
            ComplianceFramework.PCI_DSS: ["4.2.1"],
            ComplianceFramework.ISO27001: ["A.10.1"],
        },
        severity="critical",
        required_for=["production"]
    ),

    # ── Pod Security ──────────────────────────────────────────────────────────
    "pod-security-standards": PolicyDefinition(
        name="pod-security-standards",
        description="Enforce Kubernetes Pod Security Standards (restricted profile)",
        category="Pod Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.2.1"],
            ComplianceFramework.PCI_DSS: ["2.2.1"],
        },
        severity="critical",
        required_for=["staging", "production"]
    ),
    "no-privileged-containers": PolicyDefinition(
        name="no-privileged-containers",
        description="Block containers running in privileged mode",
        category="Pod Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.2.1"],
        },
        severity="critical",
        required_for=["production"]
    ),
    "read-only-root-fs": PolicyDefinition(
        name="read-only-root-fs",
        description="Enforce read-only root filesystem for all containers",
        category="Pod Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.2.6"],
            ComplianceFramework.PCI_DSS: ["2.2.1"],
        },
        severity="high",
        required_for=["production"]
    ),
    "no-host-namespaces": PolicyDefinition(
        name="no-host-namespaces",
        description="Disallow containers sharing host PID, IPC, or network namespaces",
        category="Pod Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.2.2"],
        },
        severity="high",
        required_for=["staging", "production"]
    ),

    # ── Access Control ────────────────────────────────────────────────────────
    "rbac-least-privilege": PolicyDefinition(
        name="rbac-least-privilege",
        description="Enforce RBAC least-privilege — no wildcard verbs or resources",
        category="Access Control",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.1.1"],
            ComplianceFramework.PCI_DSS: ["7.1.1"],
        },
        severity="critical",
        required_for=["production"]
    ),
    "namespace-isolation": PolicyDefinition(
        name="namespace-isolation",
        description="Enforce strict namespace isolation with resource quotas",
        category="Access Control",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.7.1"],
            ComplianceFramework.SOC2: ["CC6.3"],
        },
        severity="medium",
        required_for=["staging", "production"]
    ),

    # ── Supply Chain Security ─────────────────────────────────────────────────
    "image-scanning": PolicyDefinition(
        name="image-scanning",
        description="Require vulnerability-scanned container images (no HIGH/CRITICAL CVEs)",
        category="Supply Chain Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.2.4"],
            ComplianceFramework.PCI_DSS: ["6.3.3"],
        },
        severity="high",
        required_for=["staging", "production"]
    ),
    "container-registry": PolicyDefinition(
        name="container-registry",
        description="Allow images only from approved internal container registries",
        category="Supply Chain Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.2.4"],
            ComplianceFramework.SOC2: ["CC8.1"],
        },
        severity="high",
        required_for=["staging", "production"]
    ),

    # ── Encryption ────────────────────────────────────────────────────────────
    "secrets-encryption": PolicyDefinition(
        name="secrets-encryption",
        description="Encrypt Kubernetes Secrets at rest using KMS provider",
        category="Encryption",
        compliance_mappings={
            ComplianceFramework.PCI_DSS: ["3.4.1"],
        },
        severity="critical",
        required_for=["production"]
    ),
    "secret-rotation": PolicyDefinition(
        name="secret-rotation",
        description="Enforce automatic secret rotation every 90 days",
        category="Encryption",
        compliance_mappings={
            ComplianceFramework.PCI_DSS: ["8.3.9"],
            ComplianceFramework.SOC2: ["CC6.1"],
        },
        severity="high",
        required_for=["production"]
    ),

    # ── Resource Management ───────────────────────────────────────────────────
    "resource-limits": PolicyDefinition(
        name="resource-limits",
        description="Enforce CPU and memory resource requests and limits on all containers",
        category="Resource Management",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.2.3"],
        },
        severity="medium",
        required_for=["development", "staging", "production"]
    ),

    # ── Logging & Monitoring ──────────────────────────────────────────────────
    "audit-logging": PolicyDefinition(
        name="audit-logging",
        description="Enable Kubernetes API server audit logging",
        category="Logging",
        compliance_mappings={
            ComplianceFramework.PCI_DSS: ["10.2.1"],
        },
        severity="high",
        required_for=["production"]
    ),
    "log-forwarding": PolicyDefinition(
        name="log-forwarding",
        description="Forward all container logs to centralized logging system",
        category="Logging",
        compliance_mappings={
            ComplianceFramework.PCI_DSS: ["10.5.1"],
            ComplianceFramework.SOC2: ["CC7.2"],
        },
        severity="medium",
        required_for=["development", "staging", "production"]
    ),
}

def get_policies_for_environment(env_type: str) -> List[str]:
    return [name for name, policy in POLICY_CATALOG.items() if env_type in policy.required_for]

def get_policy_info(policy_name: str) -> Dict:
    if policy_name not in POLICY_CATALOG:
        return None
    policy = POLICY_CATALOG[policy_name]
    return {
        "name": policy.name,
        "description": policy.description,
        "category": policy.category,
        "severity": policy.severity,
        "required_for": policy.required_for,
        "compliance": {framework.value: controls for framework, controls in policy.compliance_mappings.items()}
    }
