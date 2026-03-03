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
    "pod-security-standards": PolicyDefinition(
        name="pod-security-standards",
        description="Enforce Pod Security Standards",
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
        description="Block privileged containers",
        category="Pod Security",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.2.1"],
        },
        severity="critical",
        required_for=["production"]
    ),
    "rbac-least-privilege": PolicyDefinition(
        name="rbac-least-privilege",
        description="Enforce RBAC least privilege",
        category="Access Control",
        compliance_mappings={
            ComplianceFramework.CIS_KUBERNETES: ["5.1.1"],
            ComplianceFramework.PCI_DSS: ["7.1.1"],
        },
        severity="critical",
        required_for=["production"]
    ),
    "secrets-encryption": PolicyDefinition(
        name="secrets-encryption",
        description="Encrypt secrets at rest",
        category="Encryption",
        compliance_mappings={
            ComplianceFramework.PCI_DSS: ["3.4.1"],
        },
        severity="critical",
        required_for=["production"]
    ),
    "audit-logging": PolicyDefinition(
        name="audit-logging",
        description="Enable audit logging",
        category="Logging",
        compliance_mappings={
            ComplianceFramework.PCI_DSS: ["10.2.1"],
        },
        severity="high",
        required_for=["production"]
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
