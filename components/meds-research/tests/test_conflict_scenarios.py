"""
Policy Conflict Resolution — PP2 Scenarios
============================================
Tests conflict detection and resolution across multiple real-world policy
configurations. The Python conflict checker below mirrors the logic in
components/policy-engine/pkg/conflict/resolver.go so these tests run
standalone (no running services required).

Run: pytest components/meds-research/tests/test_conflict_scenarios.py -v
"""
import pytest
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Python mirror of the Go conflict resolver (resolver.go)
# ---------------------------------------------------------------------------

@dataclass
class PolicyConflict:
    type: str        # enforcement | compliance | risk_level | configuration
    severity: str    # LOW | MEDIUM | HIGH | CRITICAL
    description: str
    policy: str
    remediation: str


@dataclass
class Policy:
    name: str
    enforcement_mode: str = "permissive"   # permissive | audit | strict
    risk_level: str = "low"                # low | medium | high
    compliance_standards: List[str] = field(default_factory=list)
    pod_security_standard: str = "baseline"   # privileged | baseline | restricted
    require_network_policies: bool = False
    require_resource_limits: bool = True
    target_environment: str = "development"


def detect_conflicts(policy: Policy) -> List[PolicyConflict]:
    """Mirror of resolver.go DetectConflicts."""
    conflicts = []

    # 1. Strict enforcement + high risk
    if policy.enforcement_mode == "strict" and policy.risk_level == "high":
        conflicts.append(PolicyConflict(
            type="enforcement",
            severity="MEDIUM",
            description="Strict enforcement mode with high risk level may cause service disruptions",
            policy=policy.name,
            remediation="Consider using 'audit' mode first or lowering risk level",
        ))

    # 2. PCI-DSS without restricted pod security
    if "pci-dss" in policy.compliance_standards and policy.pod_security_standard != "restricted":
        conflicts.append(PolicyConflict(
            type="compliance",
            severity="HIGH",
            description="PCI-DSS compliance requires 'restricted' Pod Security Standard",
            policy=policy.name,
            remediation="Set pod_security_standard to 'restricted'",
        ))

    # 3. CIS or PCI-DSS without network policies
    if any(s in policy.compliance_standards for s in ["cis", "pci-dss"]):
        if not policy.require_network_policies:
            conflicts.append(PolicyConflict(
                type="compliance",
                severity="HIGH",
                description="CIS and PCI-DSS compliance require network policies",
                policy=policy.name,
                remediation="Set require_network_policies to true",
            ))

    # 4. Production without resource limits
    if not policy.require_resource_limits and policy.target_environment == "production":
        conflicts.append(PolicyConflict(
            type="configuration",
            severity="MEDIUM",
            description="Production environment should require resource limits",
            policy=policy.name,
            remediation="Set require_resource_limits to true",
        ))

    return conflicts


def _compliance_score(policy: Policy) -> float:
    """Mirror of resolver.go calculateComplianceScore."""
    score = len(policy.compliance_standards) * 10.0
    if "pci-dss" in policy.compliance_standards:
        score += 20.0
    if "cis" in policy.compliance_standards:
        score += 15.0
    if policy.pod_security_standard == "restricted":
        score += 10.0
    if policy.require_network_policies:
        score += 5.0
    if policy.require_resource_limits:
        score += 5.0
    return score


def resolve_by_compliance(p1: Policy, p2: Policy) -> tuple:
    """Returns (winning policy, reason). Mirror of resolveByCompliance."""
    s1, s2 = _compliance_score(p1), _compliance_score(p2)
    if s1 > s2:
        return p1, f"Selected {p1.name}: better compliance coverage ({s1:.0f} vs {s2:.0f})"
    elif s2 > s1:
        return p2, f"Selected {p2.name}: better compliance coverage ({s2:.0f} vs {s1:.0f})"
    # Tie: fall back to risk-based (lower risk wins)
    risk_order = {"low": 1, "medium": 2, "high": 3}
    if risk_order.get(p1.risk_level, 2) <= risk_order.get(p2.risk_level, 2):
        return p1, f"Selected {p1.name}: equal compliance, lower risk ({p1.risk_level})"
    return p2, f"Selected {p2.name}: equal compliance, lower risk ({p2.risk_level})"


def resolve_by_priority(p1: Policy, p2: Policy) -> tuple:
    """Returns (winning policy, reason). Mirror of resolveByPriority."""
    env_priority = {"production": 3, "prod": 3, "staging": 2, "stage": 2, "development": 1, "dev": 1}
    pr1 = env_priority.get(p1.target_environment, 0)
    pr2 = env_priority.get(p2.target_environment, 0)
    if pr1 >= pr2:
        return p1, f"Selected {p1.name}: higher priority ({p1.target_environment})"
    return p2, f"Selected {p2.name}: higher priority ({p2.target_environment})"


def resolve_by_risk(p1: Policy, p2: Policy) -> tuple:
    """Returns (winning policy, reason). Mirror of resolveByRisk (lower risk wins)."""
    risk_order = {"low": 1, "medium": 2, "high": 3}
    r1 = risk_order.get(p1.risk_level, 2)
    r2 = risk_order.get(p2.risk_level, 2)
    if r1 <= r2:
        return p1, f"Selected {p1.name}: lower risk ({p1.risk_level})"
    return p2, f"Selected {p2.name}: lower risk ({p2.risk_level})"


# ---------------------------------------------------------------------------
# Scenario 1: Fully compliant PCI-DSS policy — zero conflicts
# ---------------------------------------------------------------------------
class TestScenarioCompliantPolicy:
    def test_no_conflicts_for_compliant_policy(self):
        policy = Policy(
            name="pci-compliant",
            enforcement_mode="strict",
            risk_level="low",
            compliance_standards=["pci-dss", "cis"],
            pod_security_standard="restricted",
            require_network_policies=True,
            require_resource_limits=True,
            target_environment="production",
        )
        conflicts = detect_conflicts(policy)
        assert conflicts == []

    def test_audit_mode_no_enforcement_conflict(self):
        policy = Policy(
            name="audit-pci",
            enforcement_mode="audit",
            risk_level="high",
            compliance_standards=["pci-dss"],
            pod_security_standard="restricted",
            require_network_policies=True,
            require_resource_limits=True,
            target_environment="staging",
        )
        conflicts = detect_conflicts(policy)
        assert all(c.type != "enforcement" for c in conflicts)


# ---------------------------------------------------------------------------
# Scenario 2: PCI-DSS without restricted pod security
# ---------------------------------------------------------------------------
class TestScenarioPCIDSSMissingPSS:
    def test_detects_pss_conflict(self):
        policy = Policy(
            name="pci-baseline-pss",
            compliance_standards=["pci-dss"],
            pod_security_standard="baseline",
            require_network_policies=True,
            require_resource_limits=True,
        )
        conflicts = detect_conflicts(policy)
        pss_conflicts = [c for c in conflicts if "Pod Security" in c.description]
        assert len(pss_conflicts) == 1

    def test_pss_conflict_severity_high(self):
        policy = Policy(
            name="pci-privileged-pss",
            compliance_standards=["pci-dss"],
            pod_security_standard="privileged",
            require_network_policies=True,
        )
        conflicts = detect_conflicts(policy)
        pss = next(c for c in conflicts if "Pod Security" in c.description)
        assert pss.severity == "HIGH"

    def test_pss_conflict_has_remediation(self):
        policy = Policy(
            name="pci-baseline-pss",
            compliance_standards=["pci-dss"],
            pod_security_standard="baseline",
            require_network_policies=True,
        )
        conflicts = detect_conflicts(policy)
        pss = next(c for c in conflicts if "Pod Security" in c.description)
        assert "restricted" in pss.remediation


# ---------------------------------------------------------------------------
# Scenario 3: CIS without network policies
# ---------------------------------------------------------------------------
class TestScenarioCISMissingNetworkPolicies:
    def test_detects_network_policy_conflict(self):
        policy = Policy(
            name="cis-no-netpol",
            compliance_standards=["cis"],
            pod_security_standard="restricted",
            require_network_policies=False,
            require_resource_limits=True,
        )
        conflicts = detect_conflicts(policy)
        netpol_conflicts = [c for c in conflicts if "network policies" in c.description.lower()]
        assert len(netpol_conflicts) == 1

    def test_pci_dss_also_requires_network_policies(self):
        policy = Policy(
            name="pci-no-netpol",
            compliance_standards=["pci-dss"],
            pod_security_standard="restricted",
            require_network_policies=False,
        )
        conflicts = detect_conflicts(policy)
        netpol_conflicts = [c for c in conflicts if "network policies" in c.description.lower()]
        assert len(netpol_conflicts) == 1

    def test_soc2_does_not_require_network_policies(self):
        policy = Policy(
            name="soc2-no-netpol",
            compliance_standards=["soc2"],
            require_network_policies=False,
        )
        conflicts = detect_conflicts(policy)
        netpol_conflicts = [c for c in conflicts if "network policies" in c.description.lower()]
        assert netpol_conflicts == []


# ---------------------------------------------------------------------------
# Scenario 4: Multiple conflicts simultaneously
# ---------------------------------------------------------------------------
class TestScenarioMultipleConflicts:
    def test_pci_dss_three_conflicts(self):
        policy = Policy(
            name="broken-prod-policy",
            enforcement_mode="strict",
            risk_level="high",
            compliance_standards=["pci-dss"],
            pod_security_standard="baseline",      # conflict 2
            require_network_policies=False,         # conflict 3
            require_resource_limits=True,
            target_environment="production",
        )
        # enforcement (strict+high) + PSS + network = 3 conflicts
        conflicts = detect_conflicts(policy)
        assert len(conflicts) == 3

    def test_production_without_limits_plus_pci_issues(self):
        policy = Policy(
            name="worst-case-prod",
            enforcement_mode="strict",
            risk_level="high",
            compliance_standards=["pci-dss", "cis"],
            pod_security_standard="privileged",
            require_network_policies=False,
            require_resource_limits=False,
            target_environment="production",
        )
        # enforcement + PSS + network + resource limits = 4 conflicts
        conflicts = detect_conflicts(policy)
        assert len(conflicts) == 4

    def test_all_conflict_types_present(self):
        policy = Policy(
            name="all-conflict-types",
            enforcement_mode="strict",
            risk_level="high",
            compliance_standards=["pci-dss", "cis"],
            pod_security_standard="baseline",
            require_network_policies=False,
            require_resource_limits=False,
            target_environment="production",
        )
        conflicts = detect_conflicts(policy)
        types_found = {c.type for c in conflicts}
        assert "enforcement" in types_found
        assert "compliance" in types_found
        assert "configuration" in types_found


# ---------------------------------------------------------------------------
# Scenario 5: Production without resource limits
# ---------------------------------------------------------------------------
class TestScenarioProductionResourceLimits:
    def test_production_without_limits_is_conflict(self):
        policy = Policy(
            name="prod-no-limits",
            require_resource_limits=False,
            target_environment="production",
        )
        conflicts = detect_conflicts(policy)
        limit_conflicts = [c for c in conflicts if "resource limits" in c.description.lower()]
        assert len(limit_conflicts) == 1

    def test_staging_without_limits_no_conflict(self):
        policy = Policy(
            name="staging-no-limits",
            require_resource_limits=False,
            target_environment="staging",
        )
        conflicts = detect_conflicts(policy)
        limit_conflicts = [c for c in conflicts if "resource limits" in c.description.lower()]
        assert limit_conflicts == []

    def test_resource_limit_conflict_severity_medium(self):
        policy = Policy(
            name="prod-no-limits",
            require_resource_limits=False,
            target_environment="production",
        )
        conflicts = detect_conflicts(policy)
        c = next(c for c in conflicts if "resource limits" in c.description.lower())
        assert c.severity == "MEDIUM"


# ---------------------------------------------------------------------------
# Scenario 6: Enforcement vs risk conflict
# ---------------------------------------------------------------------------
class TestScenarioEnforcementConflict:
    def test_strict_with_high_risk_conflicts(self):
        policy = Policy(
            name="strict-high",
            enforcement_mode="strict",
            risk_level="high",
        )
        conflicts = detect_conflicts(policy)
        enforcement_conflicts = [c for c in conflicts if c.type == "enforcement"]
        assert len(enforcement_conflicts) == 1

    def test_strict_with_low_risk_no_conflict(self):
        policy = Policy(
            name="strict-low",
            enforcement_mode="strict",
            risk_level="low",
        )
        conflicts = detect_conflicts(policy)
        enforcement_conflicts = [c for c in conflicts if c.type == "enforcement"]
        assert enforcement_conflicts == []

    def test_audit_with_high_risk_no_conflict(self):
        policy = Policy(
            name="audit-high",
            enforcement_mode="audit",
            risk_level="high",
        )
        conflicts = detect_conflicts(policy)
        enforcement_conflicts = [c for c in conflicts if c.type == "enforcement"]
        assert enforcement_conflicts == []


# ---------------------------------------------------------------------------
# Scenario 7: Resolution — compliance-aware strategy
# ---------------------------------------------------------------------------
class TestScenarioResolutionCompliance:
    def test_pci_policy_wins_over_basic(self):
        basic = Policy(
            name="basic-policy",
            compliance_standards=[],
            pod_security_standard="baseline",
            require_network_policies=False,
            require_resource_limits=False,
        )
        pci = Policy(
            name="pci-policy",
            compliance_standards=["pci-dss"],
            pod_security_standard="restricted",
            require_network_policies=True,
            require_resource_limits=True,
        )
        winner, reason = resolve_by_compliance(basic, pci)
        assert winner.name == "pci-policy"
        assert "pci-policy" in reason

    def test_restricted_pss_beats_baseline(self):
        baseline = Policy(name="baseline-pol", compliance_standards=["soc2"], pod_security_standard="baseline")
        restricted = Policy(name="restricted-pol", compliance_standards=["soc2"], pod_security_standard="restricted")
        winner, _ = resolve_by_compliance(baseline, restricted)
        assert winner.name == "restricted-pol"

    def test_tie_broken_by_lower_risk(self):
        p1 = Policy(name="p1", compliance_standards=[], risk_level="high")
        p2 = Policy(name="p2", compliance_standards=[], risk_level="low")
        winner, reason = resolve_by_compliance(p1, p2)
        assert winner.name == "p2"
        assert "lower risk" in reason

    def test_cis_and_pci_wins_over_pci_alone(self):
        pci_only = Policy(name="pci-only", compliance_standards=["pci-dss"], pod_security_standard="restricted",
                          require_network_policies=True, require_resource_limits=True)
        pci_and_cis = Policy(name="pci-cis", compliance_standards=["pci-dss", "cis"], pod_security_standard="restricted",
                             require_network_policies=True, require_resource_limits=True)
        winner, _ = resolve_by_compliance(pci_only, pci_and_cis)
        assert winner.name == "pci-cis"


# ---------------------------------------------------------------------------
# Scenario 8: Resolution — priority-based (prod > staging > dev)
# ---------------------------------------------------------------------------
class TestScenarioResolutionPriority:
    def test_prod_wins_over_staging(self):
        prod = Policy(name="prod-policy", target_environment="production")
        staging = Policy(name="staging-policy", target_environment="staging")
        winner, reason = resolve_by_priority(prod, staging)
        assert winner.name == "prod-policy"

    def test_staging_wins_over_dev(self):
        staging = Policy(name="staging-policy", target_environment="staging")
        dev = Policy(name="dev-policy", target_environment="development")
        winner, _ = resolve_by_priority(staging, dev)
        assert winner.name == "staging-policy"

    def test_prod_wins_over_dev(self):
        prod = Policy(name="prod-policy", target_environment="production")
        dev = Policy(name="dev-policy", target_environment="development")
        winner, _ = resolve_by_priority(prod, dev)
        assert winner.name == "prod-policy"


# ---------------------------------------------------------------------------
# Scenario 9: Resolution — risk-based (lower risk wins)
# ---------------------------------------------------------------------------
class TestScenarioResolutionRisk:
    def test_low_risk_beats_high_risk(self):
        low = Policy(name="low-risk", risk_level="low")
        high = Policy(name="high-risk", risk_level="high")
        winner, reason = resolve_by_risk(low, high)
        assert winner.name == "low-risk"

    def test_low_risk_beats_medium_risk(self):
        low = Policy(name="low-risk", risk_level="low")
        medium = Policy(name="medium-risk", risk_level="medium")
        winner, _ = resolve_by_risk(low, medium)
        assert winner.name == "low-risk"

    def test_equal_risk_returns_first(self):
        p1 = Policy(name="p1", risk_level="medium")
        p2 = Policy(name="p2", risk_level="medium")
        winner, _ = resolve_by_risk(p1, p2)
        assert winner.name == "p1"


# ---------------------------------------------------------------------------
# Scenario 10: Compliance score calculation
# ---------------------------------------------------------------------------
class TestComplianceScoreCalculation:
    def test_empty_policy_base_score(self):
        p = Policy(name="empty", compliance_standards=[], pod_security_standard="baseline",
                   require_network_policies=False, require_resource_limits=False)
        assert _compliance_score(p) == 0.0

    def test_each_standard_adds_10(self):
        p1 = Policy(name="one", compliance_standards=["soc2"])
        p2 = Policy(name="two", compliance_standards=["soc2", "iso27001"])
        assert _compliance_score(p2) - _compliance_score(p1) == 10.0

    def test_pci_dss_bonus_20(self):
        without = Policy(name="without", compliance_standards=["soc2"])
        with_pci = Policy(name="with", compliance_standards=["soc2", "pci-dss"])
        # pci-dss adds 10 (per standard) + 20 (bonus) = 30 more
        assert _compliance_score(with_pci) - _compliance_score(without) == 30.0

    def test_restricted_pss_adds_10(self):
        baseline = Policy(name="baseline", pod_security_standard="baseline")
        restricted = Policy(name="restricted", pod_security_standard="restricted")
        assert _compliance_score(restricted) - _compliance_score(baseline) == 10.0

    def test_network_policies_add_5(self):
        without = Policy(name="without", require_network_policies=False)
        with_netpol = Policy(name="with", require_network_policies=True)
        assert _compliance_score(with_netpol) - _compliance_score(without) == 5.0
