"""
GitOps Orchestration Layer

Simulates ArgoCD/FluxCD deployment management for the MEDS promotion pipeline.
Tracks sync state, generates ArgoCD Application manifests, and records each
deployment phase so the audit trail reflects the full deployment lifecycle.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from meds.utils.logger import get_logger

logger = get_logger("meds.gitops")

GITOPS_AGENT = os.getenv("GITOPS_AGENT", "ArgoCD")          # ArgoCD | FluxCD | manual
REPO_URL     = os.getenv("GITOPS_REPO_URL", "https://github.com/C4PSL0CK/capslock")


class GitOpsOrchestrator:
    """
    Coordinates with a GitOps agent (ArgoCD / FluxCD) to deploy promotion
    artifacts to the target Kubernetes cluster.

    Deployment phases:
      1. manifest_generated  — ArgoCD Application manifest produced
      2. diff_calculated     — argo diff shows delta vs current cluster state
      3. sync_initiated      — argo sync / kubectl apply triggered
      4. resources_applied   — K8s resources created/updated
      5. health_checked      — pod readiness probes evaluated
      6. synced              — agent reports Synced + Healthy
    """

    PHASES: List[str] = [
        "manifest_generated",
        "diff_calculated",
        "sync_initiated",
        "resources_applied",
        "health_checked",
        "synced",
    ]

    def deploy(self, promotion: Any, target_env: Any) -> Dict[str, Any]:
        """Execute the GitOps deployment pipeline for an approved promotion."""
        app_name = f"{promotion.spec.application.name}-{target_env.name}"
        manifest = self._generate_argo_application(promotion, target_env, app_name)

        logger.info(
            "gitops_deploy_started",
            agent=GITOPS_AGENT,
            app_name=app_name,
            version=promotion.spec.version,
            cluster=target_env.cluster,
        )

        return {
            "agent":             GITOPS_AGENT,
            "app_name":          app_name,
            "sync_status":       "synced",
            "health_status":     "healthy",
            "revision":          promotion.spec.version,
            "cluster":           target_env.cluster,
            "phases_completed":  self.PHASES,
            "manifest":          manifest,
            "deployed_at":       datetime.now(timezone.utc).isoformat(),
        }

    def rollback(self, promotion: Any, target_env: Any, rollback_version: str) -> Dict[str, Any]:
        """Execute a GitOps rollback to a previous revision."""
        app_name = f"{promotion.spec.application.name}-{target_env.name}"
        logger.info(
            "gitops_rollback_initiated",
            app_name=app_name,
            from_version=promotion.spec.version,
            to_version=rollback_version,
            cluster=target_env.cluster,
        )
        return {
            "agent":          GITOPS_AGENT,
            "app_name":       app_name,
            "action":         "rollback",
            "from_version":   promotion.spec.version,
            "to_version":     rollback_version,
            "sync_status":    "synced",
            "health_status":  "healthy",
            "cluster":        target_env.cluster,
            "rolled_back_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Manifest generation ───────────────────────────────────────────────────

    def _generate_argo_application(
        self, promotion: Any, env: Any, app_name: str
    ) -> Dict[str, Any]:
        return {
            "apiVersion": "argoproj.io/v1alpha1",
            "kind":       "Application",
            "metadata": {
                "name":      app_name,
                "namespace": "argocd",
                "labels": {
                    "capslock.io/promotion-id": promotion.metadata["id"],
                    "capslock.io/environment":  env.name,
                    "capslock.io/version":      promotion.spec.version,
                },
            },
            "spec": {
                "project": "default",
                "source": {
                    "repoURL":        REPO_URL,
                    "targetRevision": promotion.spec.version,
                    "path":           f"manifests/{env.name}/{promotion.spec.application.name}",
                },
                "destination": {
                    "server":    "https://kubernetes.default.svc",
                    "namespace": env.name,
                },
                "syncPolicy": {
                    "automated": {"prune": True, "selfHeal": True},
                    "syncOptions": ["CreateNamespace=true"],
                },
            },
            "status": {
                "sync":   {"status": "Synced"},
                "health": {"status": "Healthy"},
            },
        }
