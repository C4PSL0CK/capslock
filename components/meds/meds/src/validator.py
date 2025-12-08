from .utils import load_yaml, save_report
from .utils import report_print    # <-- Use your renamed function
from .rules import (
    check_run_as_non_root,
    check_missing_resource_limits,
    check_missing_probes,
    check_latest_tag,
    check_missing_icap_annotation,
    check_privileged_container,
    check_icap_connectivity
)

class RiskValidator:

    def __init__(self, env: str):
        self.env = env
        self.risk_score = 0
        self.reasons = []

        # Environment-specific risk thresholds
        self.thresholds = {
            "dev": 80,
            "staging": 50,
            "prod": 30
        }

    def load_manifest(self, file_path: str):
        manifest = load_yaml(file_path)
        if not manifest:
            raise Exception(f"Manifest could not be loaded: {file_path}")
        return manifest

    def run_rule(self, rule_fn, manifest):
        risky, reason, points = rule_fn(manifest)
        if risky:
            self.risk_score += points
            self.reasons.append(reason)

    def validate(self, file_path: str):
        manifest = self.load_manifest(file_path)

        # ---- Run all risk rules here ----
        self.run_rule(check_run_as_non_root, manifest)
        self.run_rule(check_missing_resource_limits, manifest)
        self.run_rule(check_missing_probes, manifest)
        self.run_rule(check_latest_tag, manifest)
        self.run_rule(check_missing_icap_annotation, manifest)
        self.run_rule(check_privileged_container, manifest)
        self.run_rule(check_icap_connectivity, manifest)

        # ---- Environment-based PASS/FAIL ----
        threshold = self.thresholds.get(self.env, 30)
        status = "PASS" if self.risk_score <= threshold else "FAIL"

        return {
            "status": status,
            "risk_score": self.risk_score,
            "risk_threshold": threshold,
            "reasons": self.reasons,
            "environment": self.env,
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Risk Validator Prototype")
    parser.add_argument("--env", type=str, required=True, help="Environment: dev/staging/prod")
    parser.add_argument("--file", type=str, required=True, help="Path to YAML manifest")

    args = parser.parse_args()

    validator = RiskValidator(env=args.env)
    result = validator.validate(file_path=args.file)

    # --- Pretty console output ---
    report_print(result)

    # --- Save JSON report to /reports/ ---
    save_report(result)

    # --- CI/CD exit codes ---
    import sys
    if result["status"] == "FAIL":
        sys.exit(1)
    else:
        sys.exit(0)
