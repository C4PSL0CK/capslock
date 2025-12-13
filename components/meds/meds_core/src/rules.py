def check_run_as_non_root(manifest):
    """
    Rule: If container is running as root (no runAsNonRoot: true),
    add risk points.
    """
    try:
        containers = manifest["spec"]["template"]["spec"]["containers"]
    except KeyError:
        return (True, "Manifest missing container spec", 20)

    for c in containers:
        sc = c.get("securityContext", {})
        if sc.get("runAsNonRoot", False) is not True:
            return (
                True,
                f"Container '{c['name']}' is running as root (runAsNonRoot not set to true)",
                40
            )
    return (False, "", 0)


def check_missing_resource_limits(manifest):
    """
    Rule: Containers should define resource limits.
    """
    try:
        containers = manifest["spec"]["template"]["spec"]["containers"]
    except KeyError:
        return (True, "Manifest missing container spec", 25)

    for c in containers:
        resources = c.get("resources", {})
        limits = resources.get("limits")

        if not limits:
            return (
                True,
                f"Container '{c['name']}' missing resource limits (cpu/memory)",
                30
            )
    return (False, "", 0)


def check_missing_probes(manifest):
    """
    Rule: Containers should define both readiness and liveness probes.
    """
    try:
        containers = manifest["spec"]["template"]["spec"]["containers"]
    except KeyError:
        return (True, "Manifest missing container spec", 20)

    for c in containers:
        if "livenessProbe" not in c:
            return (
                True,
                f"Container '{c['name']}' missing livenessProbe",
                20
            )

        if "readinessProbe" not in c:
            return (
                True,
                f"Container '{c['name']}' missing readinessProbe",
                15
            )

    return (False, "", 0)

def check_latest_tag(manifest):
    """
    Rule: Images should NOT use the 'latest' tag.
    """
    try:
        containers = manifest["spec"]["template"]["spec"]["containers"]
    except KeyError:
        return (True, "Manifest missing container spec", 25)

    for c in containers:
        image = c.get("image", "")
        if ":latest" in image or image.endswith(":latest"):
            return (
                True,
                f"Container '{c['name']}' is using 'latest' tag for image '{image}'",
                35
            )

    return (False, "", 0)

def check_latest_tag(manifest):
    """
    Rule: Images should NOT use the 'latest' tag.
    """
    try:
        containers = manifest["spec"]["template"]["spec"]["containers"]
    except KeyError:
        return (True, "Manifest missing container spec", 25)

    for c in containers:
        image = c.get("image", "")
        if ":latest" in image or image.endswith(":latest"):
            return (
                True,
                f"Container '{c['name']}' is using 'latest' tag for image '{image}'",
                35
            )

    return (False, "", 0)

def check_missing_icap_annotation(manifest):
    """
    Rule: ICAP scanning must be enabled via annotation.
    Required: metadata.annotations['icap.security/enabled'] == 'true'
    """
    metadata = manifest.get("metadata", {})
    annotations = metadata.get("annotations", {})

    enabled = annotations.get("icap.security/enabled")
    if enabled != "true":
        return (
            True,
            "ICAP annotation missing or disabled (icap.security/enabled != 'true')",
            45
        )

    return (False, "", 0)

def check_privileged_container(manifest):
    """
    Rule: Containers should NOT run in privileged mode.
    """
    try:
        containers = manifest["spec"]["template"]["spec"]["containers"]
    except KeyError:
        return (True, "Manifest missing container spec", 30)

    for c in containers:
        sc = c.get("securityContext", {})
        if sc.get("privileged", False) is True:
            return (
                True,
                f"Container '{c['name']}' is running as privileged",
                50
            )

    return (False, "", 0)

import requests

def check_icap_connectivity(manifest):
    """
    Rule: ICAP endpoint must be reachable for validation.
    """
    icap_url = "http://localhost:5000/icap/health"

    try:
        response = requests.get(icap_url, timeout=2)
        if response.status_code != 200:
            return (True, "ICAP service returned non-200 response", 50)

        data = response.json()
        if data.get("status") != "OK":
            return (True, "ICAP health check failed", 50)

        return (False, "", 0)

    except Exception as e:
        return (True, f"ICAP service unreachable: {e}", 50)
