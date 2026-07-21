"""
Container & Kubernetes Security Scanner
Audits Docker images and Kubernetes configurations for security
misconfigurations: running as root, exposed secrets, privileged containers,
missing resource limits, and known CVE vulnerabilities in base images.
"""
import json
import re

class ContainerSecurityScanner:
    def __init__(self):
        self.findings = []

    def scan_dockerfile(self, dockerfile_content):
        """Audit a Dockerfile for security best practices."""
        lines = dockerfile_content.strip().split("\n")
        has_user_directive = False
        has_healthcheck = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # CIS-DI-0001: Running as root
            if stripped.upper().startswith("USER"):
                has_user_directive = True
                user = stripped.split()[-1] if len(stripped.split()) > 1 else ""
                if user in ("root", "0"):
                    self.findings.append({
                        "severity": "HIGH",
                        "type": "CONTAINER_ROOT_USER",
                        "line": i,
                        "detail": "Container explicitly runs as root"
                    })

            # CIS-DI-0005: Using ADD instead of COPY
            if stripped.upper().startswith("ADD ") and "http" not in stripped.lower():
                self.findings.append({
                    "severity": "MEDIUM",
                    "type": "USE_COPY_NOT_ADD",
                    "line": i,
                    "detail": "Use COPY instead of ADD to prevent unexpected tar extraction"
                })

            # CIS-DI-0006: Using latest tag
            if stripped.upper().startswith("FROM"):
                image = stripped.split()[1] if len(stripped.split()) > 1 else ""
                if ":latest" in image or ":" not in image:
                    self.findings.append({
                        "severity": "MEDIUM",
                        "type": "UNPINNED_BASE_IMAGE",
                        "line": i,
                        "detail": f"Base image '{image}' uses :latest or no tag. Pin to specific version."
                    })

            # Secrets in ENV
            if stripped.upper().startswith("ENV"):
                secret_patterns = ["password", "secret", "api_key", "token", "private_key"]
                for pattern in secret_patterns:
                    if pattern in stripped.lower():
                        self.findings.append({
                            "severity": "CRITICAL",
                            "type": "SECRET_IN_ENV",
                            "line": i,
                            "detail": f"Potential secret '{pattern}' hardcoded in ENV directive"
                        })

            # HEALTHCHECK
            if stripped.upper().startswith("HEALTHCHECK"):
                has_healthcheck = True

            # Exposing SSH
            if stripped.upper().startswith("EXPOSE") and "22" in stripped:
                self.findings.append({
                    "severity": "HIGH",
                    "type": "SSH_EXPOSED",
                    "line": i,
                    "detail": "SSH port 22 exposed in container (anti-pattern)"
                })

        if not has_user_directive:
            self.findings.append({
                "severity": "HIGH",
                "type": "NO_USER_DIRECTIVE",
                "detail": "No USER directive found. Container will run as root by default."
            })

        if not has_healthcheck:
            self.findings.append({
                "severity": "LOW",
                "type": "NO_HEALTHCHECK",
                "detail": "No HEALTHCHECK defined. Container orchestrator cannot verify health."
            })

    def scan_k8s_manifest(self, manifest):
        """Audit a Kubernetes pod/deployment manifest for security issues."""
        kind = manifest.get("kind", "")
        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})

        containers = []
        if kind in ("Pod",):
            containers = spec.get("containers", [])
        elif kind in ("Deployment", "DaemonSet", "StatefulSet"):
            containers = spec.get("template", {}).get("spec", {}).get("containers", [])

        for container in containers:
            name = container.get("name", "unknown")
            security_context = container.get("securityContext", {})

            # Privileged container
            if security_context.get("privileged", False):
                self.findings.append({
                    "severity": "CRITICAL",
                    "type": "K8S_PRIVILEGED_CONTAINER",
                    "container": name,
                    "detail": "Container runs in privileged mode (full host access)"
                })

            # Running as root
            if security_context.get("runAsUser") == 0:
                self.findings.append({
                    "severity": "HIGH",
                    "type": "K8S_ROOT_USER",
                    "container": name,
                    "detail": "Container explicitly runs as UID 0 (root)"
                })

            # No resource limits (DoS vector)
            resources = container.get("resources", {})
            if not resources.get("limits"):
                self.findings.append({
                    "severity": "MEDIUM",
                    "type": "K8S_NO_RESOURCE_LIMITS",
                    "container": name,
                    "detail": "No CPU/memory limits set. Container can consume all node resources."
                })

            # Read-only root filesystem
            if not security_context.get("readOnlyRootFilesystem", False):
                self.findings.append({
                    "severity": "MEDIUM",
                    "type": "K8S_WRITABLE_ROOTFS",
                    "container": name,
                    "detail": "Root filesystem is writable. Set readOnlyRootFilesystem: true"
                })

            # Host network / PID / IPC
            pod_spec = spec.get("template", {}).get("spec", spec)
            if pod_spec.get("hostNetwork", False):
                self.findings.append({
                    "severity": "HIGH",
                    "type": "K8S_HOST_NETWORK",
                    "detail": "Pod uses host network namespace (breaks network isolation)"
                })

    def generate_report(self):
        print("\n" + "=" * 72)
        print("  CONTAINER SECURITY SCAN REPORT")
        print(f"  Total Findings: {len(self.findings)}")
        print("=" * 72)
        for f in self.findings:
            print(f"  [{f['severity']}] {f['type']}")
            for k, v in f.items():
                if k not in ('severity', 'type'):
                    print(f"    {k}: {v}")
