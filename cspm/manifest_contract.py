"""Shared contract for CSPM manifest scan findings.

The canonical finding shape is intentionally language-agnostic so the Go and
Python scanners can evolve independently without drifting on field names or
severity handling.
"""

from typing import Any, Dict, Optional

SEVERITY_LEVELS = ("critical", "high", "medium", "low")


def normalize_severity(severity: Optional[str]) -> str:
    """Return the canonical severity label used by the scanner contract."""

    if not severity:
        return "unknown"
    normalized = str(severity).strip().lower()
    return normalized if normalized in SEVERITY_LEVELS else normalized


def build_finding(
    *,
    rule_id: str,
    severity: str,
    description: str,
    remediation: str,
    resource: Optional[str] = None,
    path: Optional[str] = None,
    line_number: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a finding that matches the shared CSPM contract."""

    severity_level = normalize_severity(severity)
    finding: Dict[str, Any] = {
        "rule_id": rule_id,
        "severity": severity_level.upper() if severity_level != "unknown" else "UNKNOWN",
        "severity_level": severity_level,
        "description": description,
        "remediation": remediation,
    }

    # Backward-compatible aliases used by the current report generator and tests.
    finding["rule"] = rule_id
    finding["message"] = description

    if resource:
        finding["resource"] = resource
    if path:
        finding["path"] = path
        finding["file"] = path
    if line_number is not None:
        finding["line_number"] = line_number

    return finding


def normalize_finding(finding: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    """Normalize an incoming finding dict to the shared contract shape."""

    normalized_path = finding.get("path") or finding.get("file") or path
    return build_finding(
        rule_id=finding.get("rule_id") or finding.get("rule") or "unknown",
        severity=finding.get("severity_level") or finding.get("severity", "unknown"),
        description=finding.get("description") or finding.get("message") or "",
        remediation=finding.get("remediation", ""),
        resource=finding.get("resource"),
        path=normalized_path,
        line_number=finding.get("line_number"),
    )