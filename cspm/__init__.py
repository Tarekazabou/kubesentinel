"""
KubeSentinel CSPM Module

Cloud Security Posture Management - Static analysis of Kubernetes manifests
"""

from cspm.manifest_scanner import ManifestScanner, scan_directory
from cspm.report_generator import ReportGenerator

__version__ = "0.1.0"
__all__ = ["ManifestScanner", "ReportGenerator", "scan_directory"]
