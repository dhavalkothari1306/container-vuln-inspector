"""Scan report parsers for Trivy, Grype, Snyk, and SARIF."""

from .loader import discover_reports, load_all_reports

__all__ = ["discover_reports", "load_all_reports"]
