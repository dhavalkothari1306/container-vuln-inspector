"""Vulnerability analytics and risk scoring."""

from .risk_scoring import (
    aggregate_by_severity,
    compute_image_risk_scores,
    cvss_summary,
    prepare_package_age_frame,
)

__all__ = [
    "aggregate_by_severity",
    "compute_image_risk_scores",
    "cvss_summary",
    "prepare_package_age_frame",
]
