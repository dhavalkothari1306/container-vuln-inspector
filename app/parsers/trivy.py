"""Parse Trivy JSON and SARIF-like vulnerability reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schema import normalize_severity


def _days_since(date_str: str | None) -> float | None:
    if not date_str:
        return None
    try:
        published = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - published).total_seconds() / 86400.0, 0.0)
    except (ValueError, TypeError):
        return None


def _extract_cvss(vuln: dict[str, Any]) -> float | None:
    cvss = vuln.get("CVSS") or {}
    for vendor in ("nvd", "redhat", "ghsa", "bitnami"):
        block = cvss.get(vendor) or {}
        score = block.get("V3Score") or block.get("V2Score")
        if score is not None:
            return float(score)
    for key in ("CVSSScore", "Score", "SeverityScore"):
        if vuln.get(key) is not None:
            try:
                return float(vuln[key])
            except (TypeError, ValueError):
                pass
    return None


def _image_meta(payload: dict[str, Any], source_file: str) -> tuple[str, str]:
    artifact = payload.get("ArtifactName") or Path(source_file).stem
    metadata = payload.get("Metadata") or {}
    base = (
        metadata.get("ImageConfig", {}).get("os", {}).get("name")
        or metadata.get("OS", {}).get("Family")
        or metadata.get("RepoTags", [None])[0]
        or artifact
    )
    if isinstance(base, list):
        base = base[0] if base else artifact
    return str(artifact), str(base)


def parse_trivy(payload: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    """Normalize a Trivy JSON report into vulnerability records."""
    image, base_image = _image_meta(payload, source_file)
    records: list[dict[str, Any]] = []

    for result in payload.get("Results") or []:
        target = result.get("Target") or image
        for vuln in result.get("Vulnerabilities") or []:
            published = vuln.get("PublishedDate") or vuln.get("LastModifiedDate")
            records.append(
                {
                    "image": image,
                    "base_image": base_image if base_image else target,
                    "scanner": "trivy",
                    "vulnerability_id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "severity": normalize_severity(vuln.get("Severity")),
                    "cvss_score": _extract_cvss(vuln),
                    "published_date": published,
                    "package_age_days": _days_since(published),
                    "title": vuln.get("Title") or vuln.get("Description"),
                    "source_file": source_file,
                }
            )
    return records
