"""Parse Snyk container / open-source JSON vulnerability reports."""

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
    for key in ("cvssScore", "CVSSv3", "cvssv3", "score"):
        value = vuln.get(key)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
    return None


def parse_snyk(payload: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    """Normalize a Snyk JSON report into vulnerability records."""
    docker = payload.get("docker") or {}
    image = (
        payload.get("image")
        or docker.get("baseImage")
        or payload.get("projectName")
        or Path(source_file).stem
    )
    base_image = docker.get("baseImage") or image

    vulns = payload.get("vulnerabilities") or []
    if not vulns and isinstance(payload.get("applications"), list):
        for app in payload["applications"]:
            vulns.extend(app.get("vulnerabilities") or [])

    records: list[dict[str, Any]] = []
    for vuln in vulns:
        identifiers = vuln.get("identifiers") or {}
        cve_list = identifiers.get("CVE") or []
        vuln_id = cve_list[0] if cve_list else vuln.get("id")
        published = vuln.get("publicationTime") or vuln.get("disclosureTime")
        pkg = vuln.get("packageName") or vuln.get("name") or vuln.get("package")

        records.append(
            {
                "image": str(image),
                "base_image": str(base_image),
                "scanner": "snyk",
                "vulnerability_id": vuln_id,
                "package": pkg,
                "installed_version": vuln.get("version") or vuln.get("packageVersion"),
                "fixed_version": (
                    (vuln.get("fixedIn") or [None])[0]
                    if isinstance(vuln.get("fixedIn"), list)
                    else vuln.get("fixedIn")
                ),
                "severity": normalize_severity(vuln.get("severity")),
                "cvss_score": _extract_cvss(vuln),
                "published_date": published,
                "package_age_days": _days_since(published),
                "title": vuln.get("title"),
                "source_file": source_file,
            }
        )
    return records
