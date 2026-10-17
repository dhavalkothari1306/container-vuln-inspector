"""Parse Grype JSON vulnerability reports."""

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


def _extract_cvss(match: dict[str, Any]) -> float | None:
    vulnerability = match.get("vulnerability") or {}
    for rating in vulnerability.get("cvss") or []:
        metrics = rating.get("metrics") or {}
        score = metrics.get("baseScore")
        if score is not None:
            return float(score)
    related = match.get("relatedVulnerabilities") or []
    for item in related:
        for rating in item.get("cvss") or []:
            metrics = rating.get("metrics") or {}
            score = metrics.get("baseScore")
            if score is not None:
                return float(score)
    return None


def parse_grype(payload: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    """Normalize a Grype JSON report into vulnerability records."""
    source = payload.get("source") or {}
    target = source.get("target") or {}
    image = (
        target.get("userInput")
        or target.get("imageID")
        or source.get("name")
        or Path(source_file).stem
    )
    distro = ((payload.get("distro") or {}).get("name")) or image
    base_image = f"{distro}:{((payload.get('distro') or {}).get('version') or 'unknown')}"

    records: list[dict[str, Any]] = []
    for match in payload.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        published = vuln.get("dataSource")
        # Prefer explicit dates when present on related advisories
        for related in match.get("relatedVulnerabilities") or []:
            published = related.get("published") or published

        records.append(
            {
                "image": str(image),
                "base_image": str(base_image),
                "scanner": "grype",
                "vulnerability_id": vuln.get("id"),
                "package": artifact.get("name"),
                "installed_version": artifact.get("version"),
                "fixed_version": (vuln.get("fix") or [None])[0],
                "severity": normalize_severity(vuln.get("severity")),
                "cvss_score": _extract_cvss(match),
                "published_date": published if isinstance(published, str) and "T" in published else None,
                "package_age_days": _days_since(
                    published if isinstance(published, str) and "T" in published else None
                ),
                "title": vuln.get("description"),
                "source_file": source_file,
            }
        )
    return records
