"""Parse SARIF vulnerability reports (Trivy/Snyk/CodeQL-compatible)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .schema import normalize_severity

_SEVERITY_LEVEL = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "LOW",
}


def parse_sarif(payload: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    """Normalize a SARIF document into vulnerability records."""
    runs = payload.get("runs") or []
    records: list[dict[str, Any]] = []

    for run in runs:
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name") or "sarif"
        rules = {
            rule.get("id"): rule
            for rule in (((run.get("tool") or {}).get("driver") or {}).get("rules") or [])
            if rule.get("id")
        }
        artifacts = run.get("artifacts") or []
        image = Path(source_file).stem
        if artifacts:
            loc = (artifacts[0].get("location") or {}).get("uri")
            if loc:
                image = loc

        for result in run.get("results") or []:
            rule_id = result.get("ruleId")
            rule = rules.get(rule_id) or {}
            props = result.get("properties") or {}
            rule_props = rule.get("properties") or {}

            severity = (
                props.get("security-severity")
                or props.get("severity")
                or rule_props.get("security-severity")
                or rule_props.get("severity")
                or _SEVERITY_LEVEL.get(str(result.get("level", "")).lower())
            )
            cvss = props.get("cvss") or rule_props.get("cvss")
            try:
                cvss_score = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss_score = None

            # Map numeric SARIF security-severity (0-10) when text severity missing
            if cvss_score is None:
                try:
                    cvss_score = float(severity)
                    if cvss_score >= 9:
                        severity = "CRITICAL"
                    elif cvss_score >= 7:
                        severity = "HIGH"
                    elif cvss_score >= 4:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                except (TypeError, ValueError):
                    pass

            package = props.get("package") or props.get("artifact") or rule_props.get("package")
            version = props.get("version") or props.get("installedVersion")

            records.append(
                {
                    "image": str(image),
                    "base_image": str(props.get("baseImage") or image),
                    "scanner": str(tool).lower(),
                    "vulnerability_id": rule_id or props.get("cve"),
                    "package": package,
                    "installed_version": version,
                    "fixed_version": props.get("fixedVersion"),
                    "severity": normalize_severity(severity),
                    "cvss_score": cvss_score,
                    "published_date": props.get("publishedDate"),
                    "package_age_days": props.get("packageAgeDays"),
                    "title": (result.get("message") or {}).get("text") or rule.get("name"),
                    "source_file": source_file,
                }
            )
    return records
