"""Discover and load scan reports from the data intake directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from .grype import parse_grype
from .sarif import parse_sarif
from .schema import empty_frame, records_to_frame
from .snyk import parse_snyk
from .trivy import parse_trivy

DEFAULT_INTAKE = Path(__file__).resolve().parents[2] / "data" / "intake"


def discover_reports(intake_dir: Path | str | None = None) -> list[Path]:
    root = Path(intake_dir) if intake_dir else DEFAULT_INTAKE
    if not root.exists():
        return []
    files = sorted(root.glob("*.json")) + sorted(root.glob("*.sarif"))
    return [p for p in files if p.is_file()]


def _detect_format(payload: dict[str, Any], path: Path) -> str:
    name = path.name.lower()
    if "$schema" in payload and "sarif" in str(payload.get("$schema", "")).lower():
        return "sarif"
    if "runs" in payload and isinstance(payload.get("runs"), list):
        return "sarif"
    if "matches" in payload and "source" in payload:
        return "grype"
    if "Results" in payload or "ArtifactName" in payload:
        return "trivy"
    if "vulnerabilities" in payload or "docker" in payload:
        return "snyk"
    if "trivy" in name:
        return "trivy"
    if "grype" in name:
        return "grype"
    if "snyk" in name:
        return "snyk"
    if path.suffix.lower() == ".sarif":
        return "sarif"
    return "unknown"


def parse_report(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    fmt = _detect_format(payload, path)
    source = str(path)
    if fmt == "trivy":
        return parse_trivy(payload, source)
    if fmt == "grype":
        return parse_grype(payload, source)
    if fmt == "snyk":
        return parse_snyk(payload, source)
    if fmt == "sarif":
        return parse_sarif(payload, source)
    return []


def load_all_reports(intake_dir: Path | str | None = None) -> pd.DataFrame:
    """Load every supported report under the intake directory into one frame."""
    paths = discover_reports(intake_dir)
    records: list[dict[str, Any]] = []
    for path in paths:
        try:
            records.extend(parse_report(path))
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            continue
    if not records:
        return empty_frame()
    return records_to_frame(records)
