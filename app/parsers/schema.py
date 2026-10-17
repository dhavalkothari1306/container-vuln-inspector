"""Normalized vulnerability record schema shared across scanners."""

from __future__ import annotations

from typing import Any

import pandas as pd

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
    "UNKNOWN": 0.25,
}

COLUMNS = [
    "image",
    "base_image",
    "scanner",
    "vulnerability_id",
    "package",
    "installed_version",
    "fixed_version",
    "severity",
    "cvss_score",
    "published_date",
    "package_age_days",
    "title",
    "source_file",
]


def normalize_severity(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    text = str(value).strip().upper()
    aliases = {
        "CRIT": "CRITICAL",
        "ERROR": "HIGH",
        "WARN": "MEDIUM",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "NEGLIGIBLE": "LOW",
        "MODERATE": "MEDIUM",
    }
    text = aliases.get(text, text)
    return text if text in SEVERITY_WEIGHTS else "UNKNOWN"


def empty_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=COLUMNS)


def records_to_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    if not records:
        return empty_frame()
    df = pd.DataFrame(records)
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[COLUMNS].copy()
    df["severity"] = df["severity"].map(normalize_severity)
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["package_age_days"] = pd.to_numeric(df["package_age_days"], errors="coerce")
    return df
