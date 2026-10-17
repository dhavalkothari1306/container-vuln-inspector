"""pandas analytics: severity grouping, CVSS aggregation, rollout risk scores."""

from __future__ import annotations

import pandas as pd

from app.parsers.schema import SEVERITY_ORDER, SEVERITY_WEIGHTS


def aggregate_by_severity(df: pd.DataFrame) -> pd.DataFrame:
    """Count vulnerabilities by image / base image and severity."""
    if df.empty:
        return pd.DataFrame(columns=["image", "base_image", *SEVERITY_ORDER, "total"])

    working = df.copy()
    working["severity"] = pd.Categorical(
        working["severity"], categories=SEVERITY_ORDER, ordered=True
    )
    grouped = (
        working.groupby(["image", "base_image", "severity"], observed=False)
        .size()
        .unstack(fill_value=0)
        .reset_index()
    )
    for sev in SEVERITY_ORDER:
        if sev not in grouped.columns:
            grouped[sev] = 0
    grouped["total"] = grouped[SEVERITY_ORDER].sum(axis=1)
    return grouped.sort_values("total", ascending=False).reset_index(drop=True)


def cvss_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate CVSS scores per image and base image."""
    if df.empty:
        return pd.DataFrame(
            columns=[
                "image",
                "base_image",
                "vuln_count",
                "cvss_mean",
                "cvss_max",
                "cvss_median",
                "cvss_p95",
            ]
        )

    summary = (
        df.groupby(["image", "base_image"], dropna=False)
        .agg(
            vuln_count=("vulnerability_id", "count"),
            cvss_mean=("cvss_score", "mean"),
            cvss_max=("cvss_score", "max"),
            cvss_median=("cvss_score", "median"),
        )
        .reset_index()
    )
    p95 = (
        df.groupby(["image", "base_image"], dropna=False)["cvss_score"]
        .quantile(0.95)
        .reset_index(name="cvss_p95")
    )
    return summary.merge(p95, on=["image", "base_image"], how="left")


def compute_image_risk_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Produce an actionable pre-rollout risk score per image.

    score = severity-weighted count + 2 * max(CVSS) + mean(CVSS)
    gate  = BLOCK (>=70), REVIEW (>=40), PASS (<40)
    """
    if df.empty:
        return pd.DataFrame(
            columns=[
                "image",
                "base_image",
                "scanner",
                "weighted_severity",
                "cvss_max",
                "cvss_mean",
                "risk_score",
                "gate",
                "vuln_count",
            ]
        )

    working = df.copy()
    working["weight"] = working["severity"].map(SEVERITY_WEIGHTS).fillna(0.25)

    severity = (
        working.groupby(["image", "base_image"], dropna=False)["weight"]
        .sum()
        .rename("weighted_severity")
    )
    scanners = (
        working.groupby(["image", "base_image"], dropna=False)["scanner"]
        .agg(lambda s: ", ".join(sorted(set(s.dropna().astype(str)))))
        .rename("scanner")
    )
    cvss = cvss_summary(working).set_index(["image", "base_image"])
    counts = (
        working.groupby(["image", "base_image"], dropna=False)
        .size()
        .rename("vuln_count")
    )

    scored = pd.concat([severity, scanners, counts], axis=1).join(cvss[["cvss_max", "cvss_mean"]])
    scored = scored.reset_index()
    scored["cvss_max"] = scored["cvss_max"].fillna(0.0).round(2)
    scored["cvss_mean"] = scored["cvss_mean"].fillna(0.0).round(2)
    scored["weighted_severity"] = scored["weighted_severity"].round(2)
    scored["risk_score"] = (
        scored["weighted_severity"] + (2.0 * scored["cvss_max"]) + scored["cvss_mean"]
    ).round(2)

    def gate(score: float) -> str:
        if score >= 70:
            return "BLOCK"
        if score >= 40:
            return "REVIEW"
        return "PASS"

    scored["gate"] = scored["risk_score"].map(gate)
    return scored.sort_values("risk_score", ascending=False).reset_index(drop=True)


def prepare_package_age_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Rows suitable for package-age vs CVSS scatter plots."""
    if df.empty:
        return pd.DataFrame(
            columns=[
                "package",
                "vulnerability_id",
                "package_age_days",
                "cvss_score",
                "severity",
                "image",
                "base_image",
            ]
        )

    cols = [
        "package",
        "vulnerability_id",
        "package_age_days",
        "cvss_score",
        "severity",
        "image",
        "base_image",
    ]
    frame = df[cols].dropna(subset=["package_age_days", "cvss_score"]).copy()
    return frame.reset_index(drop=True)
