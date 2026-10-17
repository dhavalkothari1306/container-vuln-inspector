"""plotly.express charts for supply-chain vulnerability insights."""

from __future__ import annotations

import pandas as pd
import plotly.express as px

from app.parsers.schema import SEVERITY_ORDER

SEVERITY_COLORS = {
    "CRITICAL": "#9B1C1C",
    "HIGH": "#C2410C",
    "MEDIUM": "#CA8A04",
    "LOW": "#2563EB",
    "UNKNOWN": "#6B7280",
}


def base_image_severity_bar(severity_df: pd.DataFrame):
    """Horizontal stacked bar comparing base-image vulnerability severity counts."""
    if severity_df.empty:
        fig = px.bar(title="No vulnerability data loaded")
        fig.update_layout(template="plotly_white")
        return fig

    present = [s for s in SEVERITY_ORDER if s in severity_df.columns]
    melted = severity_df.melt(
        id_vars=["image", "base_image"],
        value_vars=present,
        var_name="severity",
        value_name="count",
    )
    melted["label"] = melted["base_image"].astype(str) + " ← " + melted["image"].astype(str)

    fig = px.bar(
        melted,
        x="count",
        y="label",
        color="severity",
        orientation="h",
        color_discrete_map=SEVERITY_COLORS,
        category_orders={"severity": SEVERITY_ORDER},
        title="Base Image Vulnerabilities by Severity",
        labels={"count": "Vulnerability count", "label": "Base image / image"},
    )
    fig.update_layout(
        template="plotly_white",
        barmode="stack",
        legend_title_text="Severity",
        yaxis={"categoryorder": "total ascending"},
        margin=dict(l=20, r=20, t=60, b=20),
        height=max(360, 48 * melted["label"].nunique()),
    )
    return fig


def package_age_vs_cvss_scatter(age_df: pd.DataFrame):
    """Scatter correlating package advisory age with CVSS severity."""
    if age_df.empty:
        fig = px.scatter(title="No package age / CVSS pairs available")
        fig.update_layout(template="plotly_white")
        return fig

    fig = px.scatter(
        age_df,
        x="package_age_days",
        y="cvss_score",
        color="severity",
        hover_data=["package", "vulnerability_id", "image", "base_image"],
        color_discrete_map=SEVERITY_COLORS,
        category_orders={"severity": SEVERITY_ORDER},
        title="Package Age vs CVSS Severity",
        labels={
            "package_age_days": "Days since advisory published",
            "cvss_score": "CVSS score",
        },
        size_max=14,
    )
    fig.update_traces(marker=dict(size=11, opacity=0.8, line=dict(width=0.5, color="#111")))
    fig.update_layout(
        template="plotly_white",
        legend_title_text="Severity",
        margin=dict(l=20, r=20, t=60, b=20),
        height=480,
    )
    return fig
