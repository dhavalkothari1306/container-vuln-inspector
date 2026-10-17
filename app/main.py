"""Streamlit dashboard for Container Vulnerability & Supply Chain Inspector."""

from __future__ import annotations

import sys
from pathlib import Path

# Streamlit runs this file as a script; ensure project root is importable.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

from app.analytics.risk_scoring import (
    aggregate_by_severity,
    compute_image_risk_scores,
    cvss_summary,
    prepare_package_age_frame,
)
from app.parsers.loader import DEFAULT_INTAKE, discover_reports, load_all_reports
from app.viz.charts import base_image_severity_bar, package_age_vs_cvss_scatter

st.set_page_config(
    page_title="Supply Chain Inspector",
    page_icon=":shield:",
    layout="wide",
)


def main() -> None:
    st.title("Container Vulnerability & Software Supply Chain Inspector")
    st.caption(
        "Aggregate Trivy / Grype / Snyk (JSON or SARIF) scan results into "
        "actionable risk scores before production rollouts."
    )

    intake = Path(st.sidebar.text_input("Data intake directory", value=str(DEFAULT_INTAKE)))
    st.sidebar.markdown(
        "CI deposits scan artifacts into this folder. "
        "Drop `.json` / `.sarif` files here or run the GitHub Actions workflow."
    )

    reports = discover_reports(intake)
    st.sidebar.write(f"**Reports found:** {len(reports)}")
    for path in reports:
        st.sidebar.code(path.name, language=None)

    if st.sidebar.button("Reload reports", use_container_width=True):
        st.cache_data.clear()

    @st.cache_data(show_spinner="Loading scan reports…")
    def _cached_load(intake_str: str, report_names: tuple[str, ...]):
        return load_all_reports(intake_str)

    df = _cached_load(str(intake), tuple(p.name for p in reports))

    if df.empty:
        st.warning(
            f"No vulnerabilities parsed from `{intake}`. "
            "Add sample reports under `data/intake/` or run the CI scan workflow."
        )
        st.stop()

    risk = compute_image_risk_scores(df)
    severity = aggregate_by_severity(df)
    cvss = cvss_summary(df)
    age = prepare_package_age_frame(df)

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Images scanned", int(risk["image"].nunique()))
    k2.metric("Total vulnerabilities", int(len(df)))
    k3.metric("Max risk score", f"{risk['risk_score'].max():.1f}")
    blocked = int((risk["gate"] == "BLOCK").sum())
    k4.metric("Blocked rollouts", blocked)

    st.subheader("Pre-rollout risk gates")
    st.dataframe(
        risk[
            [
                "gate",
                "image",
                "base_image",
                "scanner",
                "vuln_count",
                "weighted_severity",
                "cvss_max",
                "cvss_mean",
                "risk_score",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    left, right = st.columns(2)
    with left:
        st.plotly_chart(base_image_severity_bar(severity), use_container_width=True)
    with right:
        st.plotly_chart(package_age_vs_cvss_scatter(age), use_container_width=True)

    with st.expander("CVSS aggregation"):
        st.dataframe(cvss.round(2), use_container_width=True, hide_index=True)

    with st.expander("Severity breakdown"):
        st.dataframe(severity, use_container_width=True, hide_index=True)

    with st.expander("Normalized vulnerability records"):
        st.dataframe(df, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
