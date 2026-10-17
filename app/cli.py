"""CLI for loading intake reports and emitting risk gate decisions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.analytics.risk_scoring import compute_image_risk_scores
from app.parsers.loader import load_all_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate container scan reports and compute rollout risk gates."
    )
    parser.add_argument(
        "--intake",
        type=Path,
        default=Path("data/intake"),
        help="Directory containing Trivy/Grype/Snyk JSON or SARIF reports",
    )
    parser.add_argument(
        "--fail-on",
        choices=["BLOCK", "REVIEW", "NONE"],
        default="NONE",
        help="Exit non-zero when any image meets or exceeds this gate",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write risk summary JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    df = load_all_reports(args.intake)
    risk = compute_image_risk_scores(df)

    payload = {
        "intake": str(args.intake),
        "images": risk.to_dict(orient="records"),
        "summary": {
            "image_count": int(risk["image"].nunique()) if not risk.empty else 0,
            "vuln_count": int(len(df)),
            "blocked": int((risk["gate"] == "BLOCK").sum()) if not risk.empty else 0,
            "review": int((risk["gate"] == "REVIEW").sum()) if not risk.empty else 0,
            "pass": int((risk["gate"] == "PASS").sum()) if not risk.empty else 0,
        },
    }

    text = json.dumps(payload, indent=2, default=str)
    print(text)
    if args.json_out:
        args.json_out.write_text(text, encoding="utf-8")

    if risk.empty:
        return 0

    fail_rank = {"NONE": 99, "REVIEW": 1, "BLOCK": 2}
    gate_rank = {"PASS": 0, "REVIEW": 1, "BLOCK": 2}
    threshold = fail_rank[args.fail_on]
    if threshold < 99 and any(gate_rank[g] >= threshold for g in risk["gate"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
