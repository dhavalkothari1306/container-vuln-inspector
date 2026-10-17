# Container Vulnerability & Software Supply Chain Inspector

Aggregate static analysis and container security scan results into **actionable risk scores** before production rollouts.

| Layer | Stack |
| --- | --- |
| Telemetry | Trivy / Grype / Snyk JSON or SARIF deposited in `data/intake/` |
| Analytics | `pandas` — severity grouping, CVSS aggregation, weighted risk gates |
| Visualization | `plotly.express` — stacked base-image bars, package-age vs CVSS scatter |
| DevOps | GitHub Actions builds an image, runs Trivy, exports JSON, deposits into intake |

## Quick start

```bash
cd container-vuln-inspector
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
# source .venv/bin/activate

pip install -r requirements.txt
streamlit run app/main.py
```

Or evaluate risk gates from the CLI (useful in CI):

```bash
python -m app.cli --intake data/intake --fail-on BLOCK --json-out risk-summary.json
```

Sample reports ship under `data/intake/sample_*.json` so the dashboard works offline.

## Risk gate model

Per image:

```
risk_score = Σ(severity_weight) + 2 × max(CVSS) + mean(CVSS)
```

| Gate | Score | Meaning |
| --- | --- | --- |
| `PASS` | &lt; 40 | Safe to promote |
| `REVIEW` | 40–69 | Needs owner sign-off |
| `BLOCK` | ≥ 70 | Halt production rollout |

Severity weights: Critical=10, High=5, Medium=2, Low=0.5.

## Data intake

Drop scanner output into `data/intake/`:

- `*.json` from Trivy, Grype, or Snyk
- `*.sarif` / SARIF JSON from Trivy or compatible tools

The loader auto-detects format and normalizes to a shared schema (`image`, `base_image`, `CVE`, `severity`, `cvss_score`, `package_age_days`, …).

## GitHub Actions integration

Workflow: [`.github/workflows/container-scan.yml`](.github/workflows/container-scan.yml)

1. Build `sample_app` Docker image
2. Scan with Trivy (JSON + SARIF)
3. Copy reports into `data/intake/ci-trivy-<sha>.*`
4. Upload artifacts for downstream jobs / local dashboard import
5. Run `python -m app.cli --fail-on BLOCK` as a soft/hard gate

To use your own image, change the build context / `image-ref` in the workflow and keep depositing JSON under `data/intake/`.

## Project layout

```
app/
  parsers/          # Trivy, Grype, Snyk, SARIF normalizers
  analytics/        # pandas risk scoring
  viz/              # plotly.express charts
  main.py           # Streamlit dashboard
  cli.py            # CI-friendly risk gate CLI
data/intake/        # Scan report drop zone (CI + local)
sample_app/         # Tiny image scanned in CI
.github/workflows/  # Container scan + intake deposit
```

## Extending

- Add a parser under `app/parsers/` and wire it in `loader._detect_format`
- Tune gate thresholds in `app/analytics/risk_scoring.py`
- Point the Streamlit sidebar at a shared intake volume / artifact download directory
