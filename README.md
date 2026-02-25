# Defensive CVE Scanner MVP

A **defensive**, authorization-gated scanner prototype that:
- fingerprints common CMS platforms (WordPress/Joomla/Drupal)
- matches detected versions against a normalized CVE dataset
- can ingest CVE references from a GitHub owner’s repositories (e.g., `Nxploited`) as supplemental intel
- outputs JSON findings with remediation guidance

## Safety and intended use

This project is for **authorized security assessments only**. You must have explicit permission to scan targets.
The CLI enforces an authorization flag (`--authorized`) to prevent accidental misuse.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m scanner.cli --target https://example.com --authorized
```

### Use GitHub owner as CVE source metadata/files

```bash
# Optionally set token to improve API limits
export GITHUB_TOKEN=ghp_xxx

python -m scanner.cli \
  --target https://your-authorized-site.tld \
  --authorized \
  --github-owner Nxploited \
  --github-max-repos 500
```

Default GitHub ingestion behavior:
- Includes archived and non-archived repositories.
- Extracts CVEs from repo metadata (`name`, `description`, `topics`) and common files (`README.md`, `SECURITY.md`, `ADVISORY.md`, `CHANGELOG.md`).

Optional flags:
- `--exclude-archived`: skip archived repositories.
- `--metadata-only`: skip repository file extraction and only use metadata.

Notes:
- GitHub ingestion extracts CVE IDs from text sources and does **not** run exploit code or execute payloads from repositories.
- Records from GitHub source are merged with local CVE JSON by `cve_id`.

## Project layout

- `scanner/fingerprint.py`: lightweight passive CMS fingerprinting
- `scanner/cve_db.py`: load and merge normalized CVE records
- `scanner/github_source.py`: GitHub owner CVE metadata/file ingestion
- `scanner/matcher.py`: version rule matching
- `scanner/engine.py`: authorization gate + scan orchestration
- `scanner/cli.py`: command-line interface
- `data/sample_cves.json`: demo CVE dataset

## Next suggested upgrades

1. Add real CVE enrichment from NVD/GHSA APIs by CVE ID.
2. Add plugin/theme/module fingerprinting.
3. Add per-check safe verification logic (non-destructive).
4. Add scheduler + persistent database + dashboard.
