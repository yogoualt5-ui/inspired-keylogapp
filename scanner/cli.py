from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from .cve_db import load_cve_records, merge_cve_records
from .engine import AuthorizationError, scan_target
from .fingerprint import FingerprintError
from .github_source import owner_cves_to_records
from .models import Target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive authorized-target CVE scanner MVP")
    parser.add_argument("--target", required=True, help="Target URL (http/https)")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you are authorized to scan this target",
    )
    parser.add_argument(
        "--cve-db",
        default="data/sample_cves.json",
        help="Path to normalized CVE JSON",
    )
    parser.add_argument(
        "--github-owner",
        default="",
        help="Optional GitHub owner to harvest CVE IDs from repo metadata/files (e.g., Nxploited)",
    )
    parser.add_argument(
        "--github-max-repos",
        type=int,
        default=200,
        help="Max repositories to inspect from GitHub owner",
    )
    parser.add_argument(
        "--exclude-archived",
        action="store_true",
        help="Exclude archived repositories from GitHub CVE ingestion",
    )
    parser.add_argument(
        "--metadata-only",
        action="store_true",
        help="Only parse repo metadata (skip README/advisory file extraction)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    target = Target(url=args.target, authorized=args.authorized)
    local_cves = load_cve_records(args.cve_db)

    github_cves = []
    if args.github_owner:
        token = os.getenv("GITHUB_TOKEN")
        try:
            github_cves = owner_cves_to_records(
                owner=args.github_owner,
                max_repos=args.github_max_repos,
                token=token,
                include_archived=not args.exclude_archived,
                include_file_cves=not args.metadata_only,
            )
        except Exception as exc:
            print(f"warning: failed to load GitHub owner CVEs: {exc}", file=sys.stderr)

    cves = merge_cve_records(local_cves, github_cves)

    try:
        report = scan_target(target, cves)
    except (AuthorizationError, FingerprintError) as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(asdict(report), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
