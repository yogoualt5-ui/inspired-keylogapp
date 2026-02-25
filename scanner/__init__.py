"""Defensive CVE scanning MVP package."""

from .models import Target, Fingerprint, CVERecord, Finding, ScanReport
from .engine import scan_target
from .github_source import owner_cves_to_records

__all__ = [
    "Target",
    "Fingerprint",
    "CVERecord",
    "Finding",
    "ScanReport",
    "scan_target",
    "owner_cves_to_records",
]
