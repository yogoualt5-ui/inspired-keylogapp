from __future__ import annotations

from typing import Iterable, List

from .fingerprint import fingerprint_target
from .matcher import matches
from .models import CVERecord, Finding, ScanReport, Target


class AuthorizationError(PermissionError):
    pass


def scan_target(target: Target, cves: Iterable[CVERecord]) -> ScanReport:
    if not target.authorized:
        raise AuthorizationError("target is not marked as authorized")

    report = ScanReport(target=target.url)
    report.fingerprints = fingerprint_target(target)

    findings: List[Finding] = []
    for fp in report.fingerprints:
        for cve in cves:
            if matches(fp, cve):
                findings.append(
                    Finding(
                        cve_id=cve.cve_id,
                        severity=cve.severity,
                        confidence=fp.confidence,
                        state="vulnerable" if fp.version != "unknown" else "possible",
                        evidence=f"product={fp.product};version={fp.version};rule={cve.affected_versions}",
                        remediation=cve.remediation,
                    )
                )

    report.findings = findings
    return report
