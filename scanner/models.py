from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class Target:
    url: str
    authorized: bool


@dataclass
class Fingerprint:
    product: str
    component: str
    version: str
    confidence: str
    evidence: str


@dataclass
class CVERecord:
    cve_id: str
    product: str
    component: str
    affected_versions: List[str]
    severity: str
    description: str
    remediation: str


@dataclass
class Finding:
    cve_id: str
    severity: str
    confidence: str
    state: str
    evidence: str
    remediation: str


@dataclass
class ScanReport:
    target: str
    fingerprints: List[Fingerprint] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        points = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        return sum(points.get(f.severity.lower(), 0) for f in self.findings if f.state == "vulnerable")
