import pytest

from scanner.engine import AuthorizationError, scan_target
from scanner.models import CVERecord, Fingerprint, Target


def test_requires_authorization():
    with pytest.raises(AuthorizationError):
        scan_target(Target(url="https://example.com", authorized=False), [])


def test_creates_findings(monkeypatch):
    def fake_fingerprint(_target):
        return [
            Fingerprint(
                product="wordpress",
                component="core",
                version="6.4.2",
                confidence="high",
                evidence="sig",
            )
        ]

    monkeypatch.setattr("scanner.engine.fingerprint_target", fake_fingerprint)

    report = scan_target(
        Target(url="https://example.com", authorized=True),
        [
            CVERecord(
                cve_id="CVE-2023-12345",
                product="wordpress",
                component="core",
                affected_versions=["<6.4.3"],
                severity="high",
                description="x",
                remediation="update",
            )
        ],
    )

    assert len(report.findings) == 1
    assert report.findings[0].cve_id == "CVE-2023-12345"
