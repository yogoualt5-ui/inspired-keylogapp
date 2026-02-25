from __future__ import annotations

from packaging.version import Version

from .models import CVERecord, Fingerprint


def _version_in_range(version: str, rule: str) -> bool:
    if version == "unknown" or rule == "unknown":
        return True

    current = Version(version)

    if rule.startswith("<="):
        return current <= Version(rule[2:])
    if rule.startswith("<"):
        return current < Version(rule[1:])
    if rule.startswith(">="):
        return current >= Version(rule[2:])
    if rule.startswith(">"):
        return current > Version(rule[1:])
    if rule.startswith("=="):
        return current == Version(rule[2:])

    return current == Version(rule)


def matches(fingerprint: Fingerprint, cve: CVERecord) -> bool:
    if fingerprint.product != cve.product or fingerprint.component != cve.component:
        return False
    return any(_version_in_range(fingerprint.version, rule) for rule in cve.affected_versions)
