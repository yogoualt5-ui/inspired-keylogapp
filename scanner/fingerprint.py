from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .models import Fingerprint, Target


SIGNATURES = [
    ("wordpress", "core", re.compile(r"wp-content|wp-includes", re.I)),
    ("joomla", "core", re.compile(r"/media/system/js|Joomla!", re.I)),
    ("drupal", "core", re.compile(r"/sites/default/files|drupal-settings-json", re.I)),
]


VERSION_PATTERNS = {
    "wordpress": re.compile(r"<meta name=\"generator\" content=\"WordPress\s*([\d.]+)", re.I),
    "joomla": re.compile(r"<meta name=\"generator\" content=\"Joomla!\s*-\s*Open Source CMS\s*([\d.]+)", re.I),
    "drupal": re.compile(r"Drupal\s*([\d.]+)", re.I),
}


class FingerprintError(RuntimeError):
    pass


def _fetch(url: str) -> Dict[str, str]:
    req = Request(url, headers={"User-Agent": "Defensive-CVE-Scanner/0.1"})
    with urlopen(req, timeout=10) as response:  # nosec B310 - user-supplied authorized target in this tool context
        body = response.read(250_000).decode("utf-8", errors="ignore")
        headers = {k.lower(): v for k, v in response.headers.items()}
    return {"body": body, "headers": str(headers)}


def fingerprint_target(target: Target) -> List[Fingerprint]:
    parsed = urlparse(target.url)
    if parsed.scheme not in {"http", "https"}:
        raise FingerprintError("target URL must start with http:// or https://")

    try:
        page = _fetch(target.url)
    except Exception as exc:  # network/runtime errors
        raise FingerprintError(f"failed to fetch target: {exc}") from exc

    body = page["body"]
    evidence = []
    fingerprints: List[Fingerprint] = []

    for product, component, sig in SIGNATURES:
        if sig.search(body):
            version = "unknown"
            version_match = VERSION_PATTERNS[product].search(body)
            confidence = "medium"
            if version_match:
                version = version_match.group(1)
                confidence = "high"
            evidence.append(f"signature:{sig.pattern}")
            fingerprints.append(
                Fingerprint(
                    product=product,
                    component=component,
                    version=version,
                    confidence=confidence,
                    evidence=";".join(evidence),
                )
            )

    return fingerprints
