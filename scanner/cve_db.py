from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .models import CVERecord


def load_cve_records(path: str | Path) -> List[CVERecord]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        CVERecord(
            cve_id=item["cve_id"],
            product=item["product"],
            component=item.get("component", "core"),
            affected_versions=item["affected_versions"],
            severity=item["severity"],
            description=item["description"],
            remediation=item["remediation"],
        )
        for item in data
    ]



def merge_cve_records(*record_lists):
    by_id = {}
    for records in record_lists:
        for rec in records:
            by_id.setdefault(rec.cve_id, rec)
    return sorted(by_id.values(), key=lambda x: x.cve_id)
