from scanner.cve_db import merge_cve_records
from scanner.models import CVERecord


def test_merge_cve_records_deduplicates_by_cve_id():
    a = CVERecord("CVE-2024-0001", "wordpress", "core", ["<6.0"], "high", "a", "r")
    b = CVERecord("CVE-2024-0001", "joomla", "core", ["<4.0"], "critical", "b", "r")
    c = CVERecord("CVE-2024-0002", "drupal", "core", ["<10.0"], "medium", "c", "r")

    merged = merge_cve_records([a], [b, c])
    assert [r.cve_id for r in merged] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert merged[0].product == "wordpress"
