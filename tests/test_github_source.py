from scanner.github_source import (
    _extract_cves,
    _extract_cves_from_repo_files,
    _guess_product,
    fetch_owner_repo_snippets,
    owner_cves_to_records,
)


def test_extract_cves_from_text_fields():
    found = _extract_cves("foo CVE-2024-1234", "bar cve-2023-99999")
    assert found == ["CVE-2023-99999", "CVE-2024-1234"]


def test_guess_product_wordpress():
    assert _guess_product("wp-plugin-awesome", ["security"], "") == "wordpress"


def test_extract_cves_from_repo_files(monkeypatch):
    monkeypatch.setattr("scanner.github_source._get_default_branch", lambda owner, repo, token=None: "main")

    def fake_fetch(owner, repo, path, branch, token=None):
        if path.lower() == "readme.md":
            return "This references CVE-2024-7777"
        return ""

    monkeypatch.setattr("scanner.github_source._fetch_repo_file_text", fake_fetch)
    cves = _extract_cves_from_repo_files("Nxploited", "repo")
    assert cves == ["CVE-2024-7777"]


def test_fetch_owner_repo_snippets_include_exclude_archived(monkeypatch):
    def fake_request_json(url, token=None):
        if "users/Nxploited/repos" in url:
            return [
                {
                    "name": "active-cve-2024-1000",
                    "html_url": "https://github.com/Nxploited/active",
                    "description": "CVE-2024-1000",
                    "topics": ["wordpress"],
                    "language": "Python",
                    "archived": False,
                },
                {
                    "name": "archived-cve-2023-2000",
                    "html_url": "https://github.com/Nxploited/archived",
                    "description": "CVE-2023-2000",
                    "topics": ["joomla"],
                    "language": "Python",
                    "archived": True,
                },
            ]
        return {"default_branch": "main"}

    monkeypatch.setattr("scanner.github_source._request_json", fake_request_json)
    monkeypatch.setattr("scanner.github_source._extract_cves_from_repo_files", lambda owner, repo, token=None: [])

    included = fetch_owner_repo_snippets("Nxploited", include_archived=True)
    excluded = fetch_owner_repo_snippets("Nxploited", include_archived=False)

    assert len(included) == 2
    assert len(excluded) == 1
    assert included[1].archived is True


def test_owner_cves_to_records(monkeypatch):
    def fake_fetch_owner_repo_snippets(
        owner,
        max_repos=200,
        token=None,
        include_archived=True,
        include_file_cves=True,
    ):
        assert owner == "Nxploited"
        assert include_archived is True
        assert include_file_cves is True
        return [
            type("S", (), {
                "name": "wordpress-CVE-2024-1111",
                "html_url": "https://github.com/Nxploited/wordpress-CVE-2024-1111",
                "description": "PoC for CVE-2024-1111",
                "topics": ["wordpress", "cve"],
                "language": "Python",
                "archived": False,
                "cves": ["CVE-2024-1111"],
            })(),
            type("S", (), {
                "name": "archived-joomla",
                "html_url": "https://github.com/Nxploited/archived-joomla",
                "description": "references CVE-2023-2222",
                "topics": ["joomla"],
                "language": "Python",
                "archived": True,
                "cves": ["CVE-2023-2222"],
            })(),
        ]

    monkeypatch.setattr("scanner.github_source.fetch_owner_repo_snippets", fake_fetch_owner_repo_snippets)
    records = owner_cves_to_records("Nxploited")

    assert [r.cve_id for r in records] == ["CVE-2023-2222", "CVE-2024-1111"]
    assert records[1].product == "wordpress"
    assert "archived repo" in records[0].description
