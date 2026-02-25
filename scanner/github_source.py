from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .models import CVERecord

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DEFAULT_CVE_FILES = (
    "README.md",
    "readme.md",
    "SECURITY.md",
    "security.md",
    "ADVISORY.md",
    "advisory.md",
    "CHANGELOG.md",
    "changelog.md",
)


@dataclass
class RepoSnippet:
    name: str
    html_url: str
    description: str
    topics: List[str]
    language: str
    archived: bool
    cves: List[str]


def _request_json(url: str, token: str | None = None) -> Dict | List:
    headers = {"User-Agent": "Defensive-CVE-Scanner/0.3", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, headers=headers)
    with urlopen(req, timeout=20) as response:  # nosec B310 - fixed GitHub API endpoint
        return json.loads(response.read().decode("utf-8"))


def _extract_cves(*texts: str) -> List[str]:
    found = set()
    for text in texts:
        if not text:
            continue
        for match in CVE_PATTERN.findall(text):
            found.add(match.upper())
    return sorted(found)


def _guess_product(repo_name: str, topics: Iterable[str], description: str) -> str:
    hay = " ".join([repo_name, description, *topics]).lower()
    if "wordpress" in hay or "wp" in hay:
        return "wordpress"
    if "joomla" in hay:
        return "joomla"
    if "drupal" in hay:
        return "drupal"
    return "unknown"


def _get_default_branch(owner: str, repo: str, token: str | None = None) -> str:
    payload = _request_json(f"https://api.github.com/repos/{owner}/{repo}", token=token)
    if isinstance(payload, dict) and payload.get("default_branch"):
        return payload["default_branch"]
    return "main"


def _fetch_repo_file_text(owner: str, repo: str, path: str, branch: str, token: str | None = None) -> str:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    payload = _request_json(url, token=token)
    if not isinstance(payload, dict) or payload.get("encoding") != "base64":
        return ""
    content = payload.get("content", "")
    if not content:
        return ""
    try:
        return base64.b64decode(content).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_cves_from_repo_files(owner: str, repo: str, token: str | None = None) -> List[str]:
    branch = _get_default_branch(owner, repo, token=token)
    all_cves = set()
    for filename in DEFAULT_CVE_FILES:
        text = _fetch_repo_file_text(owner, repo, filename, branch, token=token)
        for cve_id in _extract_cves(text):
            all_cves.add(cve_id)
    return sorted(all_cves)


def fetch_owner_repo_snippets(
    owner: str,
    max_repos: int = 200,
    token: str | None = None,
    include_archived: bool = True,
    include_file_cves: bool = True,
) -> List[RepoSnippet]:
    per_page = 100
    page = 1
    snippets: List[RepoSnippet] = []

    while len(snippets) < max_repos:
        query = urlencode({"per_page": per_page, "page": page, "sort": "updated", "type": "all"})
        url = f"https://api.github.com/users/{owner}/repos?{query}"
        payload = _request_json(url, token=token)
        if not isinstance(payload, list) or not payload:
            break

        for repo in payload:
            archived = bool(repo.get("archived", False))
            if archived and not include_archived:
                continue

            description = repo.get("description") or ""
            name = repo.get("name", "")
            topics = repo.get("topics") or []
            html_url = repo.get("html_url", "")
            language = repo.get("language") or ""

            cves = set(_extract_cves(name, description, " ".join(topics)))
            if include_file_cves and name:
                for cve_id in _extract_cves_from_repo_files(owner=owner, repo=name, token=token):
                    cves.add(cve_id)

            snippets.append(
                RepoSnippet(
                    name=name,
                    html_url=html_url,
                    description=description,
                    topics=topics,
                    language=language,
                    archived=archived,
                    cves=sorted(cves),
                )
            )
            if len(snippets) >= max_repos:
                break

        if len(payload) < per_page:
            break
        page += 1

    return snippets


def owner_cves_to_records(
    owner: str,
    max_repos: int = 200,
    token: str | None = None,
    include_archived: bool = True,
    include_file_cves: bool = True,
) -> List[CVERecord]:
    snippets = fetch_owner_repo_snippets(
        owner=owner,
        max_repos=max_repos,
        token=token,
        include_archived=include_archived,
        include_file_cves=include_file_cves,
    )
    records: Dict[str, CVERecord] = {}

    for snippet in snippets:
        for cve_id in snippet.cves:
            if cve_id in records:
                continue
            product = _guess_product(snippet.name, snippet.topics, snippet.description)
            archived_tag = " (archived repo)" if snippet.archived else ""
            records[cve_id] = CVERecord(
                cve_id=cve_id,
                product=product,
                component="core",
                affected_versions=["unknown"],
                severity="unknown",
                description=f"CVE reference discovered in GitHub repo metadata/files: {snippet.html_url}{archived_tag}",
                remediation="Validate advisory details and apply vendor patches.",
            )

    return sorted(records.values(), key=lambda x: x.cve_id)
