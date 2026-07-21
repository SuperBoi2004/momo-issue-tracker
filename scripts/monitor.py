#!/usr/bin/env python3
"""Refresh trusted maintainers and create a strict 24-hour issue digest."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
AT = re.compile(r"(?<![\w@])@([A-Za-z0-9][A-Za-z0-9-]{0,38})\b")
URL = re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})")
PAREN = re.compile(r"\(([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$")
YAML_KEY = re.compile(r"^(\s*)([A-Za-z0-9_-]+):(?:\s*\[\])?\s*$")
YAML_ITEM = re.compile(r"^\s*-\s*([A-Za-z0-9][A-Za-z0-9-]{0,38})\b")


class Failure(RuntimeError):
    pass


def gh_json(endpoint: str, fields: list[str] | None = None, paginate=False) -> Any:
    command = ["gh", "api", "--method", "GET"]
    if paginate:
        command += ["--paginate", "--slurp"]
    command.append(endpoint)
    for field in fields or []:
        command += ["-f", field]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise Failure(result.stderr.strip() or f"gh api failed for {endpoint}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Failure(f"Invalid JSON from gh api for {endpoint}") from exc


def fetch_file(repo: str, path: str) -> tuple[str, dict[str, str]]:
    metadata = gh_json(f"repos/{repo}")
    branch = metadata["default_branch"]
    payload = gh_json(
        f"repos/{repo}/contents/{quote(path, safe='/')}?ref={quote(branch, safe='')}"
    )
    content = base64.b64decode(payload["content"]).decode()
    evidence = {
        "repo": repo,
        "path": path,
        "branch": branch,
        "sha": payload["sha"],
        "url": f"https://github.com/{repo}/blob/{branch}/{path}",
    }
    return content, evidence


def heading(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).casefold()


def line_handles(line: str) -> set[str]:
    handles = set(AT.findall(line)) | set(URL.findall(line)) | set(PAREN.findall(line))
    try:
        fields = next(csv.reader([line]))
    except csv.Error:
        fields = []
    if len(fields) >= 3:
        candidate = fields[1].strip().lstrip("@")
        if LOGIN.fullmatch(candidate):
            handles.add(candidate)
    return handles


def parse_markdown(content: str, source: dict[str, Any]) -> dict[str, set[str]]:
    includes = {heading(value) for value in source["include"]}
    excludes = {heading(value) for value in source.get("exclude", [])}
    current = ""
    found: dict[str, set[str]] = defaultdict(set)
    removed: set[str] = set()
    for line in content.splitlines():
        match = HEADING.match(line)
        if match:
            current = heading(match.group(1))
            continue
        handles = line_handles(line)
        if current in excludes:
            removed.update(value.casefold() for value in handles)
        elif current in includes:
            for value in handles:
                found[value].add(current)
    return {
        login: roles
        for login, roles in found.items()
        if login.casefold() not in removed
    }


def parse_owners(content: str, source: dict[str, Any]) -> dict[str, set[str]]:
    allowed = {value.casefold() for value in source["keys"]}
    found: dict[str, set[str]] = defaultdict(set)
    active: str | None = None
    active_indent = -1
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        key = YAML_KEY.match(line)
        if key:
            indent = len(key.group(1))
            if active is not None and indent <= active_indent:
                active = None
            candidate = key.group(2).casefold()
            if candidate in allowed:
                active, active_indent = candidate, indent
            continue
        item = YAML_ITEM.match(line)
        if active and item:
            found[item.group(1)].add(active)
    return found


def validate_login(login: str) -> str | None:
    try:
        user = gh_json(f"users/{quote(login, safe='')}")
    except Failure:
        return None
    canonical = str(user.get("login", ""))
    if user.get("type") != "User" or not LOGIN.fullmatch(canonical):
        return None
    return canonical


def discover(config: dict[str, Any], now: datetime) -> dict[str, Any]:
    output: dict[str, Any] = {
        "version": 1,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "policy": "Only validated users listed in authoritative governance files",
        "repositories": {},
    }
    for target in config["repositories"]:
        repo = target["repo"]
        metadata = gh_json(f"repos/{repo}")
        if metadata.get("archived"):
            raise Failure(f"Refusing archived repository {repo}")
        source = target["source"]
        content, evidence = fetch_file(source["repo"], source["path"])
        parsed = (
            parse_markdown(content, source)
            if source["type"] == "markdown"
            else parse_owners(content, source)
        )
        trusted = []
        seen: set[str] = set()
        for candidate in sorted(parsed, key=str.casefold):
            canonical = validate_login(candidate)
            if canonical and canonical.casefold() not in seen:
                seen.add(canonical.casefold())
                trusted.append(
                    {
                        "login": canonical,
                        "roles": sorted(parsed[candidate]),
                        "source": f"{source['repo']}:{source['path']}",
                    }
                )
        if not trusted:
            raise Failure(f"No trusted users discovered for {repo}")
        output["repositories"][repo] = {
            "name": target["name"],
            "source_file": evidence,
            "trusted_authors": trusted,
        }
        print(f"{repo}: {len(trusted)} trusted authors")
    return output


def github_time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Failure(f"Invalid GitHub timestamp: {value!r}") from exc
    return result.astimezone(timezone.utc)


def search_issues(repo: str, cutoff: datetime) -> list[dict[str, Any]]:
    query = f"repo:{repo} is:issue created:>={cutoff:%Y-%m-%d}"
    pages = gh_json(
        "search/issues",
        [
            f"q={query}",
            "sort=created",
            "order=desc",
            "per_page=100",
        ],
        paginate=True,
    )
    return [item for page in pages for item in page.get("items", [])]


def labels(issue: dict[str, Any]) -> set[str]:
    return {
        str(item.get("name", "")).strip().casefold()
        for item in issue.get("labels", [])
        if item.get("name")
    }


def triage(issue: dict[str, Any], repo: str) -> dict[str, Any]:
    issue_labels = labels(issue)
    text = f"{issue.get('title', '')}\n{issue.get('body') or ''}".casefold()
    category = "other"
    category_signal = False
    categories = {
        "bug": {"bug", "kind/bug", "type/bug"},
        "feature": {"enhancement", "feature", "kind/feature", "type/feature"},
        "documentation": {"documentation", "docs", "kind/documentation"},
        "test": {"test", "testing", "kind/test"},
    }
    for name, values in categories.items():
        if issue_labels & values:
            category, category_signal = name, True
            break
    if category == "other":
        for name, words in {
            "bug": ("bug", "crash", "regression", "broken", "panic"),
            "feature": ("feature", "enhancement", "support for"),
            "documentation": ("documentation", "readme", "typo"),
            "test": ("test", "coverage", "flaky"),
        }.items():
            if any(word in text for word in words):
                category = name
                break

    easy = issue_labels & {
        "good first issue", "help wanted", "size/xs", "size/s", "difficulty/easy"
    }
    hard = issue_labels & {
        "size/l", "size/xl", "epic", "security", "kind/design", "difficulty/hard"
    }
    hard_words = (
        "architecture", "breaking change", "migration", "redesign",
        "security", "performance", "cross-component", "api change",
    )
    if hard or any(word in text for word in hard_words):
        difficulty = "hard"
    elif easy or any(word in text for word in ("typo", "readme", "small fix")):
        difficulty = "easy"
    else:
        difficulty = "medium"
    confidence = (
        "high" if category_signal and (easy or hard)
        else "medium" if category_signal or len(str(issue.get("body") or "")) >= 120
        else "low"
    )
    approachable = (
        difficulty == "easy"
        and confidence == "high"
        and not issue_labels & {"blocked", "needs-design", "do-not-merge"}
    )
    return {
        "category": category,
        "difficulty": difficulty,
        "confidence": confidence,
        "approachable": approachable,
        "context": repo,
    }


def monitor(allowlist: dict[str, Any], now: datetime) -> tuple[list[dict[str, Any]], dict[str, int]]:
    cutoff = now - timedelta(hours=24)
    result = []
    counts = {"search_candidates": 0, "outside_exact_window": 0, "untrusted": 0}
    for repo, policy in allowlist["repositories"].items():
        trusted = {
            item["login"].casefold() for item in policy["trusted_authors"]
        }
        candidates = search_issues(repo, cutoff)
        counts["search_candidates"] += len(candidates)
        for issue in candidates:
            created = github_time(issue["created_at"])
            if created < cutoff or created > now:
                counts["outside_exact_window"] += 1
                continue
            author = str((issue.get("user") or {}).get("login", ""))
            if author.casefold() not in trusted:
                counts["untrusted"] += 1
                continue
            result.append(
                {
                    "repo": repo,
                    "number": issue["number"],
                    "title": issue["title"],
                    "url": issue["html_url"],
                    "author": author,
                    "created_at": issue["created_at"],
                    "labels": sorted(labels(issue)),
                    "triage": triage(issue, repo),
                }
            )
    result.sort(key=lambda item: (not item["triage"]["approachable"], item["repo"], item["created_at"]))
    return result, counts


def markdown_text(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def render(issues: list[dict[str, Any]], counts: dict[str, int], now: datetime) -> str:
    cutoff = now - timedelta(hours=24)
    lines = [
        "# Daily trusted-author GitHub issue digest", "",
        f"Window: `{cutoff.isoformat().replace('+00:00', 'Z')}` through "
        f"`{now.isoformat().replace('+00:00', 'Z')}` (strict `created_at`).", "",
        "## Recommended approachable issues", "",
    ]
    recommended = [item for item in issues if item["triage"]["approachable"]]
    if not recommended:
        lines.append("No high-confidence approachable issues found.")
    for item in recommended:
        value = item["triage"]
        lines.append(
            f"- [{markdown_text(item['repo'])} #{item['number']}: "
            f"{markdown_text(item['title'])}]({item['url']}) "
            f"— @{item['author']}; {value['category']}, {value['difficulty']}, "
            f"{value['confidence']} confidence"
        )
    lines += ["", "## Other trusted-author issues", ""]
    others = [item for item in issues if not item["triage"]["approachable"]]
    if not others:
        lines.append("None.")
    for item in others:
        value = item["triage"]
        lines.append(
            f"- [{markdown_text(item['repo'])} #{item['number']}: "
            f"{markdown_text(item['title'])}]({item['url']}) "
            f"— @{item['author']}; {value['category']}, {value['difficulty']}, "
            f"{value['confidence']} confidence"
        )
    lines += [
        "", "## Audit summary", "",
        f"- Search candidates: {counts['search_candidates']}",
        f"- Excluded outside exact window: {counts['outside_exact_window']}",
        f"- Excluded untrusted authors: {counts['untrusted']}",
        f"- Included: {len(issues)}", "",
    ]
    return "\n".join(lines)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as handle:
        handle.write(content)
        temporary = handle.name
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--now", help="ISO UTC time override")
    args = parser.parse_args()
    if not shutil.which("gh"):
        print("error: gh is not installed", file=sys.stderr)
        return 2
    if subprocess.run(["gh", "auth", "status"], capture_output=True).returncode:
        print("error: gh is not authenticated", file=sys.stderr)
        return 1
    now = github_time(args.now) if args.now else datetime.now(timezone.utc)
    try:
        config = json.loads((ROOT / "config/repos.json").read_text())
        allowlist = discover(config, now)
        issues, counts = monitor(allowlist, now)
        date = now.strftime("%Y-%m-%d")
        digest = render(issues, counts, now)
        payload = {
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "filter_field": "created_at",
            "counts": counts | {"included": len(issues)},
            "issues": issues,
        }
        atomic_write(ROOT / "config/trusted-authors.json", json.dumps(allowlist, indent=2) + "\n")
        atomic_write(ROOT / f"output/digest-{date}.md", digest)
        atomic_write(ROOT / f"output/digest-{date}.json", json.dumps(payload, indent=2) + "\n")
        atomic_write(ROOT / "output/latest.md", digest)
        atomic_write(ROOT / "output/latest.json", json.dumps(payload, indent=2) + "\n")
    except (Failure, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote output/digest-{date}.md with {len(issues)} trusted-author issues")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
