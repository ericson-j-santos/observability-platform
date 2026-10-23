from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

API_ROOT = "https://api.github.com"
DIAGNOSTIC = re.compile(
    r"(##\[error\]|error[:=]|failed|failure|blocked|missing|required|mismatch|"
    r"timeout|invalid|not found|does not exist|exception|traceback|"
    r"SELF_HOSTED|SecretNotFound|HTTP [45]\d\d|decision=BLOCKED|"
    r"COST_UNKNOWN_BLOCKED|Resource not accessible by integration)",
    re.IGNORECASE,
)
INTERESTING_CONCLUSIONS = {"failure", "cancelled", "timed_out", "action_required"}
SAFE_LOG_REDIRECT_SUFFIXES = (
    ".blob.core.windows.net",
    ".actions.githubusercontent.com",
    ".githubusercontent.com",
)


class GitHubCollectionError(RuntimeError):
    pass


def _headers(token: str) -> dict[str, str]:
    if not token.strip():
        raise GitHubCollectionError("github_token_required")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token.strip()}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "observability-platform-failure-analysis",
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _safe_redirect_url(location: str) -> str:
    parsed = urllib.parse.urlparse(str(location or ""))
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not host
        or not any(host.endswith(suffix) for suffix in SAFE_LOG_REDIRECT_SUFFIXES)
    ):
        raise GitHubCollectionError("github_redirect_not_allowlisted")
    return parsed.geturl()


def _read(url: str, token: str, *, timeout: int = 30) -> bytes:
    request = urllib.request.Request(url, headers=_headers(token))
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.read(2_000_000)
    except urllib.error.HTTPError as exc:
        if exc.code not in {301, 302, 303, 307, 308}:
            raise GitHubCollectionError("github_read_failed") from exc
        redirect = _safe_redirect_url(exc.headers.get("Location", ""))
        anonymous = urllib.request.Request(
            redirect,
            headers={"User-Agent": "observability-platform-failure-analysis"},
        )
        try:
            with urllib.request.urlopen(anonymous, timeout=timeout) as response:
                return response.read(2_000_000)
        except (urllib.error.URLError, TimeoutError, OSError) as redirected_exc:
            raise GitHubCollectionError("github_redirect_read_failed") from redirected_exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise GitHubCollectionError("github_read_failed") from exc


def _json(url: str, token: str) -> dict[str, Any]:
    raw = _read(url, token)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubCollectionError("github_json_invalid") from exc
    if not isinstance(payload, dict):
        raise GitHubCollectionError("github_json_not_object")
    return payload


def diagnostic_excerpt(log_text: str, *, max_lines: int = 24) -> str:
    lines = []
    for raw in (log_text or "").splitlines():
        line = raw.strip()
        if line and DIAGNOSTIC.search(line):
            lines.append(line)
    if not lines:
        return ""
    return "\n".join(lines[-max_lines:])[:12_000]


def _iso(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return datetime.now(UTC).isoformat()
    return text


def collect_github_actions_failures(
    *,
    repository: str,
    token: str,
    max_runs: int = 100,
    max_failed_jobs: int = 40,
    since_hours: int = 24,
) -> list[dict[str, Any]]:
    if "/" not in repository:
        raise GitHubCollectionError("repository_invalid")
    max_runs = max(1, min(int(max_runs), 100))
    max_failed_jobs = max(1, min(int(max_failed_jobs), 100))
    since_hours = max(1, min(int(since_hours), 168))
    query = urllib.parse.urlencode({"per_page": max_runs})
    runs_payload = _json(f"{API_ROOT}/repos/{repository}/actions/runs?{query}", token)
    runs = runs_payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise GitHubCollectionError("workflow_runs_missing")
    cutoff = datetime.now(UTC) - timedelta(hours=since_hours)
    records: list[dict[str, Any]] = []
    log_budget = max_failed_jobs

    for run in runs:
        if not isinstance(run, dict):
            continue
        conclusion = str(run.get("conclusion") or "").lower()
        if conclusion not in INTERESTING_CONCLUSIONS:
            continue
        created = str(run.get("created_at") or "")
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            continue
        if created_dt < cutoff:
            continue

        run_id = str(run.get("id") or "")
        workflow = str(run.get("name") or "unknown")
        base = {
            "repository": repository,
            "run_id": run_id,
            "workflow": workflow,
            "conclusion": conclusion,
            "occurred_at": _iso(created),
            "head_sha": str(run.get("head_sha") or ""),
            "event": str(run.get("event") or ""),
            "run_url": str(run.get("html_url") or ""),
        }

        if conclusion == "cancelled":
            records.append({**base, "job": "", "message": ""})
            continue

        if log_budget <= 0:
            records.append({**base, "job": "", "message": "log_budget_exhausted"})
            continue

        jobs_payload = _json(
            f"{API_ROOT}/repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100",
            token,
        )
        jobs = jobs_payload.get("jobs")
        if not isinstance(jobs, list):
            records.append({**base, "job": "", "message": "jobs_missing"})
            continue

        failed_jobs = [
            job
            for job in jobs
            if isinstance(job, dict)
            and str(job.get("conclusion") or "").lower() in INTERESTING_CONCLUSIONS
        ]
        if not failed_jobs:
            records.append({**base, "job": "", "message": ""})
            continue

        for job in failed_jobs:
            if log_budget <= 0:
                break
            job_id = str(job.get("id") or "")
            job_name = str(job.get("name") or "")
            message = ""
            if job_id:
                try:
                    raw = _read(
                        f"{API_ROOT}/repos/{repository}/actions/jobs/{job_id}/logs",
                        token,
                        timeout=45,
                    )
                    message = diagnostic_excerpt(raw.decode("utf-8", errors="replace"))
                except GitHubCollectionError:
                    message = "job_log_unavailable"
            records.append({**base, "job": job_name, "message": message})
            log_budget -= 1

    return records
