from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

API_ROOT = "https://api.github.com"
COLLECTION_SCHEMA = "observability.failure-collection/v1"
DIAGNOSTIC = re.compile(
    r"(##\[error\]|error[:=]|failed|failure|blocked|missing|required|mismatch|"
    r"timeout|invalid|not found|does not exist|exception|traceback|"
    r"SELF_HOSTED|SecretNotFound|HTTP [45]\d\d|decision=BLOCKED|"
    r"COST_UNKNOWN_BLOCKED|Resource not accessible by integration)",
    re.IGNORECASE,
)
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
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


def _pr_number(run: dict[str, Any]) -> int | None:
    pulls = run.get("pull_requests")
    if not isinstance(pulls, list):
        return None
    for item in pulls:
        if isinstance(item, dict) and isinstance(item.get("number"), int):
            return int(item["number"])
    return None


def _scope_key(run: dict[str, Any]) -> str:
    pr_number = _pr_number(run)
    if pr_number is not None:
        return f"pr:{pr_number}"
    branch = str(run.get("head_branch") or "").strip().lower()
    if branch:
        return f"branch:{branch}"
    sha = str(run.get("head_sha") or "").strip().lower()
    if sha:
        return f"sha:{sha}"
    return f"run:{str(run.get('id') or '')}"


def _parse_github_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _cancelled_has_successor(run: dict[str, Any], runs: list[dict[str, Any]]) -> bool:
    workflow = str(run.get("name") or "")
    scope = _scope_key(run)
    created_at = _parse_github_time(run.get("created_at"))
    cancelled_at = _parse_github_time(run.get("updated_at"))
    run_id = str(run.get("id") or "")
    if created_at is None or cancelled_at is None or cancelled_at < created_at:
        return False

    grace = timedelta(seconds=60)
    for candidate in runs:
        if not isinstance(candidate, dict) or str(candidate.get("id") or "") == run_id:
            continue
        if str(candidate.get("name") or "") != workflow or _scope_key(candidate) != scope:
            continue
        candidate_created = _parse_github_time(candidate.get("created_at"))
        if candidate_created is None or candidate_created <= created_at:
            continue
        if candidate_created > cancelled_at + grace:
            continue
        if str(candidate.get("conclusion") or "").lower() != "cancelled":
            return True
    return False


def _successful_successor(
    run: dict[str, Any],
    runs: list[dict[str, Any]],
) -> dict[str, Any] | None:
    workflow = str(run.get("name") or "")
    scope = _scope_key(run)
    created_at = _parse_github_time(run.get("created_at"))
    run_id = str(run.get("id") or "")
    if created_at is None:
        return None

    candidates = []
    for candidate in runs:
        if not isinstance(candidate, dict) or str(candidate.get("id") or "") == run_id:
            continue
        if str(candidate.get("name") or "") != workflow or _scope_key(candidate) != scope:
            continue
        if str(candidate.get("conclusion") or "").lower() != "success":
            continue
        candidate_created = _parse_github_time(candidate.get("created_at"))
        if candidate_created is None or candidate_created <= created_at:
            continue
        candidates.append((candidate_created, candidate))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0])[1]


def _fetch_workflow_runs(
    *,
    repository: str,
    token: str,
    max_runs: int,
    cutoff: datetime,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    page = 1
    while len(runs) < max_runs:
        page_size = min(100, max_runs - len(runs))
        query = urllib.parse.urlencode({"per_page": page_size, "page": page})
        payload = _json(f"{API_ROOT}/repos/{repository}/actions/runs?{query}", token)
        raw_page = payload.get("workflow_runs")
        if not isinstance(raw_page, list):
            raise GitHubCollectionError("workflow_runs_missing")
        typed_page = [item for item in raw_page if isinstance(item, dict)]
        runs.extend(typed_page)
        if len(raw_page) < page_size:
            break
        timestamps = [
            value
            for value in (_parse_github_time(item.get("created_at")) for item in typed_page)
            if value is not None
        ]
        if timestamps and min(timestamps) < cutoff:
            break
        page += 1
    return runs[:max_runs]


def _validate_repository(repository: str) -> str:
    normalized = str(repository or "").strip()
    if not REPOSITORY.fullmatch(normalized):
        raise GitHubCollectionError("repository_invalid")
    return normalized


def collect_github_actions_run_data(
    *,
    repository: str,
    token: str,
    max_runs: int = 300,
    max_failed_jobs: int = 80,
    since_hours: int = 24,
    now: datetime | None = None,
) -> dict[str, Any]:
    repository = _validate_repository(repository)
    max_runs = max(1, min(int(max_runs), 1000))
    max_failed_jobs = max(1, min(int(max_failed_jobs), 200))
    since_hours = max(1, min(int(since_hours), 720))
    observed_now = (now or datetime.now(UTC)).astimezone(UTC)
    cutoff = observed_now - timedelta(hours=since_hours)
    fetched_runs = _fetch_workflow_runs(
        repository=repository,
        token=token,
        max_runs=max_runs,
        cutoff=cutoff,
    )
    runs = [
        run
        for run in fetched_runs
        if (_parse_github_time(run.get("created_at")) or datetime.min.replace(tzinfo=UTC)) >= cutoff
    ]
    records: list[dict[str, Any]] = []
    log_budget = max_failed_jobs
    failed_job_logs_collected = 0

    for run in runs:
        conclusion = str(run.get("conclusion") or "").lower()
        if conclusion not in INTERESTING_CONCLUSIONS:
            continue
        created = str(run.get("created_at") or "")
        run_id = str(run.get("id") or "")
        workflow = str(run.get("name") or "unknown")
        successor = _successful_successor(run, runs)
        base = {
            "repository": repository,
            "run_id": run_id,
            "workflow": workflow,
            "conclusion": conclusion,
            "occurred_at": _iso(created),
            "head_sha": str(run.get("head_sha") or ""),
            "head_branch": str(run.get("head_branch") or ""),
            "event": str(run.get("event") or ""),
            "run_url": str(run.get("html_url") or ""),
            "run_attempt": int(run.get("run_attempt") or 1),
            "pr_number": _pr_number(run),
            "recovery_observed": successor is not None,
            "recovery_run_id": str(successor.get("id") or "") if successor else "",
            "recovery_occurred_at": str(successor.get("created_at") or "") if successor else "",
        }

        if conclusion == "cancelled":
            records.append({
                **base,
                "job": "",
                "message": "",
                "cancellation_superseded": _cancelled_has_successor(run, runs),
            })
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
                records.append({**base, "job": "", "message": "log_budget_exhausted"})
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
                    failed_job_logs_collected += 1
                except GitHubCollectionError:
                    message = "job_log_unavailable"
            records.append({**base, "job": job_name, "message": message})
            log_budget -= 1

    counts = {
        name: sum(
            1
            for run in runs
            if str(run.get("conclusion") or "").lower() == conclusion
        )
        for name, conclusion in (
            ("successful_runs", "success"),
            ("failure_runs", "failure"),
            ("cancelled_runs", "cancelled"),
            ("timed_out_runs", "timed_out"),
            ("action_required_runs", "action_required"),
        )
    }
    last_fetched = _parse_github_time(fetched_runs[-1].get("created_at")) if fetched_runs else None
    truncated = (
        len(fetched_runs) >= max_runs
        and last_fetched is not None
        and last_fetched >= cutoff
    )
    collection = {
        "schema_version": COLLECTION_SCHEMA,
        "provider": "github_actions",
        "repository": repository,
        "window_start": cutoff.isoformat().replace("+00:00", "Z"),
        "window_end": observed_now.isoformat().replace("+00:00", "Z"),
        "runs_scanned": len(fetched_runs),
        "runs_in_window": len(runs),
        **counts,
        "failed_job_logs_collected": failed_job_logs_collected,
        "records_emitted": len(records),
        "truncated": truncated,
    }
    return {**collection, "records": records}


def collect_github_actions_failures(
    *,
    repository: str,
    token: str,
    max_runs: int = 100,
    max_failed_jobs: int = 40,
    since_hours: int = 24,
) -> list[dict[str, Any]]:
    return collect_github_actions_run_data(
        repository=repository,
        token=token,
        max_runs=max_runs,
        max_failed_jobs=max_failed_jobs,
        since_hours=since_hours,
    )["records"]
