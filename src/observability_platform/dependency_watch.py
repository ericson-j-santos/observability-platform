"""Read-only cross-repository dependency policy watch with GitHub Issues alerts.

Only the controller repository may receive checkpoint/alert issues. No target
repository is modified. All detection uses ADDED unified diff lines, never
untrusted files executed from a target repository.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import sys
from urllib import error, parse, request

CONTROLLER = "ericson-j-santos/observability-platform"
TARGETS = (
    "ericson-j-santos/desktop-pc24x7-runtime",
    "ericson-j-santos/engineering-worker-pool",
)
STATE_TITLE = "[monitor-state] Dependency policy checkpoint (not an alert)"
BOT_LOGIN = "github-actions[bot]"
STATE_MARKER = "<!-- dependency-policy-watch-state/v1 -->"
ALERT_MARKER = "<!-- dependency-policy-watch-key:"
SCHEMA = "dependency-policy-watch/v1"
MAX_PAGES = 10
MAX_BODY = 3_000_000
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
DOC_EXTENSIONS = {".md", ".rst", ".adoc", ".ipynb"}
BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".exe", ".dll", ".svg", ".woff", ".woff2", ".mp4"}
IGNORE_PARTS = {"__pycache__", "fixtures", "testdata", "snapshots", "examples"}
SENSITIVE_RE = re.compile(r"(?i)(?:ghp_|github_pat_|sk-)[a-z0-9_-]{8,}|(?:(?:password|passwd|token|api[_-]?key|secret|authorization)\s*[:=]\s*)[^\s,;]+")


class IncompleteEvidence(RuntimeError):
    """Incomplete/unsafe collection: fail closed without advancing the cursor."""


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def redacted(line: str) -> str:
    result = SENSITIVE_RE.sub("[REDACTED]", line.strip())
    return result.replace("@", "@\u200b")[:180]


@dataclass(frozen=True)
class Finding:
    repository: str
    origin: str
    origin_id: str
    head_sha: str
    path: str
    line: int
    technology: str
    classification: str
    signal: str
    evidence: str
    url: str
    signature: str


def relevant_file(path: str) -> bool:
    parts = PurePosixPath(path).parts
    lower = path.lower()
    if not path or path.startswith("/") or ".." in parts:
        return False
    if any(part.lower() in IGNORE_PARTS for part in parts):
        return False
    if lower.startswith(("docs/", "tests/", "test/", ".github/issue_template/")):
        return False
    suffix = PurePosixPath(lower).suffix
    return suffix not in DOC_EXTENSIONS and suffix not in BINARY_EXTENSIONS


def detected(path: str, line: str, *, new_file: bool) -> tuple[str, str, str] | None:
    """Return (technology, verdict, signal) for a newly added active instruction.

    Cost findings are *suspicions*, even if the dependency is explicit: billing
    requires account-specific independent evidence, which static diffs lack.
    """
    s = line.strip()
    lo = s.lower()
    p = path.lower()
    name = PurePosixPath(p).name
    if not s or s.startswith(("#", "//", "*", "<!--")):
        return None
    workflow = p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))
    dockerfile = name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")
    compose = re.match(r"^(docker-compose|compose)(?:\.[a-z0-9_-]+)?\.ya?ml$", name) is not None
    k8s_manifest = any(part in ("k8s", "kubernetes", "helm", "charts") for part in PurePosixPath(p).parts)
    # Dockerfile/Compose/K8s manifests are conclusive dependencies when newly added.
    if dockerfile and (re.match(r"(?i)^FROM\s+\S+", s) or new_file and re.match(r"(?i)^(RUN|COPY|ADD|CMD|ENTRYPOINT)\s+", s)):
        return ("Docker", "COMPROVADA", "Dockerfile instruction")
    if compose and re.match(r"(?i)^(services|image|build|dockerfile):?\s*", s):
        return ("Docker", "COMPROVADA", "Docker Compose configuration")
    if k8s_manifest and re.match(r"(?i)^(apiVersion|kind):\s*(?:apps/|batch/|v1|Deployment|Pod|Service|CronJob|Job|StatefulSet|DaemonSet)", s):
        return ("Kubernetes", "COMPROVADA", "Kubernetes manifest")
    if workflow and re.match(r"(?i)^(container|services):\s*(?:\S.*)?$", s):
        return ("Docker", "COMPROVADA", "GitHub Actions container/services dependency")
    if re.search(r"(?i)\buses:\s*(?:docker/(?:build-push-action|setup-buildx-action|login-action|metadata-action)|azure/k8s-[\w-]+)", s):
        t = "Docker" if "docker/" in lo else "Kubernetes"
        return (t, "COMPROVADA", "Container/Kubernetes action")
    # Execute/install commands: exclude natural-language mentions and documentation.
    for technology, keyword in (("Docker", "docker"), ("Podman", "podman"), ("Kubernetes", "kubectl|helm|k3s|minikube")):
        if re.search(rf"(?i)(?:^|[\s;|&'\"`])(?:sudo\s+)?(?:{keyword})(?:\s+|:)(?:build|run|compose|pull|push|login|install|apply|upgrade|create|deploy|delete|config|version|info|ps|stop|start|system|image|network|machine|exec|--version)\b", s):
            return (technology, "COMPROVADA", f"{technology} command")
        if re.search(rf"(?i)\b(?:apt(?:-get)?|apk|dnf|yum|brew|choco|pip(?:3)?|uv)\s+(?:install|add)\b[^#\n]*\b(?:{keyword})\b", s):
            return (technology, "COMPROVADA", f"{technology} tool installation")
    if re.search(r"(?i)(?:\bdocker\s*[:=]\s*[\"']?[^\s]+|\bdockerode\b|\bpodman-py\b|\b@kubernetes/client-node\b|\bkubernetes\s*(?:==|>=|~=))", s):
        if (name in {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "poetry.lock", "uv.lock"} or name.endswith("requirements.txt")):
            tech = "Kubernetes" if "kubernetes" in lo else "Podman" if "podman" in lo else "Docker"
            return (tech, "COMPROVADA", f"{tech} package dependency")
    # Explicitly declared expensive runners can introduce billing, but actual
    # pricing/account impact cannot be verified from repository code alone.
    if workflow and re.search(r"(?i)\bruns-on\s*:\s*(?:ubuntu|windows|macos)-(?:[4-9]|[1-9][0-9]+)-core\b", s):
        return ("Custo adicional", "SUSPEITA", "GitHub larger runner label")
    if re.search(r"(?i)\b(?:fly\s+deploy|render\s+deploy|vercel\s+deploy\s+--prod|aws\s+cloudformation\s+deploy|gcloud\s+run\s+deploy|az\s+deployment\s+create)\b", s):
        return ("Custo adicional", "SUSPEITA", "External/cloud deployment")
    if re.search(r"(?i)\bresource\s+[\"'](?:aws_instance|aws_db_instance|azurerm_linux_virtual_machine|azurerm_mssql_server|google_compute_instance|google_sql_database_instance)[\"']", s):
        return ("Custo adicional", "SUSPEITA", "Provisioning cloud resource")
    if re.search(r"(?i)\b(?:paid_plan|billing_enabled|enable_paid_tier|plan\s*:\s*(?:pro|premium|enterprise))\b", s):
        return ("Custo adicional", "SUSPEITA", "Paid-tier configuration")
    return None


def added_lines(patch: str):
    line_no: int | None = None
    found_hunk = False
    for raw in patch.splitlines():
        m = HUNK_RE.match(raw)
        if m:
            line_no = int(m.group(1))
            found_hunk = True
            continue
        if not found_hunk or line_no is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            yield line_no, raw[1:]
            line_no += 1
        elif raw.startswith(" "):
            line_no += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
    if patch.strip() and not found_hunk:
        raise IncompleteEvidence("Malformed GitHub diff: no hunk headers")


def scan_files(repo: str, origin: str, origin_id: str, head_sha: str, files: list[dict]) -> list[Finding]:
    if repo not in TARGETS or not SHA_RE.fullmatch(head_sha):
        raise IncompleteEvidence("Unexpected repository or invalid SHA")
    results = []
    for file in files:
        path = file.get("filename", "")
        if not relevant_file(path):
            continue
        if file.get("status") == "removed":
            continue
        patch = file.get("patch")
        if not isinstance(patch, str):
            raise IncompleteEvidence(f"Missing text diff: {repo}/{path}")
        for lineno, added in added_lines(patch):
            signal = detected(path, added, new_file=file.get("status") == "added")
            if not signal:
                continue
            tech, classification, reason = signal
            key = sha("|".join((repo, origin, origin_id if origin == "PR" else "main", path, tech, re.sub(r"\s+", " ", added.strip()))))
            safe_path = parse.quote(path, safe="/")
            url = (f"https://github.com/{repo}/pull/{origin_id}/files" if origin == "PR"
                   else f"https://github.com/{repo}/blob/{head_sha}/{safe_path}#L{lineno}")
            results.append(Finding(repo, origin, origin_id, head_sha, path, lineno, tech, classification, reason, redacted(added), url, key))
    return results


class GitHubAPI:
    """Minimal, bounded GitHub API client. No data from target repos is executed."""

    def __init__(self, token: str = ""):
        self.token = token

    def call(self, method: str, path: str, data: dict | None = None):
        if method not in {"GET", "POST", "PATCH"} or not path.startswith("/repos/"):
            raise ValueError("Invalid GitHub API operation")
        url = "https://api.github.com" + path
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "dependency-policy-watch/v1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = json.dumps(data, separators=(",", ":")).encode("utf-8") if data is not None else None
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = request.Request(url, data=body, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=25) as response:
                if response.status < 200 or response.status >= 300:
                    raise IncompleteEvidence(f"GitHub HTTP {response.status}")
                raw = response.read(MAX_BODY + 1)
        except (error.URLError, TimeoutError) as ex:
            raise IncompleteEvidence(f"GitHub API {method} failed for {path.split('?')[0]}: {type(ex).__name__}") from ex
        if len(raw) > MAX_BODY:
            raise IncompleteEvidence("GitHub API response size exceeded")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError) as ex:
            raise IncompleteEvidence("Malformed GitHub API response") from ex

    def get(self, path: str):
        return self.call("GET", path)

    def post(self, path: str, data: dict):
        if not path.startswith(f"/repos/{CONTROLLER}/issues"):
            raise ValueError("Writes to monitored repositories are forbidden")
        return self.call("POST", path, data)

    def patch(self, path: str, data: dict):
        if not re.fullmatch(rf"/repos/{re.escape(CONTROLLER)}/issues/\d+", path):
            raise ValueError("Writes to monitored repositories are forbidden")
        return self.call("PATCH", path, data)


def pages(api: GitHubAPI, path: str) -> list[dict]:
    records: list[dict] = []
    for number in range(1, MAX_PAGES + 1):
        sep = "&" if "?" in path else "?"
        items = api.get(f"{path}{sep}per_page=100&page={number}")
        if not isinstance(items, list):
            raise IncompleteEvidence("Paginated response is not a list")
        records.extend(items)
        if len(items) < 100:
            return records
    raise IncompleteEvidence("GitHub pagination incomplete: max pages reached")


def default_state() -> dict:
    return {"schema_version": SCHEMA, "main_heads": {}, "pr_heads": {}}


def read_issues(api: GitHubAPI) -> tuple[dict | None, dict, set[str]]:
    checkpoint = None
    state = default_state()
    known_keys: set[str] = set()
    for issue in pages(api, f"/repos/{CONTROLLER}/issues?state=all"):
        if issue.get("pull_request"):
            continue
        # Public issues are untrusted: only markers created by this exact GitHub
        # Actions bot can influence the checkpoint or suppress notifications.
        if issue.get("user", {}).get("login") != BOT_LOGIN:
            continue
        body = issue.get("body") or ""
        if STATE_MARKER in body:
            if checkpoint is not None:
                raise IncompleteEvidence("Multiple checkpoint issues")
            checkpoint = issue
            match = re.search(r"```json\s*(\{.*?\})\s*```", body, re.S)
            if match is None:
                raise IncompleteEvidence("Checkpoint JSON missing")
            try:
                state = json.loads(match.group(1))
            except ValueError as exc:
                raise IncompleteEvidence("Checkpoint JSON invalid") from exc
            if (not isinstance(state, dict) or state.get("schema_version") != SCHEMA
                or not isinstance(state.get("main_heads"), dict) or not isinstance(state.get("pr_heads"), dict)):
                raise IncompleteEvidence("Unexpected checkpoint schema")
        if issue.get("title", "").startswith("[Dependency Watch/"):
            for match in re.finditer(r"<!-- dependency-policy-watch-key:([0-9a-f]{24}) -->", body):
                known_keys.add(match.group(1))
    return checkpoint, state, known_keys


def collect(api: GitHubAPI, state: dict) -> tuple[list[Finding], dict, dict]:
    updated = copy.deepcopy(state)
    findings: list[Finding] = []
    stats: dict = {}
    for repo in TARGETS:
        meta = api.get(f"/repos/{repo}")
        if meta.get("full_name", "").lower() != repo.lower() or meta.get("private") is not False or meta.get("default_branch") != "main":
            raise IncompleteEvidence(f"Target accessibility/branch changed: {repo}")
        info = api.get(f"/repos/{repo}/branches/main")
        head = info.get("commit", {}).get("sha", "")
        if not SHA_RE.fullmatch(head):
            raise IncompleteEvidence(f"Invalid main SHA for {repo}")
        previous = state["main_heads"].get(repo)
        delta = "baseline" if not previous else "unchanged"
        if previous and previous != head:
            if not SHA_RE.fullmatch(previous):
                raise IncompleteEvidence(f"Invalid checkpoint SHA for {repo}")
            comparison = api.get(f"/repos/{repo}/compare/{previous}...{head}")
            if comparison.get("status") != "ahead" or comparison.get("total_commits", 0) > 250:
                raise IncompleteEvidence(f"Main history diverged/truncated: {repo}")
            files = comparison.get("files")
            if not isinstance(files, list) or len(files) >= 300:
                raise IncompleteEvidence(f"Main diff unavailable or truncated: {repo}")
            findings.extend(scan_files(repo, "main", head[:12], head, files))
            delta = "compared"
        updated["main_heads"][repo] = head
        current_prs = {}
        changed = 0
        for pr in pages(api, f"/repos/{repo}/pulls?state=open"):
            number = pr.get("number")
            pr_head = pr.get("head", {}).get("sha", "")
            if not isinstance(number, int) or not SHA_RE.fullmatch(pr_head):
                raise IncompleteEvidence(f"Invalid PR metadata: {repo}")
            current_prs[str(number)] = pr_head
            if state["pr_heads"].get(repo, {}).get(str(number)) == pr_head:
                continue
            files = pages(api, f"/repos/{repo}/pulls/{number}/files")
            findings.extend(scan_files(repo, "PR", str(number), pr_head, files))
            changed += 1
        updated["pr_heads"][repo] = current_prs
        stats[repo] = {"main": head, "main_comparison": delta, "open_prs": len(current_prs), "prs_inspected": changed}
    return findings, updated, stats


def build_issue_body(findings: list[Finding]) -> str:
    first = findings[0]
    status = "VIOLAÇÃO COMPROVADA" if any(f.classification == "COMPROVADA" for f in findings) else "SUSPEITA COM EVIDÊNCIA"
    source = f"PR #{first.origin_id}" if first.origin == "PR" else f"main @ {first.head_sha[:12]}"
    out = ["## Dependency policy watch", "", f"**Estado:** {status}", f"**Repositório fiscalizado:** `{first.repository}`", f"**Origem:** {source}", f"**HEAD SHA:** `{first.head_sha}`", "", "### Evidências adicionadas no diff"]
    for finding in findings:
        out.extend(["", f"- **{finding.technology} / {finding.classification}** — {finding.signal}", f"  - Arquivo: `{finding.path}:{finding.line}`", f"  - Trecho sanitizado: `{finding.evidence.replace('`', '')}`", f"  - Fonte: {finding.url}", f"  {ALERT_MARKER}{finding.signature} -->"])
    out.extend(["", "### Impacto e riscos", "- Contêineres/orquestração: possível violação da arquitetura sem Docker/Podman/Kubernetes; confirmar uso efetivo antes de alterar.", "- Custo: evidência estática não comprova cobrança. Integrações, recursos provisionados e larger runners exigem confirmação de preço, plano e hard stop.", "- Sem autorização para mudanças nos repositórios fiscalizados ou para despesa adicional.", "", "### Menor correção segura", "- Reverter somente a nova dependência no mesmo PR/commit de origem, ou substituir pelo executor nativo já autorizado; preservar testes e controles.", "- Validar o comportamento no SHA alterado, caso positivo/negativo, E2E aplicável e leitura independente antes do merge.", "", "_Alerta emitido automaticamente pelo GitHub Actions do repositório de controle. Nenhuma mudança foi feita no repositório fiscalizado._"])
    return "\n".join(out)


def publish(api: GitHubAPI, findings: list[Finding], known: set[str]) -> list[dict]:
    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for f in findings:
        if f.signature in known:
            continue
        groups.setdefault((f.repository, f.origin, f.origin_id), []).append(f)
        known.add(f.signature)  # dedup within the same run, across source kinds
    created = []
    for (repo, origin, origin_id), items in groups.items():
        technologies = ", ".join(sorted({x.technology for x in items}))
        scope = f"PR #{origin_id}" if origin == "PR" else f"main {origin_id}"
        status = "COMPROVADA" if any(f.classification == "COMPROVADA" for f in items) else "SUSPEITA"
        title = f"[Dependency Watch/{status}] {repo.split('/')[-1]} {scope}: {technologies}"
        data = {"title": title[:230], "body": build_issue_body(items), "assignees": ["ericson-j-santos"]}
        result = api.post(f"/repos/{CONTROLLER}/issues", data)
        if not isinstance(result.get("number"), int):
            raise IncompleteEvidence("GitHub did not return an issue number")
        persisted = api.get(f"/repos/{CONTROLLER}/issues/{result['number']}")
        body = persisted.get("body") or ""
        assignees = persisted.get("assignees") or []
        if not all(f"{ALERT_MARKER}{f.signature} -->" in body for f in items):
            raise IncompleteEvidence("Independent alert issue readback failed")
        if "ericson-j-santos" not in [a.get("login") for a in assignees]:
            raise IncompleteEvidence("Alert owner assignment not persisted")
        created.append({"number": result["number"], "url": result.get("html_url"), "classification": status})
    return created


def save_checkpoint(api: GitHubAPI, checkpoint: dict | None, updated: dict) -> int:
    body = f"{STATE_MARKER}\n\nCheckpoint técnico, não é alerta. Guarda apenas HEADs públicos e PRs abertos.\n\n```json\n{json.dumps(updated, sort_keys=True, indent=2)}\n```\n"
    if checkpoint is None:
        r = api.post(f"/repos/{CONTROLLER}/issues", {"title": STATE_TITLE, "body": body})
    elif checkpoint.get("body") == body:
        return checkpoint["number"]
    else:
        r = api.patch(f"/repos/{CONTROLLER}/issues/{checkpoint['number']}", {"body": body})
    if not isinstance(r.get("number"), int):
        raise IncompleteEvidence("Checkpoint issue was not persisted")
    return r["number"]


def run(api: GitHubAPI, *, dry_run: bool) -> dict:
    checkpoint, state, known = read_issues(api)
    findings, updated, stats = collect(api, state)
    unsent = [f for f in findings if f.signature not in known]
    created = []
    checkpoint_number = checkpoint.get("number") if checkpoint else None
    if not dry_run:
        created = publish(api, findings, known)
        checkpoint_number = save_checkpoint(api, checkpoint, updated)
        # Read back the actual persisted checkpoint after writes.
        reloaded = api.get(f"/repos/{CONTROLLER}/issues/{checkpoint_number}")
        if STATE_MARKER not in (reloaded.get("body") or ""):
            raise IncompleteEvidence("Independent checkpoint readback failed")
        _, actual_state, _ = read_issues(api)
        if actual_state != updated:
            raise IncompleteEvidence("Checkpoint state mismatch on independent readback")
    return {"schema_version": SCHEMA, "dry_run": dry_run, "targets": stats,
            "findings": [asdict(f) for f in findings], "new_finding_count": len(unsent),
            "issues_created": created, "checkpoint_issue": checkpoint_number,
            "verdict": "FINDINGS" if unsent else "NO_NEW_FINDINGS"}


def main() -> int:
    cli = argparse.ArgumentParser(description="Free, native GitHub dependency policy monitor")
    cli.add_argument("--notify", action="store_true", help="Publish deduplicated issues and checkpoint (trusted main only)")
    cli.add_argument("--output", default="", help="Optional JSON output path (not GitHub artifact)")
    args = cli.parse_args()
    if args.notify and not (os.getenv("GITHUB_REPOSITORY") == CONTROLLER and os.getenv("GITHUB_REF") == "refs/heads/main" and os.getenv("GITHUB_EVENT_NAME") in {"schedule", "workflow_dispatch"}):
        print("BLOCKED: issue publication is restricted to scheduled/manual runs on the controller main", file=sys.stderr)
        return 2
    api = GitHubAPI(os.getenv("GITHUB_TOKEN", ""))
    try:
        report = run(api, dry_run=not args.notify)
    except (IncompleteEvidence, ValueError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    # Never print raw report secrets from target repository code: the record
    # contains only sanitised snippets and hashes.
    summary = {k: report[k] for k in ("schema_version", "dry_run", "targets", "new_finding_count", "issues_created", "checkpoint_issue", "verdict")}
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
