"""Dependency watch: real diff semantics, negative controls and idempotence."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from observability_platform import dependency_watch as w

REPO1, REPO2 = w.TARGETS
SHA1 = "a" * 40
SHA2 = "b" * 40
SHA3 = "c" * 40


def file(path, added, status="modified"):
    return {"filename": path, "status": status, "patch": "@@ -0,0 +1,1 @@\n+" + added}


class StubAPI:
    def __init__(self, *, changed=True, fail=False):
        self.changed = changed
        self.fail = fail
        self.write_calls = []
        self.issue_store = []
        self.last_id = 10
        self.main_heads = {REPO1: SHA2, REPO2: SHA2}

    def get(self, path):
        if path.startswith(f"/repos/{w.CONTROLLER}/issues?"):
            return deepcopy(self.issue_store)
        if path.startswith(f"/repos/{w.CONTROLLER}/issues/"):
            num = int(path.split("/")[-1])
            return deepcopy(next(x for x in self.issue_store if x["number"] == num))
        for repo in w.TARGETS:
            if path == f"/repos/{repo}":
                return {"full_name": repo, "private": False, "default_branch": "main"}
            if path == f"/repos/{repo}/branches/main":
                return {"commit": {"sha": self.main_heads[repo]}}
            if path.startswith(f"/repos/{repo}/compare/"):
                if self.fail:
                    raise w.IncompleteEvidence("API diff unavailable")
                return {"status": "ahead", "total_commits": 1, "files": [file(".github/workflows/deploy.yml", "run: docker compose up -d")]}
            if path.startswith(f"/repos/{repo}/pulls?state=open"):
                return ([{"number": 7, "head": {"sha": SHA2}}] if repo == REPO1 else [])
            if path.startswith(f"/repos/{repo}/pulls/7/files"):
                return [file(".github/workflows/deploy.yml", "run: docker compose up -d")]
        raise AssertionError("Unexpected GET: " + path)

    def post(self, path, data):
        assert path == f"/repos/{w.CONTROLLER}/issues"
        self.write_calls.append(("POST", path, data))
        self.last_id += 1
        item = {"number": self.last_id, "title": data["title"], "body": data["body"], "state": "open", "user": {"login": w.BOT_LOGIN}, "assignees": [{"login": x} for x in data.get("assignees", [])], "html_url": f"https://github.com/{w.CONTROLLER}/issues/{self.last_id}"}
        self.issue_store.append(item)
        return deepcopy(item)

    def patch(self, path, data):
        assert path.startswith(f"/repos/{w.CONTROLLER}/issues/")
        self.write_calls.append(("PATCH", path, data))
        num = int(path.split("/")[-1])
        for issue in self.issue_store:
            if issue["number"] == num:
                issue.update(data)
                return deepcopy(issue)
        raise AssertionError("Patch missing issue")


def stored_state(api, **kwargs):
    state = w.default_state()
    state["main_heads"] = {REPO1: SHA1, REPO2: SHA2}
    if kwargs.get("pr_already_seen"):
        state["pr_heads"] = {REPO1: {"7": SHA2}}
    api.post(f"/repos/{w.CONTROLLER}/issues", {"title": w.STATE_TITLE, "body": f'{w.STATE_MARKER}\n```json\n{__import__("json").dumps(state)}\n```'})
    api.write_calls.clear()


class DetectionTests(unittest.TestCase):
    def get_one(self, f):
        matches = w.scan_files(REPO1, "PR", "7", SHA2, [f])
        self.assertEqual(len(matches), 1, matches)
        return matches[0]

    def test_docker_workflow_confirmed(self):
        x = self.get_one(file(".github/workflows/test.yml", "run: docker compose up -d"))
        self.assertEqual((x.technology, x.classification, x.line), ("Docker", "COMPROVADA", 1))
        self.assertIn("/pull/7/files", x.url)
        self.assertEqual(x.head_sha, SHA2)

    def test_container_workflow_confirmed(self):
        self.assertEqual(self.get_one(file(".github/workflows/test.yml", "container: python:3.12")).technology, "Docker")

    def test_podman_command(self):
        self.assertEqual(self.get_one(file("scripts/setup.sh", "podman run --rm alpine")).technology, "Podman")

    def test_kubernetes_manifest_and_command(self):
        self.assertEqual(self.get_one(file("k8s/deployment.yaml", "kind: Deployment", "added")).technology, "Kubernetes")
        self.assertEqual(self.get_one(file("scripts/deploy.sh", "kubectl apply -f k8s/")).technology, "Kubernetes")

    def test_dockerfile_and_compose(self):
        self.assertEqual(self.get_one(file("Dockerfile", "FROM python:3.12", "added")).technology, "Docker")
        self.assertEqual(self.get_one(file("compose.dev.yml", "services:", "added")).technology, "Docker")

    def test_explicit_package_dependency(self):
        self.assertEqual(self.get_one(file("requirements.txt", "kubernetes>=30.0")).technology, "Kubernetes")
        self.assertEqual(self.get_one(file("package.json", '"dockerode": "^4"')).technology, "Docker")

    def test_large_paid_runner_is_suspicion_not_proven_billing(self):
        finding = self.get_one(file(".github/workflows/ci.yml", "runs-on: ubuntu-8-core"))
        self.assertEqual((finding.technology, finding.classification), ("Custo adicional", "SUSPEITA"))

    def test_external_deploy_suspected_only(self):
        self.assertEqual(self.get_one(file("scripts/deploy.sh", "fly deploy --remote-only")).classification, "SUSPEITA")

    def test_no_alert_for_docs_removed_lines_test_data_or_comments(self):
        paths = [file("docs/deployment.md", "docker compose up"), file("tests/example.sh", "docker run alpine"), file("scripts/file.sh", "# docker run alpine"), file(".github/workflows/ci.yml", "runs-on: ubuntu-latest")]
        self.assertEqual(w.scan_files(REPO1, "PR", "7", SHA2, paths), [])
        self.assertEqual(w.scan_files(REPO1, "PR", "7", SHA2, [{"filename": "scripts/test.sh", "status": "removed", "patch": "@@ -1 +0,0 @@\n-docker run test"}]), [])

    def test_addition_removal_and_line_number(self):
        patch_text = "@@ -4,3 +4,4 @@\n context\n-docker run old\n+echo hello\n+docker run alpine\n context"
        x = self.get_one({"filename": "scripts/run.sh", "status": "modified", "patch": patch_text})
        self.assertEqual(x.line, 6)

    def test_missing_patch_fails_closed(self):
        with self.assertRaises(w.IncompleteEvidence):
            w.scan_files(REPO1, "PR", "7", SHA2, [{"filename": "scripts/new.sh", "status": "added"}])

    def test_repo_allowlist(self):
        with self.assertRaises(w.IncompleteEvidence):
            w.scan_files("outsider/other", "PR", "7", SHA2, [file("scripts/new.sh", "docker run alpine")])

    def test_secret_redaction_and_mention_neutralization(self):
        sample = "docker run -e token=ghp_abcdefghijk12345678 alpine @owner"
        x = self.get_one(file("scripts/run.sh", sample))
        self.assertNotIn("ghp_", x.evidence)
        self.assertNotIn("@owner", x.evidence)

    def test_signature_stable_within_pr_and_unique_across_sources(self):
        f = file("scripts/a.sh", "docker run alpine")
        a = w.scan_files(REPO1, "PR", "7", SHA1, [f])[0]
        b = w.scan_files(REPO1, "PR", "7", SHA2, [f])[0]
        another = w.scan_files(REPO1, "PR", "8", SHA2, [f])[0]
        main = w.scan_files(REPO1, "main", "12", SHA2, [f])[0]
        self.assertEqual(a.signature, b.signature)
        self.assertNotEqual(a.signature, another.signature)
        self.assertNotEqual(a.signature, main.signature)


class LifecycleTests(unittest.TestCase):
    def test_first_run_baselines_main_and_scans_open_pr(self):
        api = StubAPI()
        report = w.run(api, dry_run=True)
        self.assertEqual(report["new_finding_count"], 1)
        self.assertEqual(report["targets"][REPO1]["main_comparison"], "baseline")
        self.assertEqual(api.write_calls, [])

    def test_notify_then_idempotent_rerun_and_independent_readback(self):
        api = StubAPI()
        first = w.run(api, dry_run=False)
        self.assertEqual(first["new_finding_count"], 1)
        self.assertEqual(len(first["issues_created"]), 1)
        self.assertEqual(len(api.issue_store), 2) # one alert and one checkpoint
        writes_before = len(api.write_calls)
        again = w.run(api, dry_run=False)
        self.assertEqual(again["new_finding_count"], 0)
        self.assertEqual(again["issues_created"], [])
        self.assertEqual(len(api.write_calls), writes_before)

    def test_main_diff_alert_when_cursor_moves_and_finding_not_previously_alerted(self):
        api = StubAPI()
        stored_state(api, pr_already_seen=True)
        report = w.run(api, dry_run=False)
        self.assertEqual(report["targets"][REPO1]["main_comparison"], "compared")
        self.assertEqual(report["new_finding_count"], 1)
        self.assertEqual(len(report["issues_created"]), 1)

    def test_incomplete_diff_cannot_advance_checkpoint_or_alert(self):
        api = StubAPI(fail=True)
        stored_state(api)
        before = deepcopy(api.issue_store)
        with self.assertRaises(w.IncompleteEvidence):
            w.run(api, dry_run=False)
        self.assertEqual(api.issue_store, before)
        self.assertEqual(api.write_calls, [])

    def test_remote_mutations_are_blocked(self):
        github = w.GitHubAPI()
        with self.assertRaises(ValueError):
            github.post(f"/repos/{REPO1}/issues", {"title": "unsafe"})
        with self.assertRaises(ValueError):
            github.patch(f"/repos/{REPO2}/issues/1", {"body": "unsafe"})

    def test_publish_guard_rejects_pr_context_even_when_explicit(self):
        with patch.object(sys, "argv", ["guard", "--notify"]), patch.dict(os.environ, {"GITHUB_REPOSITORY": w.CONTROLLER, "GITHUB_REF": "refs/pull/42/merge", "GITHUB_EVENT_NAME": "pull_request"}):
            self.assertEqual(w.main(), 2)

    def test_untrusted_issue_cannot_spoof_checkpoint_or_dedup(self):
        api = StubAPI()
        api.issue_store.append({"number": 1, "title": w.STATE_TITLE, "body": w.STATE_MARKER, "user": {"login": "attacker"}})
        first = w.run(api, dry_run=False)
        self.assertEqual(first["new_finding_count"], 1)

    def test_marker_correctness(self):
        api = StubAPI()
        w.run(api, dry_run=False)
        alert = next(x for x in api.issue_store if x["title"] != w.STATE_TITLE)
        self.assertIn(w.ALERT_MARKER, alert["body"])
        self.assertIn("HEAD SHA", alert["body"])
        self.assertIn("Menor correção segura", alert["body"])


if __name__ == "__main__":
    unittest.main()
