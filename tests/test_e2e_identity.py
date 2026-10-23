from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import e2e_alert_lifecycle as lifecycle
import e2e_identity as identity
import e2e_platform_adapter as adapter

REPOSITORY = "ericson-j-santos/observability-platform"

PRODUCER = r"""
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
counter = root / "artifacts" / "invocations.txt"
counter.parent.mkdir(parents=True, exist_ok=True)
counter.write_text(str(int(counter.read_text()) + 1) if counter.exists() else "1")
mode = os.environ.get("ADAPTER_TEST_MODE", "ok")
if mode == "dirty":
    (root / "tracked.txt").write_text("modified during test")
elif mode == "commit":
    (root / "tracked.txt").write_text("new commit during test")
    subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "fixture change"], cwd=root, check=True, capture_output=True)
elif mode == "fail":
    raise SystemExit(7)
elif mode == "invalid":
    print("not-json")
    raise SystemExit(0)
print(json.dumps({
    "status": "E2E_OK",
    "correlation_id": os.environ["E2E_CORRELATION_ID"],
    "signals": ["logs", "metrics", "traces"],
    "loki_lookup": True,
    "secret_leak": False,
}))
"""


class GitFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        (self.root / "scripts").mkdir()
        (self.root / "scripts" / "e2e_dev.py").write_text(PRODUCER, encoding="utf-8")
        (self.root / "tracked.txt").write_text("original", encoding="utf-8")
        (self.root / ".gitignore").write_text("artifacts/\n__pycache__/\n", encoding="utf-8")
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "E2E Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("remote", "add", "origin", f"https://github.com/{REPOSITORY}.git")
        self.git("add", ".")
        self.git("commit", "-m", "fixture baseline")
        self.sha = self.git("rev-parse", "HEAD")
        self.output = self.root / "artifacts" / "e2e-platform" / "evidence.json"
        self.environment = {
            "GITHUB_REPOSITORY": REPOSITORY,
            "E2E_EXPECTED_SHA": self.sha,
            "E2E_ENVIRONMENT": "ci",
            "E2E_CORRELATION_ID": "controlled-adapter-run",
            "ADAPTER_TEST_MODE": "ok",
        }

    def git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.root), *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return completed.stdout.strip()

    def old_evidence(self) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text('{"status":"passed","correlation_id":"OLD"}', encoding="utf-8")

    def run_adapter(self, **changes: str) -> dict[str, object]:
        with mock.patch.object(adapter, "ROOT", self.root), mock.patch.dict(
            os.environ, self.environment | changes
        ):
            return adapter.run(self.output)


class CheckoutIdentityTests(GitFixture):
    def test_clean_checkout_matches_real_head_and_repository(self) -> None:
        self.assertEqual(identity.verify_checkout(REPOSITORY, self.sha, root=self.root), self.sha)
        self.assertEqual(identity.verify_checkout(REPOSITORY, self.sha.upper(), root=self.root), self.sha)

    def test_rejects_wrong_sha_and_wrong_root(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "checkout_sha_mismatch"):
            identity.verify_checkout(REPOSITORY, "0" * 40, root=self.root)
        with self.assertRaisesRegex(RuntimeError, "checkout_root_mismatch"):
            identity.verify_checkout(REPOSITORY, self.sha, root=self.root / "scripts")

    def test_rejects_staged_and_unstaged_tracked_changes(self) -> None:
        tracked = self.root / "tracked.txt"
        tracked.write_text("changed", encoding="utf-8")
        for staged in (False, True):
            with self.subTest(staged=staged):
                if staged:
                    self.git("add", "tracked.txt")
                with self.assertRaisesRegex(RuntimeError, "checkout_tracked_changes"):
                    identity.verify_checkout(REPOSITORY, self.sha, root=self.root)

    def test_accepts_canonical_https_and_ssh_origins(self) -> None:
        for origin in (
            f"https://github.com/{REPOSITORY}",
            f"git@github.com:{REPOSITORY}.git",
            f"ssh://git@github.com/{REPOSITORY}.git",
        ):
            with self.subTest(origin=origin):
                self.git("remote", "set-url", "origin", origin)
                self.assertEqual(identity.verify_checkout(REPOSITORY, self.sha, root=self.root), self.sha)

    def test_rejects_other_repository_host_and_credentialed_origin_without_echo(self) -> None:
        for origin in (
            "https://github.com/another/project.git",
            f"https://github.com.evil.invalid/{REPOSITORY}.git",
            f"https://synthetic-user:synthetic-value@github.com/{REPOSITORY}.git",
            f"https://github.com/{REPOSITORY}.git?token=synthetic-value",
            f"https://github.com/{REPOSITORY}.git#fragment",
        ):
            self.git("remote", "set-url", "origin", origin)
            with self.assertRaisesRegex(RuntimeError, "^checkout_repository_mismatch$") as error:
                identity.verify_checkout(REPOSITORY, self.sha, root=self.root)
            self.assertNotIn("synthetic-value", str(error.exception))

    def test_safe_output_does_not_delete_tracked_or_external_files(self) -> None:
        original = (self.root / "tracked.txt").read_text()
        with self.assertRaisesRegex(RuntimeError, "evidence_output_outside_artifacts"):
            identity.prepare_evidence_path(self.root / "tracked.txt", root=self.root)
        self.assertEqual((self.root / "tracked.txt").read_text(), original)
        self.old_evidence()
        self.git("add", "-f", self.output.relative_to(self.root).as_posix())
        with self.assertRaisesRegex(RuntimeError, "evidence_output_tracked"):
            identity.prepare_evidence_path(self.output, root=self.root)
        self.assertTrue(self.output.exists())

    def test_safe_output_rejects_file_and_parent_symlinks(self) -> None:
        target = Path(self.temporary.name) / "external.json"
        target.write_text("preserve", encoding="utf-8")
        self.output.parent.mkdir(parents=True)
        self.output.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "evidence_output_symlink"):
            identity.prepare_evidence_path(self.output, root=self.root)
        self.assertEqual(target.read_text(), "preserve")
        self.output.unlink()
        link = self.output.parent / "linked"
        link.symlink_to(target.parent, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "evidence_output_symlink"):
            identity.prepare_evidence_path(link / "external.json", root=self.root)
        self.assertEqual(target.read_text(), "preserve")

    def test_failed_atomic_write_leaves_no_partial_json_or_temporary(self) -> None:
        output = identity.prepare_evidence_path(self.output, root=self.root)
        with self.assertRaises(TypeError):
            identity.write_evidence(output, {"invalid": object()})
        self.assertFalse(output.exists())
        self.assertEqual(list(output.parent.glob(".evidence-*.tmp")), [])


class AdapterFlowTests(GitFixture):
    def test_positive_result_is_bound_to_real_git_head_and_replay_runs_again(self) -> None:
        self.old_evidence()
        first = self.run_adapter()
        self.assertEqual(first["sha"], self.sha)
        self.assertEqual(json.loads(self.output.read_text())["correlation_id"], "controlled-adapter-run")
        self.run_adapter(E2E_CORRELATION_ID="second-controlled-run")
        self.assertEqual((self.root / "artifacts" / "invocations.txt").read_text(), "2")
        self.assertEqual(json.loads(self.output.read_text())["correlation_id"], "second-controlled-run")
        self.assertEqual(list(self.output.parent.glob(".evidence-*.tmp")), [])

    def test_wrong_sha_is_rejected_before_producer_and_old_evidence_removed(self) -> None:
        self.old_evidence()
        with self.assertRaisesRegex(RuntimeError, "checkout_sha_mismatch"):
            self.run_adapter(E2E_EXPECTED_SHA="0" * 40)
        self.assertFalse(self.output.exists())
        self.assertFalse((self.root / "artifacts" / "invocations.txt").exists())

    def test_invalid_identity_removes_old_evidence_before_preflight(self) -> None:
        self.old_evidence()
        with self.assertRaisesRegex(RuntimeError, "sha_must_be_full_40_chars"):
            self.run_adapter(E2E_EXPECTED_SHA="main")
        self.assertFalse(self.output.exists())
        self.assertFalse((self.root / "artifacts" / "invocations.txt").exists())

    def test_failed_or_invalid_producer_cannot_reuse_old_evidence(self) -> None:
        for mode in ("fail", "invalid"):
            with self.subTest(mode=mode):
                self.old_evidence()
                with self.assertRaises(RuntimeError):
                    self.run_adapter(ADAPTER_TEST_MODE=mode)
                self.assertFalse(self.output.exists())

    def test_postflight_rejects_tracked_changes(self) -> None:
        self.old_evidence()
        with self.assertRaisesRegex(RuntimeError, "checkout_tracked_changes"):
            self.run_adapter(ADAPTER_TEST_MODE="dirty")
        self.assertFalse(self.output.exists())

    def test_postflight_rejects_changed_head(self) -> None:
        self.old_evidence()
        with self.assertRaisesRegex(RuntimeError, "checkout_sha_mismatch"):
            self.run_adapter(ADAPTER_TEST_MODE="commit")
        self.assertFalse(self.output.exists())
        self.assertNotEqual(self.git("rev-parse", "HEAD"), self.sha)

    def test_lifecycle_preflight_blocks_before_runtime_and_removes_old_evidence(self) -> None:
        self.old_evidence()
        with mock.patch.object(lifecycle, "ROOT", self.root), mock.patch.dict(
            os.environ, self.environment | {"E2E_EXPECTED_SHA": "0" * 40}
        ), mock.patch.object(lifecycle, "compose") as compose:
            with self.assertRaisesRegex(RuntimeError, "checkout_sha_mismatch"):
                lifecycle.run(self.output)
            compose.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_lifecycle_restores_collector_before_postflight_rejection(self) -> None:
        self.old_evidence()

        def mutate_source(*args: str) -> None:
            if args == ("stop", "collector"):
                (self.root / "tracked.txt").write_text("changed during lifecycle")

        with mock.patch.object(lifecycle, "ROOT", self.root), mock.patch.dict(
            os.environ, self.environment
        ), mock.patch.object(lifecycle, "wait_http"), mock.patch.object(
            lifecycle, "wait_for_up"
        ), mock.patch.object(lifecycle, "wait_for_alert"), mock.patch.object(
            lifecycle, "compose", side_effect=mutate_source
        ) as compose:
            with self.assertRaisesRegex(RuntimeError, "checkout_tracked_changes"):
                lifecycle.run(self.output)
            self.assertEqual(
                compose.call_args_list,
                [mock.call("stop", "collector"), mock.call("start", "collector")],
            )
        self.assertFalse(self.output.exists())

    def test_lifecycle_attempts_restore_when_stop_fails(self) -> None:
        self.old_evidence()
        calls: list[tuple[str, ...]] = []

        def fail_stop(*args: str) -> None:
            calls.append(args)
            if args == ("stop", "collector"):
                raise RuntimeError("synthetic_stop_failure")

        with mock.patch.object(lifecycle, "ROOT", self.root), mock.patch.dict(
            os.environ, self.environment
        ), mock.patch.object(lifecycle, "wait_http"), mock.patch.object(
            lifecycle, "wait_for_up"
        ), mock.patch.object(lifecycle, "wait_for_alert"), mock.patch.object(
            lifecycle, "compose", side_effect=fail_stop
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic_stop_failure"):
                lifecycle.run(self.output)
        self.assertEqual(calls, [("stop", "collector"), ("start", "collector")])
        self.assertFalse(self.output.exists())

    def test_ci_checks_out_evidence_head_and_limits_artifact_retention(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("retention-days: 1\n", workflow)
        self.assertIn("python scripts/evidence_regression_witness.py", workflow)


if __name__ == "__main__":
    unittest.main()
