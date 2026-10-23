from __future__ import annotations

import unittest

from observability_platform.failure_analysis import analyze_failure_records, classify_record
from observability_platform.github_actions_collector import GitHubCollectionError, _safe_redirect_url, diagnostic_excerpt


def rec(workflow: str, conclusion: str, message: str, run_id: str = "1000001") -> dict:
    return {
        "repository": "owner/repo",
        "run_id": run_id,
        "workflow": workflow,
        "conclusion": conclusion,
        "occurred_at": "2026-10-23T22:00:00Z",
        "message": message,
    }


class FailureAnalysisTests(unittest.TestCase):
    def test_primary_contract_failure_is_not_multiplied_by_admission_cascades(self):
        records = [
            rec(
                "Pre-PR Readiness Gate",
                "failure",
                "FAILED tests/test_runner.py::test_contract - AssertionError\n2 failed, 988 passed",
                "1000001",
            ),
            rec(
                "CI Enterprise Fast",
                "failure",
                '{"result":"ADMISSION_BLOCKED","reason":"pre_pr_failed_for_head_sha"}',
                "1000002",
            ),
            rec(
                "CI — ReqSys v2 Enterprise",
                "failure",
                '{"result":"ADMISSION_BLOCKED","reason":"pre_pr_failed_for_head_sha"}',
                "1000003",
            ),
        ]
        report = analyze_failure_records(records, generated_at="2026-10-23T22:01:00Z")
        self.assertEqual(report["root_cause_groups"][0]["category"], "test_contract_regression")
        self.assertEqual(report["root_cause_groups"][0]["occurrences"], 1)
        self.assertEqual(report["cascade_groups"][0]["category"], "admission_cascade")
        self.assertEqual(report["cascade_groups"][0]["occurrences"], 2)

    def test_cost_and_permission_failures_get_stable_fingerprints(self):
        records = [
            rec("TODO Global Hourly Cycle", "failure", "COST_UNKNOWN_BLOCKED cost_unknown_no_azure_hard_stop", "1234567"),
            rec("TODO Global Hourly Cycle", "failure", "COST_UNKNOWN_BLOCKED cost_unknown_no_azure_hard_stop run=9876543", "7654321"),
            rec("Notify Teams - ReqSys Logs", "failure", "HttpError: Resource not accessible by integration", "2222222"),
        ]
        report = analyze_failure_records(records, generated_at="2026-10-23T22:01:00Z")
        categories = {item["category"]: item for item in report["root_cause_groups"]}
        self.assertEqual(categories["cost_governance_block"]["occurrences"], 2)
        self.assertEqual(categories["integration_permission_denied"]["occurrences"], 1)

    def test_cancelled_runs_are_noise_not_root_causes(self):
        report = analyze_failure_records(
            [rec("Teams Notification Observability", "cancelled", "", "3333333")],
            generated_at="2026-10-23T22:01:00Z",
        )
        self.assertEqual(report["root_cause_groups"], [])
        self.assertEqual(report["noise_groups"][0]["category"], "concurrency_cancelled")

    def test_sensitive_sample_is_redacted(self):
        report = analyze_failure_records(
            [rec("Custom", "failure", "failed for user alice@example.com with Bearer abc.def.ghi")],
            generated_at="2026-10-23T22:01:00Z",
        )
        sample = report["root_cause_groups"][0]["sample"]
        self.assertNotIn("alice@example.com", sample)
        self.assertNotIn("abc.def.ghi", sample)
        self.assertIn("[REDACTED_EMAIL]", sample)
        self.assertIn("Bearer [REDACTED]", sample)

    def test_missing_identity_field_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "missing_fields"):
            analyze_failure_records([{"workflow": "x"}])

    def test_collector_excerpt_keeps_diagnostics_and_discards_noise(self):
        log = "\n".join([
            "normal startup line",
            "##[error]Process completed with exit code 1.",
            "COST_UNKNOWN_BLOCKED cost_unknown_no_azure_hard_stop",
            "healthy line",
        ])
        excerpt = diagnostic_excerpt(log)
        self.assertNotIn("normal startup", excerpt)
        self.assertNotIn("healthy line", excerpt)
        self.assertIn("exit code 1", excerpt)
        self.assertIn("COST_UNKNOWN_BLOCKED", excerpt)

    def test_gate_generic_exit_is_cascade(self):
        category, _ = classify_record(
            rec("PR CI Watch", "failure", "Process completed with exit code 1.")
        )
        self.assertEqual(category, "gate_cascade")


    def test_log_redirect_never_allows_arbitrary_host(self):
        self.assertEqual(
            _safe_redirect_url("https://productionresultssa9.blob.core.windows.net/x"),
            "https://productionresultssa9.blob.core.windows.net/x",
        )
        with self.assertRaisesRegex(GitHubCollectionError, "redirect_not_allowlisted"):
            _safe_redirect_url("https://example.com/steal")
        with self.assertRaisesRegex(GitHubCollectionError, "redirect_not_allowlisted"):
            _safe_redirect_url("http://productionresultssa9.blob.core.windows.net/x")


if __name__ == "__main__":
    unittest.main()
