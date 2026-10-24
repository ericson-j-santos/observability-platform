from __future__ import annotations

import unittest

from observability_platform.failure_analysis import analyze_failure_records, classify_record
from observability_platform.github_actions_collector import (
    GitHubCollectionError,
    _cancelled_has_successor,
    _safe_redirect_url,
    diagnostic_excerpt,
)


def rec(
    workflow: str,
    conclusion: str,
    message: str,
    run_id: str = "1000001",
    **extra,
) -> dict:
    return {
        "repository": "owner/repo",
        "run_id": run_id,
        "workflow": workflow,
        "conclusion": conclusion,
        "occurred_at": "2026-10-23T22:00:00Z",
        "message": message,
        **extra,
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
        root_categories = {item["category"]: item for item in report["root_cause_groups"]}
        control_categories = {item["category"]: item for item in report["control_groups"]}
        self.assertEqual(control_categories["cost_governance_block"]["occurrences"], 2)
        self.assertEqual(root_categories["integration_permission_denied"]["occurrences"], 1)
        self.assertNotIn("cost_governance_block", {item["category"] for item in report["pareto"]})

    def test_governed_human_gate_is_control_not_bug(self):
        records = [
            rec(
                "Governed PR Automation",
                "failure",
                "Autorização humana explícita ausente: label governed-merge-approved.",
                "6101",
            ),
            rec(
                "Governed PR Automation",
                "failure",
                "PR ainda está em draft e não pertence à fila recuperada.",
                "6102",
            ),
        ]
        report = analyze_failure_records(records, generated_at="2026-10-23T22:01:00Z")
        self.assertEqual(report["root_cause_groups"], [])
        self.assertEqual(report["pareto"], [])
        self.assertEqual(len(report["control_groups"]), 2)
        signatures = {item["signature"] for item in report["control_groups"]}
        self.assertEqual(signatures, {"human_approval_required", "draft_not_in_recovered_queue"})

    def test_cancelled_run_is_noise_only_with_successor_evidence(self):
        report = analyze_failure_records(
            [rec(
                "Teams Notification Observability",
                "cancelled",
                "",
                "3333333",
                cancellation_superseded=True,
            )],
            generated_at="2026-10-23T22:01:00Z",
        )
        self.assertEqual(report["root_cause_groups"], [])
        self.assertEqual(report["noise_groups"][0]["category"], "concurrency_cancelled")

    def test_cancelled_run_without_successor_is_not_silently_discarded(self):
        report = analyze_failure_records(
            [rec("Custom Workflow", "cancelled", "", "3333334")],
            generated_at="2026-10-23T22:01:00Z",
        )
        self.assertEqual(report["noise_groups"], [])
        self.assertEqual(report["cascade_groups"][0]["category"], "unverified_cancellation")

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


    def test_duplicate_push_and_pr_failure_on_same_sha_is_one_logical_incident(self):
        records = [
            rec(
                "Pre-PR Readiness Gate",
                "failure",
                "FAILED tests/test_runner.py::test_contract - AssertionError",
                "4001",
                event="push",
                head_sha="a" * 40,
            ),
            rec(
                "Pre-PR Readiness Gate",
                "failure",
                "FAILED tests/test_runner.py::test_contract - AssertionError",
                "4002",
                event="pull_request",
                head_sha="a" * 40,
            ),
        ]
        report = analyze_failure_records(records, generated_at="2026-10-23T22:01:00Z")
        group = report["root_cause_groups"][0]
        self.assertEqual(group["occurrences"], 2)
        self.assertEqual(group["incident_count"], 1)
        self.assertEqual(report["pareto"][0]["incident_count"], 1)

    def test_scheduled_recurrence_same_sha_remains_separate_incidents(self):
        records = [
            rec(
                "TODO Global Hourly Cycle",
                "failure",
                "COST_UNKNOWN_BLOCKED cost_unknown_no_azure_hard_stop",
                "5001",
                event="schedule",
                head_sha="b" * 40,
            ),
            rec(
                "TODO Global Hourly Cycle",
                "failure",
                "COST_UNKNOWN_BLOCKED cost_unknown_no_azure_hard_stop",
                "5002",
                event="schedule",
                head_sha="b" * 40,
            ),
        ]
        report = analyze_failure_records(records, generated_at="2026-10-23T22:01:00Z")
        self.assertEqual(report["control_groups"][0]["incident_count"], 2)
        self.assertEqual(report["control_groups"][0]["category"], "cost_governance_block")
        self.assertEqual(report["pareto"], [])

    def test_report_contract_always_separates_controls(self):
        report = analyze_failure_records(
            [rec(
                "TODO Global Hourly Cycle",
                "failure",
                "COST_UNKNOWN_BLOCKED cost_unknown_no_azure_hard_stop",
                "5003",
            )],
            generated_at="2026-10-23T22:01:00Z",
        )
        self.assertIn("control_groups", report)
        self.assertEqual(report["root_cause_groups"], [])
        self.assertEqual(report["cascade_groups"], [])
        self.assertEqual(report["noise_groups"], [])

    def test_stale_published_data_is_a_root_cause(self):
        category, _ = classify_record(
            rec("Dashboard Smoke", "failure", "data.json desatualizado: 61.69h")
        )
        self.assertEqual(category, "data_freshness_stale")

    def test_cancelled_successor_detection_uses_same_workflow_and_target(self):
        old = {
            "id": 1,
            "name": "CI",
            "head_sha": "c" * 40,
            "created_at": "2026-10-23T22:00:00Z",
            "conclusion": "cancelled",
            "pull_requests": [],
        }
        newer = {
            "id": 2,
            "name": "CI",
            "head_sha": "c" * 40,
            "created_at": "2026-10-23T22:01:00Z",
            "conclusion": "success",
            "pull_requests": [],
        }
        self.assertTrue(_cancelled_has_successor(old, [old, newer]))
        self.assertFalse(_cancelled_has_successor(newer, [old, newer]))

    def test_generic_credentials_and_query_tokens_are_redacted(self):
        report = analyze_failure_records(
            [rec(
                "Custom",
                "failure",
                "password=hunter2 api_key=XYZ123 "
                "url=https://example.test/callback?token=sensitive",
            )],
            generated_at="2026-10-23T22:01:00Z",
        )
        sample = report["root_cause_groups"][0]["sample"]
        signature = report["root_cause_groups"][0]["signature"]
        for forbidden in (
            "hunter2", "XYZ123", "sensitive",
        ):
            self.assertNotIn(forbidden, sample)
            self.assertNotIn(forbidden, signature)
        self.assertIn("[REDACTED]", sample)

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
