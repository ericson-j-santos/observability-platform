from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from observability_platform.failure_analysis import (
    analyze_failure_records,
    render_backlog_markdown,
)
from observability_platform.github_actions_collector import (
    GitHubCollectionError,
    _cancelled_has_successor,
    _fetch_workflow_runs,
    _successful_successor,
    collect_github_actions_run_data,
)


def record(
    workflow: str,
    conclusion: str,
    message: str,
    run_id: str,
    **extra,
) -> dict:
    return {
        "repository": "owner/repo",
        "run_id": run_id,
        "workflow": workflow,
        "conclusion": conclusion,
        "occurred_at": extra.pop("occurred_at", "2026-10-24T12:00:00Z"),
        "message": message,
        **extra,
    }


def workflow_run(
    run_id: int,
    conclusion: str,
    created_at: str,
    *,
    workflow: str = "CI",
    branch: str = "main",
    sha: str = "a" * 40,
    event: str = "push",
    updated_at: str | None = None,
) -> dict:
    return {
        "id": run_id,
        "name": workflow,
        "head_branch": branch,
        "head_sha": sha,
        "created_at": created_at,
        "updated_at": updated_at or created_at,
        "conclusion": conclusion,
        "event": event,
        "html_url": f"https://github.com/owner/repo/actions/runs/{run_id}",
        "run_attempt": 1,
        "pull_requests": [],
    }


class FailureIntelligenceV2Tests(unittest.TestCase):
    def test_backlog_contains_only_active_root_causes(self):
        report = analyze_failure_records(
            [
                record(
                    "Pre-PR Readiness Gate",
                    "failure",
                    "FAILED tests/test_api.py::test_contract - AssertionError",
                    "1001",
                    event="push",
                    head_sha="a" * 40,
                ),
                record(
                    "CI Enterprise Fast",
                    "failure",
                    "ADMISSION_BLOCKED pre_pr_failed_for_head_sha",
                    "1002",
                    event="push",
                    head_sha="a" * 40,
                ),
                record(
                    "Governed Automation",
                    "failure",
                    "COST_UNKNOWN_BLOCKED cost_unknown_no_azure_hard_stop",
                    "1003",
                ),
                record(
                    "CI",
                    "cancelled",
                    "",
                    "1004",
                    cancellation_superseded=True,
                ),
            ],
            generated_at="2026-10-24T12:10:00Z",
        )

        self.assertEqual(report["schema_version"], "observability.failure-analysis/v2")
        self.assertEqual(len(report["actionable_backlog"]), 1)
        self.assertEqual(
            report["actionable_backlog"][0]["category"],
            "test_contract_regression",
        )
        self.assertEqual(report["summary"]["controls"], 1)
        self.assertEqual(report["summary"]["cascades"], 1)
        self.assertEqual(report["summary"]["expected_cancellations"], 1)
        self.assertEqual(
            {
                group["classification"]
                for name in (
                    "root_cause_groups",
                    "control_groups",
                    "cascade_groups",
                    "noise_groups",
                )
                for group in report[name]
            },
            {"root_cause", "control", "cascade", "noise"},
        )

    def test_recovered_root_cause_is_removed_from_active_pareto_and_backlog(self):
        report = analyze_failure_records(
            [
                record(
                    "CI",
                    "failure",
                    "FAILED tests/test_api.py::test_contract - AssertionError",
                    "2001",
                    event="push",
                    head_sha="b" * 40,
                    recovery_observed=True,
                    recovery_run_id="2002",
                )
            ],
            generated_at="2026-10-24T12:10:00Z",
        )

        self.assertEqual(report["active_root_cause_groups"], [])
        self.assertEqual(report["pareto"], [])
        self.assertEqual(report["actionable_backlog"], [])
        recovered = report["recovered_root_cause_groups"][0]
        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(recovered["active_incident_count"], 0)
        self.assertEqual(recovered["recovery_run_ids"], ["2002"])

    def test_pareto_exposes_frequency_impact_and_cumulative_share(self):
        report = analyze_failure_records(
            [
                record(
                    "CI",
                    "failure",
                    "FAILED tests/test_api.py::test_contract - AssertionError",
                    "3001",
                    event="schedule",
                ),
                record(
                    "CI",
                    "failure",
                    "FAILED tests/test_api.py::test_contract - AssertionError",
                    "3002",
                    event="schedule",
                    occurred_at="2026-10-24T13:00:00Z",
                ),
                record("Custom", "failure", "opaque failure", "3003"),
            ],
            generated_at="2026-10-24T13:10:00Z",
        )

        first = report["pareto"][0]
        self.assertEqual(first["category"], "test_contract_regression")
        self.assertEqual(first["frequency_score"], 2)
        self.assertEqual(first["impact_score"], 5)
        self.assertEqual(first["priority_score"], 10)
        self.assertAlmostEqual(first["cumulative_priority_percent"], 76.92, places=2)
        self.assertEqual(first["pareto_tier"], "top_80")

    def test_log_budget_exhaustion_is_control_not_product_bug(self):
        report = analyze_failure_records(
            [record("CI", "failure", "log_budget_exhausted", "4001")],
            generated_at="2026-10-24T13:10:00Z",
        )
        self.assertEqual(report["root_cause_groups"], [])
        self.assertEqual(report["pareto"], [])
        self.assertEqual(
            report["control_groups"][0]["category"],
            "collection_limit_control",
        )

    def test_markdown_is_reproducible_and_separates_exclusions(self):
        report = analyze_failure_records(
            [record("CI", "failure", "opaque failure", "5001")],
            generated_at="2026-10-24T13:10:00Z",
            collection={
                "repository": "owner/repo",
                "window_start": "2026-10-24T12:00:00Z",
                "window_end": "2026-10-24T13:00:00Z",
                "runs_in_window": 2,
                "failure_runs": 1,
                "successful_runs": 1,
            },
        )
        markdown = render_backlog_markdown(report)
        self.assertIn("# Failure intelligence backlog", markdown)
        self.assertIn("## Actionable backlog", markdown)
        self.assertIn("## Excluded from bug backlog", markdown)
        self.assertIn("needs_observability", markdown)
        self.assertEqual(markdown, render_backlog_markdown(report))

    def test_contract_files_are_v2_and_require_backlog(self):
        analysis_schema = json.loads(
            Path("contracts/failure-analysis.schema.json").read_text(encoding="utf-8")
        )
        collection_schema = json.loads(
            Path("contracts/failure-collection.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            analysis_schema["properties"]["schema_version"]["const"],
            "observability.failure-analysis/v2",
        )
        self.assertIn("actionable_backlog", analysis_schema["required"])
        self.assertIn("active_root_cause_groups", analysis_schema["required"])
        self.assertEqual(
            collection_schema["properties"]["schema_version"]["const"],
            "observability.failure-collection/v1",
        )
        self.assertIn("records", collection_schema["required"])


class GitHubActionsCollectionV2Tests(unittest.TestCase):
    def test_concurrency_successor_can_have_new_sha_on_same_branch(self):
        cancelled = workflow_run(
            6001,
            "cancelled",
            "2026-10-24T12:00:00Z",
            sha="a" * 40,
            updated_at="2026-10-24T12:02:00Z",
        )
        successor = workflow_run(
            6002,
            "success",
            "2026-10-24T12:01:30Z",
            sha="b" * 40,
            updated_at="2026-10-24T12:04:00Z",
        )
        other_branch = workflow_run(
            6003,
            "success",
            "2026-10-24T12:01:00Z",
            branch="feature",
            sha="c" * 40,
        )
        other_event = workflow_run(
            6004,
            "success",
            "2026-10-24T12:01:00Z",
            event="workflow_dispatch",
            sha="d" * 40,
        )
        self.assertTrue(_cancelled_has_successor(cancelled, [cancelled, successor]))
        self.assertFalse(_cancelled_has_successor(cancelled, [cancelled, other_branch]))
        self.assertFalse(_cancelled_has_successor(cancelled, [cancelled, other_event]))

    def test_recovery_requires_later_success_in_same_workflow_scope(self):
        failed = workflow_run(7001, "failure", "2026-10-24T12:00:00Z")
        recovered = workflow_run(
            7002,
            "success",
            "2026-10-24T12:10:00Z",
            sha="d" * 40,
        )
        wrong_scope = workflow_run(
            7003,
            "success",
            "2026-10-24T12:05:00Z",
            branch="feature",
        )
        wrong_event = workflow_run(
            7004,
            "success",
            "2026-10-24T12:06:00Z",
            event="workflow_dispatch",
        )
        self.assertEqual(
            _successful_successor(failed, [failed, recovered])["id"],
            7002,
        )
        self.assertIsNone(_successful_successor(failed, [failed, wrong_scope]))
        self.assertIsNone(_successful_successor(failed, [failed, wrong_event]))

    def test_run_collection_paginates_until_requested_limit_or_short_page(self):
        first_page = [
            workflow_run(
                8000 + index,
                "success",
                "2026-10-24T12:00:00Z",
            )
            for index in range(100)
        ]
        second_page = [
            workflow_run(
                9000 + index,
                "success",
                "2026-10-24T11:00:00Z",
            )
            for index in range(20)
        ]
        with patch(
            "observability_platform.github_actions_collector._json",
            side_effect=[
                {"workflow_runs": first_page},
                {"workflow_runs": second_page},
            ],
        ) as mocked:
            runs = _fetch_workflow_runs(
                repository="owner/repo",
                token="not-a-real-token",
                max_runs=150,
                cutoff=datetime(2026, 10, 24, 10, 0, tzinfo=UTC),
            )
        self.assertEqual(len(runs), 120)
        self.assertEqual(mocked.call_count, 2)
        self.assertIn("page=2", mocked.call_args_list[1].args[0])

    def test_collection_records_window_counts_and_recovery(self):
        failed = workflow_run(10001, "failure", "2026-10-24T12:00:00Z")
        recovered = workflow_run(
            10002,
            "success",
            "2026-10-24T12:10:00Z",
            sha="e" * 40,
        )
        jobs = {
            "jobs": [
                {
                    "id": 111,
                    "name": "test",
                    "conclusion": "failure",
                }
            ]
        }
        with (
            patch(
                "observability_platform.github_actions_collector._fetch_workflow_runs",
                return_value=[recovered, failed],
            ),
            patch(
                "observability_platform.github_actions_collector._json",
                return_value=jobs,
            ),
            patch(
                "observability_platform.github_actions_collector._read",
                return_value=b"##[error]FAILED tests/test_api.py::test_contract",
            ),
        ):
            collection = collect_github_actions_run_data(
                repository="owner/repo",
                token="not-a-real-token",
                max_runs=100,
                max_failed_jobs=10,
                since_hours=24,
                now=datetime(2026, 10, 24, 13, 0, tzinfo=UTC),
            )

        self.assertEqual(collection["runs_in_window"], 2)
        self.assertEqual(collection["failure_runs"], 1)
        self.assertEqual(collection["successful_runs"], 1)
        self.assertEqual(collection["failed_job_logs_collected"], 1)
        self.assertTrue(collection["records"][0]["recovery_observed"])
        self.assertEqual(collection["records"][0]["recovery_run_id"], "10002")
        self.assertNotIn("not-a-real-token", json.dumps(collection))

    def test_invalid_repository_fails_before_network_access(self):
        with patch(
            "observability_platform.github_actions_collector._fetch_workflow_runs"
        ) as mocked:
            with self.assertRaisesRegex(GitHubCollectionError, "repository_invalid"):
                collect_github_actions_run_data(
                    repository="owner/repo/../../other",
                    token="not-a-real-token",
                )
        mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
