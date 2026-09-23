from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import e2e_platform_adapter as adapter  # noqa: E402


class E2EPlatformAdapterTests(unittest.TestCase):
    def test_parse_e2e_result_accepts_expected_contract(self) -> None:
        payload = (
            '{"status":"E2E_OK","correlation_id":"obs-correlation-123",'
            '"signals":["logs","metrics","traces"],"loki_lookup":true,"secret_leak":false}\n'
        )
        parsed = adapter.parse_e2e_result(payload, "obs-correlation-123")
        self.assertEqual(parsed["status"], "E2E_OK")

    def test_parse_e2e_result_rejects_correlation_mismatch(self) -> None:
        payload = (
            '{"status":"E2E_OK","correlation_id":"other-correlation",'
            '"signals":["logs","metrics","traces"],"loki_lookup":true,"secret_leak":false}\n'
        )
        with self.assertRaisesRegex(RuntimeError, "e2e_correlation_mismatch"):
            adapter.parse_e2e_result(payload, "obs-correlation-123")

    def test_build_evidence_marks_idempotency_not_applicable(self) -> None:
        now = datetime.now(UTC)
        evidence = adapter.build_evidence(
            repository="ericson-j-santos/observability-platform",
            sha="a" * 40,
            environment="ci",
            correlation_id="obs-correlation-123",
            started_at=now,
            completed_at=now,
        )
        self.assertEqual(evidence["sha"], "a" * 40)
        self.assertTrue(evidence["negative_control"]["passed"])
        self.assertTrue(evidence["independent_read"]["passed"])
        self.assertFalse(evidence["idempotency"]["applicable"])

    def test_ci_pins_platform_sha_consistently(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        platform_sha = "6ca2bf4e63af918872ab5b2b52485cb4f5f07314"
        self.assertIn(
            f"e2e-evidence.yml@{platform_sha}",
            workflow,
        )
        self.assertIn(f"platform_ref: {platform_sha}", workflow)

    def test_build_evidence_rejects_mutable_or_short_sha(self) -> None:
        now = datetime.now(UTC)
        with self.assertRaisesRegex(RuntimeError, "sha_must_be_full_40_chars"):
            adapter.build_evidence(
                repository="ericson-j-santos/observability-platform",
                sha="main",
                environment="ci",
                correlation_id="obs-correlation-123",
                started_at=now,
                completed_at=now,
            )


if __name__ == "__main__":
    unittest.main()
