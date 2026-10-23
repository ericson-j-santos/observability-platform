#!/usr/bin/env python3
"""Demonstrate that the same regression controls fail before the fix and pass now."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from e2e_identity import prepare_evidence_path, verify_checkout, write_evidence

ROOT = Path(__file__).resolve().parents[1]
BASELINE_SHA = "880ea825d00027f405c6801f31b9944e653a3784"
CONTROLS = (
    "test_wrong_sha_is_rejected_before_producer_and_old_evidence_removed",
    "test_invalid_identity_removes_old_evidence_before_preflight",
)


def main() -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    expected_sha = os.environ.get("E2E_EXPECTED_SHA", "")
    sha = verify_checkout(repository, expected_sha, root=ROOT)
    output = prepare_evidence_path(Path("artifacts/e2e-platform/regression-witness.json"), root=ROOT)
    baseline = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{BASELINE_SHA}:scripts/e2e_platform_adapter.py"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout

    sys.path.insert(0, str(ROOT / "tests"))
    import test_e2e_identity as controls

    current_adapter = controls.adapter
    with tempfile.TemporaryDirectory() as temporary:
        legacy_path = Path(temporary) / "legacy_adapter.py"
        legacy_path.write_text(baseline, encoding="utf-8")
        spec = importlib.util.spec_from_file_location("legacy_evidence_adapter", legacy_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("baseline_adapter_load_failed")
        legacy_adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy_adapter)
        try:
            controls.adapter = legacy_adapter
            old_result = unittest.TextTestRunner(stream=io.StringIO()).run(
                unittest.TestSuite(controls.AdapterFlowTests(name) for name in CONTROLS)
            )
        finally:
            controls.adapter = current_adapter

    if old_result.testsRun != len(CONTROLS) or old_result.errors or len(old_result.failures) != len(CONTROLS):
        raise RuntimeError("baseline_did_not_reproduce_expected_regressions")

    new_result = unittest.TextTestRunner(stream=io.StringIO()).run(
        unittest.TestSuite(controls.AdapterFlowTests(name) for name in CONTROLS)
    )
    if new_result.testsRun != len(CONTROLS) or not new_result.wasSuccessful():
        raise RuntimeError("current_adapter_regression_controls_failed")

    verify_checkout(repository, sha, root=ROOT)
    evidence = {
        "status": "REGRESSION_WITNESS_OK",
        "repository": repository,
        "sha": sha,
        "baseline_sha": BASELINE_SHA,
        "controls": list(CONTROLS),
        "baseline_expected_failures": len(old_result.failures),
        "current_passed": new_result.testsRun,
        "scope": "adapter_protocol_in_temporary_git_repositories; not_stack_e2e",
    }
    write_evidence(output, evidence)
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
