#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def validate_identity(repository: str, sha: str) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise RuntimeError("repository_invalid")
    if not SHA_RE.fullmatch(sha):
        raise RuntimeError("sha_must_be_full_40_chars")


def parse_e2e_result(stdout: str, expected_correlation_id: str) -> dict[str, object]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("e2e_result_missing")
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise RuntimeError("e2e_result_invalid_json") from exc
    if payload.get("status") != "E2E_OK":
        raise RuntimeError("e2e_status_not_ok")
    if payload.get("correlation_id") != expected_correlation_id:
        raise RuntimeError("e2e_correlation_mismatch")
    if set(payload.get("signals") or []) != {"logs", "metrics", "traces"}:
        raise RuntimeError("e2e_signals_incomplete")
    if payload.get("loki_lookup") is not True:
        raise RuntimeError("e2e_independent_read_missing")
    if payload.get("secret_leak") is not False:
        raise RuntimeError("e2e_negative_control_failed")
    return payload


def build_evidence(
    *,
    repository: str,
    sha: str,
    environment: str,
    correlation_id: str,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, object]:
    validate_identity(repository, sha)
    return {
        "schema_version": "1.0.0",
        "project": "Observability Platform",
        "repository": repository,
        "sha": sha.lower(),
        "environment": environment,
        "correlation_id": correlation_id,
        "objective": "Validar logs, métricas e traces com redaction e leitura independente no Loki.",
        "status": "passed",
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
        "positive_control": {
            "passed": True,
            "evidence": "collector_logs_metrics_traces_correlated; loki_lookup=true",
        },
        "negative_control": {
            "applicable": True,
            "passed": True,
            "evidence": "synthetic_secret_absent_from_collector_and_loki; redaction_marker_present",
        },
        "independent_read": {
            "passed": True,
            "source": "Loki query_range by correlation_id",
            "evidence": "loki_lookup=true",
        },
        "idempotency": {
            "applicable": False,
            "passed": None,
            "evidence": "Fluxo de telemetria append-only; não há mutação idempotente neste cenário.",
        },
        "test_of_test": {
            "applicable": False,
            "passed": None,
            "evidence": "Validação fail-closed exercitada pelos self-tests versionados do e2e-platform.",
        },
    }


def run(output_path: Path) -> dict[str, object]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("E2E_EXPECTED_SHA") or os.environ.get("GITHUB_SHA", "")
    environment = os.environ.get("E2E_ENVIRONMENT", "ci")
    correlation_id = os.environ.get("E2E_CORRELATION_ID") or f"observability-{uuid.uuid4().hex[:16]}"
    validate_identity(repository, sha)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = output_path.with_name("observability-e2e.log")
    started_at = datetime.now(UTC)

    env = os.environ.copy()
    env["E2E_CORRELATION_ID"] = correlation_id
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "e2e_dev.py")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    combined = completed.stdout + completed.stderr
    log_path.write_text(combined, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"observability_e2e_failed:{completed.returncode}")
    parse_e2e_result(completed.stdout, correlation_id)

    evidence = build_evidence(
        repository=repository,
        sha=sha,
        environment=environment,
        correlation_id=correlation_id,
        started_at=started_at,
        completed_at=datetime.now(UTC),
    )
    output_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/e2e-platform/evidence.json"),
    )
    args = parser.parse_args()
    try:
        evidence = run(args.output)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "result": "OBSERVABILITY_E2E_PLATFORM_ADAPTER_FAILED",
                    "error": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(
            {
                "result": "OBSERVABILITY_E2E_PLATFORM_ADAPTER_PASSED",
                "sha": evidence["sha"],
                "correlation_id": evidence["correlation_id"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
