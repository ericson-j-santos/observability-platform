#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

from e2e_identity import prepare_evidence_path, verify_checkout, write_evidence

ROOT = Path(__file__).resolve().parents[1]
PROMETHEUS = os.getenv("PROMETHEUS_HTTP_ENDPOINT", "http://127.0.0.1:9090")
ALERTMANAGER = os.getenv("ALERTMANAGER_HTTP_ENDPOINT", "http://127.0.0.1:9093")
COLLECTOR_HEALTH = os.getenv("COLLECTOR_HEALTH_ENDPOINT", "http://127.0.0.1:13133")
ALERT_NAME = "ObservabilityCollectorUnavailable"
JOB_NAME = "observability-collector-otlp-metrics"


def request_json(url: str, timeout: float = 5.0):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        body = response.read().decode() or "{}"
        return response.status, json.loads(body)


def wait_http(url: str, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 300:
                    return
        except Exception as exc:
            last_error = exc
        time.sleep(1)
    raise RuntimeError(
        f"service_not_ready endpoint={url} last={type(last_error).__name__ if last_error else 'unknown'}"
    )


def compose(*args: str) -> None:
    result = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "compose.dev.yml"), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"compose_failed action={' '.join(args)} returncode={result.returncode}")


def prometheus_up() -> float | None:
    query = f'up{{job="{JOB_NAME}"}}'
    url = f"{PROMETHEUS}/api/v1/query?{urllib.parse.urlencode({'query': query})}"
    status, payload = request_json(url)
    if status != 200 or payload.get("status") != "success":
        return None
    result = payload.get("data", {}).get("result", [])
    if not result:
        return None
    try:
        return float(result[0]["value"][1])
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def active_alerts() -> list[dict]:
    query = urllib.parse.urlencode(
        {"active": "true", "silenced": "false", "inhibited": "false", "unprocessed": "false"}
    )
    status, payload = request_json(f"{ALERTMANAGER}/api/v2/alerts?{query}")
    if status != 200 or not isinstance(payload, list):
        raise RuntimeError("alertmanager_invalid_response")
    return [
        alert
        for alert in payload
        if alert.get("labels", {}).get("alertname") == ALERT_NAME
        and alert.get("status", {}).get("state") == "active"
    ]


def wait_for_up(expected: float, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if prometheus_up() == expected:
            return
        time.sleep(1)
    raise RuntimeError(f"prometheus_target_state_timeout expected={expected}")


def wait_for_alert(active: bool, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if bool(active_alerts()) is active:
            return
        time.sleep(1)
    raise RuntimeError(f"alert_state_timeout expected_active={str(active).lower()}")


def validate_sha(value: str) -> str:
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value.lower()):
        raise RuntimeError("e2e_expected_sha_must_be_full_40_chars")
    return value.lower()


def run(output_path: Path) -> dict[str, object]:
    output_path = prepare_evidence_path(output_path, root=ROOT)
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    expected_sha = validate_sha(os.environ["E2E_EXPECTED_SHA"])
    observed_sha = verify_checkout(repository, expected_sha, root=ROOT)
    correlation_id = os.environ["E2E_CORRELATION_ID"].strip()
    environment = os.getenv("E2E_ENVIRONMENT", "ci").strip() or "ci"
    if not correlation_id:
        raise RuntimeError("e2e_correlation_id_required")

    wait_http(f"{PROMETHEUS}/-/ready")
    wait_http(f"{ALERTMANAGER}/-/ready")
    wait_http(COLLECTOR_HEALTH)

    wait_for_up(1.0)
    wait_for_alert(False)
    initial_control_absent = True

    collector_stop_attempted = False
    firing_observed = False
    try:
        collector_stop_attempted = True
        compose("stop", "collector")
        wait_for_up(0.0)
        wait_for_alert(True)
        firing_observed = True
    finally:
        if collector_stop_attempted:
            compose("start", "collector")

    wait_http(COLLECTOR_HEALTH)
    wait_for_up(1.0)
    wait_for_alert(False)

    verify_checkout(repository, observed_sha, root=ROOT)
    evidence = {
        "schema_version": "observability.alert-lifecycle/v1",
        "status": "ALERT_E2E_OK",
        "repository": repository,
        "sha": observed_sha,
        "environment": environment,
        "correlation_id": correlation_id,
        "alert_name": ALERT_NAME,
        "control_initial_absent": initial_control_absent,
        "scrape_down_observed": firing_observed,
        "firing_observed": firing_observed,
        "target_recovered": True,
        "resolved_observed": True,
        "production_touched": False,
    }
    write_evidence(output_path, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/e2e-platform/alert-lifecycle.json"),
    )
    args = parser.parse_args()
    try:
        evidence = run(args.output)
    except Exception as exc:
        print(json.dumps({"result": "ALERT_E2E_FAILED", "error": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
