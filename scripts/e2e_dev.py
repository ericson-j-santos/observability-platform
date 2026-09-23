#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from observability_platform.event import build_event  # noqa: E402

COLLECTOR = os.getenv("OTEL_HTTP_ENDPOINT", "http://127.0.0.1:4318")
LOKI = os.getenv("LOKI_HTTP_ENDPOINT", "http://127.0.0.1:3100")
EVIDENCE_FILES = {
    "logs": "/evidence/logs.json",
    "metrics": "/evidence/metrics.json",
    "traces": "/evidence/traces.json",
}


def request_json(method: str, url: str, payload: dict | None = None, timeout: float = 5.0):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode() or "{}"
            return response.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(
            f"http_request_failed method={method} url={url} status={exc.code} body={body[:1000]}"
        ) from exc


def wait_http(url: str, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 300:
                    return
        except Exception as exc:
            last = exc
        time.sleep(1)
    raise RuntimeError(f"service_not_ready url={url} last={type(last).__name__ if last else 'unknown'}")


def post_signal(path: str, payload: dict) -> None:
    status, _ = request_json("POST", f"{COLLECTOR}{path}", payload)
    if status not in (200, 202):
        raise RuntimeError(f"collector_rejected signal={path} status={status}")


def read_evidence(signal: str) -> str:
    path = EVIDENCE_FILES[signal]
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(ROOT / "compose.dev.yml"),
            "exec",
            "-T",
            "evidence-reader",
            "cat",
            path,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return result.stdout if result.returncode == 0 else ""


def wait_evidence(signal: str, markers: list[str], timeout: float = 30.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = read_evidence(signal)
        if text and all(marker in text for marker in markers):
            return text
        time.sleep(1)
    raise RuntimeError(f"collector_evidence_missing signal={signal} markers={markers}")


def query_loki(correlation_id: str, timeout: float = 30.0) -> str:
    deadline = time.time() + timeout
    query = '{service_name="observability-e2e"}'
    url = f"{LOKI}/loki/api/v1/query_range?{urllib.parse.urlencode({'query': query, 'limit': 100})}"
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            status, payload = request_json("GET", url)
            rendered = json.dumps(payload)
            if status == 200 and correlation_id in rendered:
                return rendered
        except Exception as exc:
            last_error = exc
        time.sleep(1)
    raise RuntimeError(
        f"loki_correlation_not_found last={type(last_error).__name__ if last_error else 'none'}"
    )


def main() -> int:
    wait_http(f"{LOKI}/ready")
    wait_http("http://127.0.0.1:13133")

    correlation_id = f"e2e-{uuid.uuid4()}"
    secret = f"secret-{uuid.uuid4()}"
    event = build_event(
        event_name="observability.e2e.completed",
        service_name="observability-e2e",
        service_version="0.1.0",
        environment="ci",
        correlation_id=correlation_id,
        attributes={"token": secret, "result": "ok"},
    )
    rendered_event = json.dumps(event, separators=(",", ":"))
    if secret in rendered_event:
        raise RuntimeError("redaction_failed_before_transport")

    now = str(time.time_ns())
    resource = {
        "attributes": [
            {"key": "service.name", "value": {"stringValue": "observability-e2e"}},
            {"key": "deployment.environment.name", "value": {"stringValue": "ci"}}
        ]
    }

    post_signal("/v1/logs", {
        "resourceLogs": [{
            "resource": resource,
            "scopeLogs": [{
                "scope": {"name": "observability.e2e"},
                "logRecords": [{
                    "timeUnixNano": now,
                    "severityText": "INFO",
                    "body": {"stringValue": rendered_event},
                    "attributes": [{"key": "correlation_id", "value": {"stringValue": correlation_id}}]
                }]
            }]
        }]
    })

    metric_marker = f"metric-{correlation_id}"
    post_signal("/v1/metrics", {
        "resourceMetrics": [{
            "resource": resource,
            "scopeMetrics": [{
                "scope": {"name": "observability.e2e"},
                "metrics": [{
                    "name": "observability.e2e.requests",
                    "description": "E2E metric",
                    "unit": "1",
                    "gauge": {
                        "dataPoints": [{
                            "timeUnixNano": now,
                            "asInt": "1",
                            "attributes": [
                                {"key": "correlation_id", "value": {"stringValue": correlation_id}},
                                {"key": "e2e.metric.marker", "value": {"stringValue": metric_marker}}
                            ]
                        }]
                    }
                }]
            }]
        }]
    })

    trace_marker = f"trace-{correlation_id}"
    trace_id = uuid.uuid4().hex
    span_id = uuid.uuid4().hex[:16]
    post_signal("/v1/traces", {
        "resourceSpans": [{
            "resource": resource,
            "scopeSpans": [{
                "scope": {"name": "observability.e2e"},
                "spans": [{
                    "traceId": trace_id,
                    "spanId": span_id,
                    "name": "observability.e2e",
                    "kind": "SPAN_KIND_INTERNAL",
                    "startTimeUnixNano": now,
                    "endTimeUnixNano": str(time.time_ns()),
                    "attributes": [
                        {"key": "correlation_id", "value": {"stringValue": correlation_id}},
                        {"key": "e2e.trace.marker", "value": {"stringValue": trace_marker}}
                    ],
                    "status": {"code": "STATUS_CODE_OK"}
                }]
            }]
        }]
    })

    logs_evidence = wait_evidence("logs", [correlation_id, "[REDACTED]"])
    metrics_evidence = wait_evidence("metrics", [correlation_id, metric_marker])
    traces_evidence = wait_evidence("traces", [correlation_id, trace_marker])
    evidence = logs_evidence + metrics_evidence + traces_evidence
    if secret in evidence:
        raise RuntimeError("secret_leaked_to_collector_evidence")

    loki_result = query_loki(correlation_id)
    if secret in loki_result:
        raise RuntimeError("secret_leaked_to_loki")
    if "[REDACTED]" not in loki_result:
        raise RuntimeError("redaction_marker_missing_in_loki")

    print(json.dumps({
        "status": "E2E_OK",
        "correlation_id": correlation_id,
        "signals": ["logs", "metrics", "traces"],
        "loki_lookup": True,
        "secret_leak": False
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
