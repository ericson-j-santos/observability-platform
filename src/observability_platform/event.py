from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .redaction import redact

SCHEMA_VERSION = "observability.event/v1"
VALID_SEVERITIES = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _required_text(name: str, value: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        raise ValueError(f"{name}_required")
    return normalized


def build_event(
    *,
    event_name: str,
    service_name: str,
    environment: str,
    correlation_id: str,
    severity: str = "INFO",
    service_version: str = "unknown",
    request_id: str | None = None,
    trace_id: str | None = None,
    span_id: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_severity = severity.strip().upper()
    if normalized_severity not in VALID_SEVERITIES:
        raise ValueError("invalid_severity")

    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "severity": normalized_severity,
        "event_name": _required_text("event_name", event_name),
        "service_name": _required_text("service_name", service_name),
        "service_version": _required_text("service_version", service_version),
        "environment": _required_text("environment", environment),
        "correlation_id": _required_text("correlation_id", correlation_id),
        "attributes": redact(attributes or {}),
    }
    for key, value in {
        "request_id": request_id,
        "trace_id": trace_id,
        "span_id": span_id,
    }.items():
        if value:
            event[key] = str(value).strip()
    return event
