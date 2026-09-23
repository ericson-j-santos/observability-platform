from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEY = re.compile(
    r"authorization|cookie|token|secret|password|passwd|api[_-]?key|connection[_-]?string",
    re.IGNORECASE,
)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
CPF = re.compile(r"(?<!\d)(?:\d{3}\.?){2}\d{3}-?\d{2}(?!\d)")
PHONE = re.compile(r"(?<!\d)(?:\+?55\s*)?(?:\(?\d{2}\)?\s*)?9?\d{4}[-\s]?\d{4}(?!\d)")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*\b")


def redact(value: Any, key: str | None = None) -> Any:
    if key and SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if not isinstance(value, str):
        return value

    sanitized = BEARER.sub("Bearer [REDACTED]", value)
    sanitized = EMAIL.sub("[REDACTED_EMAIL]", sanitized)
    sanitized = CPF.sub("[REDACTED_CPF]", sanitized)
    sanitized = PHONE.sub("[REDACTED_PHONE]", sanitized)
    return sanitized


def safe_error(error: BaseException) -> dict[str, str]:
    """Never serializes str(error), which may contain credentials or payloads."""
    return {"type": error.__class__.__name__}
