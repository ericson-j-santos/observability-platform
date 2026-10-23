from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, Iterable

from .redaction import redact

REPORT_SCHEMA = "observability.failure-analysis/v1"

_SHA = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
_LONG_NUMBER = re.compile(r"\b\d{6,}\b")
_TIMESTAMP = re.compile(r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b")
_FAILED_TEST = re.compile(r"\bFAILED\s+([^\s]+)")
_EXIT_CODE = re.compile(r"process completed with exit code \d+\.?", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|access[-_]?token|refresh[-_]?token|"
    r"id[-_]?token|api[-_]?key|client[-_]?secret|authorization|connection[-_]?string)"
    r"\b\s*[:=]\s*[^\s,;]+"
)
_SECRET_QUERY = re.compile(
    r"(?i)([?&](?:access_token|token|api_key|key|sig|signature|code)=)[^&#\s]+"
)

CHANGE_SCOPED_EVENTS = {"push", "pull_request", "pull_request_target", "merge_group"}
CASCADE_WORKFLOW_MARKERS = (
    "evidence gate",
    "ci watch",
    "remediation",
    "merge queue",
    "admission",
)

CATEGORY_META: dict[str, dict[str, Any]] = {
    "test_contract_regression": {
        "root_cause": True, "noise": False, "severity": "high", "weight": 5,
        "hint": "Corrigir o contrato/teste na mesma mudança funcional e adicionar regressão que acompanhe o novo comportamento.",
    },
    "cost_governance_block": {
        "root_cause": True, "noise": False, "severity": "high", "weight": 5,
        "hint": "Comprovar custo incremental zero e hard stop; não contornar a governança financeira.",
    },
    "integration_permission_denied": {
        "root_cause": True, "noise": False, "severity": "high", "weight": 5,
        "hint": "Ajustar somente a permissão mínima necessária da integração e validar acesso positivo/negativo.",
    },
    "runner_unavailable": {
        "root_cause": True, "noise": False, "severity": "high", "weight": 5,
        "hint": "Recuperar o executor governado e comprovar pickup + sessão + efeito real antes de repetir a tarefa.",
    },
    "data_freshness_stale": {
        "root_cause": True, "noise": False, "severity": "high", "weight": 4,
        "hint": "Corrigir o produtor/publicador responsável pela atualização e provar frescor por leitura independente.",
    },
    "contract_invalid": {
        "root_cause": True, "noise": False, "severity": "high", "weight": 4,
        "hint": "Alinhar contrato, implementação e critérios de aceite; não relaxar o gate para ocultar divergência.",
    },
    "quality_gate_lint": {
        "root_cause": True, "noise": False, "severity": "medium", "weight": 3,
        "hint": "Corrigir o lint na fonte e manter o gate bloqueante; rerun sem mudança não é correção.",
    },
    "workflow_dependency_wait": {
        "root_cause": False, "noise": False, "severity": "medium", "weight": 2,
        "hint": "Corrigir a dependência upstream ou o contrato de espera; não tratar o gate derivado como causa primária.",
    },
    "admission_cascade": {
        "root_cause": False, "noise": False, "severity": "medium", "weight": 1,
        "hint": "Rastrear para o gate upstream que bloqueou a admissão e corrigir somente a causa original.",
    },
    "gate_cascade": {
        "root_cause": False, "noise": False, "severity": "medium", "weight": 1,
        "hint": "Identificar o workflow upstream que falhou; este registro é efeito cascata.",
    },
    "concurrency_cancelled": {
        "root_cause": False, "noise": True, "severity": "low", "weight": 1,
        "hint": "Revisar concorrência/event storm se cancelamentos forem frequentes; não contar como bug independente.",
    },
    "unverified_cancellation": {
        "root_cause": False, "noise": False, "severity": "medium", "weight": 2,
        "hint": "Confirmar sucessor/supersessão ou causa do cancelamento antes de descartá-lo como ruído.",
    },
    "unclassified_failure": {
        "root_cause": True, "noise": False, "severity": "medium", "weight": 3,
        "hint": "Melhorar o log sanitizado para expor uma causa estável e então criar classificador/teste específico.",
    },
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def normalize_message(message: str) -> str:
    sanitized = str(redact(message or ""))
    sanitized = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}=[REDACTED]", sanitized
    )
    sanitized = _SECRET_QUERY.sub(r"\1[REDACTED]", sanitized)
    sanitized = _TIMESTAMP.sub("<timestamp>", sanitized)
    sanitized = _SHA.sub("<sha>", sanitized)
    sanitized = _LONG_NUMBER.sub("<id>", sanitized)
    sanitized = _WHITESPACE.sub(" ", sanitized).strip()
    return sanitized[:1200]


def _failed_tests(message: str) -> tuple[str, ...]:
    tests = []
    for match in _FAILED_TEST.findall(message or ""):
        clean = match.strip().rstrip(":,")
        if clean and clean not in tests:
            tests.append(clean)
    return tuple(sorted(tests))


def _likely_cascade_workflow(workflow: str) -> bool:
    normalized = workflow.lower()
    return any(marker in normalized for marker in CASCADE_WORKFLOW_MARKERS)


def classify_record(record: dict[str, Any]) -> tuple[str, str]:
    workflow = _text(record.get("workflow"))
    conclusion = _text(record.get("conclusion")).lower()
    message = _text(record.get("message"))
    lower = message.lower()

    if conclusion == "cancelled":
        if bool(record.get("cancellation_superseded")):
            return "concurrency_cancelled", workflow or "cancelled"
        return "unverified_cancellation", workflow or "cancelled"

    if "cost_unknown_blocked" in lower or "cost_unknown_no_azure_hard_stop" in lower:
        return "cost_governance_block", "cost_unknown_no_hard_stop"

    if "resource not accessible by integration" in lower:
        return "integration_permission_denied", "resource_not_accessible_by_integration"

    if "self_hosted_runner_pickup_timeout_or_busy" in lower:
        return "runner_unavailable", "self_hosted_runner_pickup_timeout_or_busy"

    if (
        "desatualizado:" in lower
        or "stale data" in lower
        or ("freshness" in lower and ("exceeded" in lower or "expired" in lower))
    ):
        return "data_freshness_stale", normalize_message(message)

    if "contract_invalid" in lower or (
        "sdd:contract" in lower and ("failed" in lower or "ausente" in lower or "missing" in lower)
    ):
        return "contract_invalid", normalize_message(message)

    if (
        "ruff" in lower
        and ("found " in lower or "f401" in lower or "i001" in lower or "would reformat" in lower)
    ):
        return "quality_gate_lint", normalize_message(message)

    tests = _failed_tests(message)
    if tests:
        return "test_contract_regression", "|".join(tests)

    if "assertionerror" in lower or ("pytest" in lower and " failed" in lower):
        return "test_contract_regression", normalize_message(message)

    if (
        "pre_pr_failed_for_head_sha" in lower
        or "admission_blocked" in lower
        or "ci_admission_blocked" in lower
    ):
        return "admission_cascade", "upstream_pre_pr_admission_blocked"

    if (
        "required_workflows_not_completed_within_wait_window" in lower
        or "required_workflows_stalled_without_material_progress" in lower
        or "required_workflows_exceeded_total_wait_cap" in lower
    ):
        return "workflow_dependency_wait", "required_workflow_wait"

    normalized = normalize_message(message)
    generic_exit_only = bool(normalized and _EXIT_CODE.fullmatch(normalized))
    if _likely_cascade_workflow(workflow) and (
        not normalized or generic_exit_only or "failed with status" in lower
    ):
        return "gate_cascade", workflow

    return "unclassified_failure", normalized or f"{workflow}:{conclusion or 'failure'}"


def _validate_record(record: dict[str, Any]) -> None:
    required = ("repository", "run_id", "workflow", "conclusion", "occurred_at")
    missing = [key for key in required if not _text(record.get(key))]
    if missing:
        raise ValueError("missing_fields:" + ",".join(sorted(missing)))


def _logical_incident_id(record: dict[str, Any], fingerprint: str) -> str:
    repository = _text(record.get("repository"))
    event = _text(record.get("event")).lower()
    head_sha = _text(record.get("head_sha")).lower()
    run_id = _text(record.get("run_id"))
    anchor = head_sha if event in CHANGE_SCOPED_EVENTS and head_sha else run_id
    return hashlib.sha256(
        f"{repository}|{anchor}|{fingerprint}".encode("utf-8")
    ).hexdigest()


def _priority_score(incidents: int, workflows: int, category: str) -> int:
    meta = CATEGORY_META[category]
    return int(incidents * max(1, workflows) * int(meta["weight"]))


def analyze_failure_records(
    records: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    total = 0
    for raw in records:
        if not isinstance(raw, dict):
            raise ValueError("record_must_be_object")
        _validate_record(raw)
        total += 1
        category, signature = classify_record(raw)
        meta = CATEGORY_META[category]
        fingerprint = hashlib.sha256(f"{category}|{signature}".encode("utf-8")).hexdigest()
        key = (category, fingerprint)
        group = groups.setdefault(
            key,
            {
                "category": category,
                "fingerprint": fingerprint,
                "signature": signature[:700],
                "root_cause": bool(meta["root_cause"]),
                "noise": bool(meta["noise"]),
                "severity": meta["severity"],
                "remediation_hint": meta["hint"],
                "occurrences": 0,
                "repositories": set(),
                "workflows": set(),
                "logical_incidents": set(),
                "head_shas": set(),
                "run_ids": [],
                "first_seen": None,
                "last_seen": None,
                "sample": "",
            },
        )
        group["occurrences"] += 1
        group["repositories"].add(_text(raw.get("repository")))
        group["workflows"].add(_text(raw.get("workflow")))
        group["logical_incidents"].add(_logical_incident_id(raw, fingerprint))
        head_sha = _text(raw.get("head_sha")).lower()
        if head_sha:
            group["head_shas"].add(head_sha)
        run_id = _text(raw.get("run_id"))
        if run_id not in group["run_ids"] and len(group["run_ids"]) < 5:
            group["run_ids"].append(run_id)
        occurred = _text(raw.get("occurred_at"))
        previous_first = group["first_seen"]
        previous_last = group["last_seen"]
        group["first_seen"] = occurred if previous_first is None else min(previous_first, occurred)
        group["last_seen"] = occurred if previous_last is None else max(previous_last, occurred)
        if not group["sample"]:
            group["sample"] = normalize_message(_text(raw.get("message")))[:300]

    serial: list[dict[str, Any]] = []
    for group in groups.values():
        workflows = sorted(group.pop("workflows"))
        repositories = sorted(group.pop("repositories"))
        logical_incidents = group.pop("logical_incidents")
        head_shas = sorted(group.pop("head_shas"))
        group["workflows"] = workflows
        group["repositories"] = repositories
        group["incident_count"] = len(logical_incidents)
        group["head_shas"] = head_shas[:10]
        group["priority_score"] = _priority_score(
            group["incident_count"], len(workflows), group["category"]
        )
        serial.append(group)

    serial.sort(
        key=lambda item: (
            not item["root_cause"],
            item["noise"],
            -item["priority_score"],
            -item["occurrences"],
            item["category"],
            item["fingerprint"],
        )
    )
    root_causes = [item for item in serial if item["root_cause"] and not item["noise"]]
    cascades = [item for item in serial if not item["root_cause"] and not item["noise"]]
    noise = [item for item in serial if item["noise"]]

    when = generated_at or datetime.now(UTC).isoformat()
    return {
        "schema_version": REPORT_SCHEMA,
        "generated_at": when,
        "records_analyzed": total,
        "root_cause_groups": root_causes,
        "cascade_groups": cascades,
        "noise_groups": noise,
        "pareto": [
            {
                "rank": index + 1,
                "category": item["category"],
                "fingerprint": item["fingerprint"],
                "priority_score": item["priority_score"],
                "occurrences": item["occurrences"],
                "incident_count": item["incident_count"],
                "workflows": item["workflows"],
                "remediation_hint": item["remediation_hint"],
            }
            for index, item in enumerate(root_causes[:10])
        ],
    }


def dump_report(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
