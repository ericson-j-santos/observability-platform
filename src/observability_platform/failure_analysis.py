from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, Iterable

from .redaction import redact

REPORT_SCHEMA = "observability.failure-analysis/v2"
COLLECTION_SCHEMA = "observability.failure-collection/v1"

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
SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 5}

CATEGORY_META: dict[str, dict[str, Any]] = {
    "test_contract_regression": {
        "root_cause": True, "noise": False, "severity": "high", "weight": 5,
        "hint": "Corrigir o contrato/teste na mesma mudança funcional e adicionar regressão que acompanhe o novo comportamento.",
    },
    "cost_governance_block": {
        "root_cause": False, "control": True, "noise": False, "severity": "high", "weight": 0,
        "hint": "Manter bloqueado até comprovar custo incremental zero e hard stop; não tratar a proteção financeira como defeito.",
    },
    "governance_control_block": {
        "root_cause": False, "control": True, "noise": False, "severity": "low", "weight": 0,
        "hint": "Aguardar a precondição governada (autorização, ready state ou fila elegível) sem abrir bug nem gerar retry sem mudança material.",
    },
    "collection_limit_control": {
        "root_cause": False, "control": True, "noise": False, "severity": "low", "weight": 0,
        "hint": "Reduzir a janela ou ampliar o limite somente dentro do custo zero; não transformar ausência de log em bug do produto.",
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
        if record.get("cancellation_superseded") is True:
            return "concurrency_cancelled", workflow or "cancelled"
        return "unverified_cancellation", workflow or "cancelled"

    if "cost_unknown_blocked" in lower or "cost_unknown_no_azure_hard_stop" in lower:
        return "cost_governance_block", "cost_unknown_no_hard_stop"

    if (
        "autorização humana explícita ausente" in lower
        or "autorizacao humana explicita ausente" in lower
    ):
        return "governance_control_block", "human_approval_required"

    if "pr ainda está em draft e não pertence à fila recuperada" in lower:
        return "governance_control_block", "draft_not_in_recovered_queue"

    if lower == "log_budget_exhausted":
        return "collection_limit_control", "failed_job_log_budget_exhausted"

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


def _classification(meta: dict[str, Any]) -> str:
    if bool(meta.get("root_cause")):
        return "root_cause"
    if bool(meta.get("control")):
        return "control"
    if bool(meta.get("noise")):
        return "noise"
    return "cascade"


def _logical_incident_id(record: dict[str, Any], fingerprint: str) -> str:
    repository = _text(record.get("repository"))
    event = _text(record.get("event")).lower()
    head_sha = _text(record.get("head_sha")).lower()
    run_id = _text(record.get("run_id"))
    anchor = head_sha if event in CHANGE_SCOPED_EVENTS and head_sha else run_id
    return hashlib.sha256(
        f"{repository}|{anchor}|{fingerprint}".encode("utf-8")
    ).hexdigest()


def _impact_score(severity: str, repositories: int, workflows: int) -> int:
    return int(
        SEVERITY_WEIGHTS[severity]
        * max(1, repositories)
        * max(1, workflows)
    )


def _collection_summary(
    collection: dict[str, Any] | None,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    source = collection if isinstance(collection, dict) else {}
    occurred = sorted(_text(item.get("occurred_at")) for item in records if _text(item.get("occurred_at")))
    unique_runs = {
        _text(item.get("run_id")): _text(item.get("conclusion")).lower()
        for item in records
        if _text(item.get("run_id"))
    }

    def count(name: str, fallback: int = 0) -> int:
        value = source.get(name, fallback)
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return fallback

    return {
        "schema_version": _text(source.get("schema_version")) or COLLECTION_SCHEMA,
        "provider": _text(source.get("provider")) or "github_actions",
        "repository": _text(source.get("repository")),
        "window_start": _text(source.get("window_start")) or (occurred[0] if occurred else ""),
        "window_end": _text(source.get("window_end")) or (occurred[-1] if occurred else ""),
        "runs_scanned": count("runs_scanned", len(unique_runs)),
        "runs_in_window": count("runs_in_window", len(unique_runs)),
        "successful_runs": count("successful_runs"),
        "failure_runs": count(
            "failure_runs",
            sum(1 for value in unique_runs.values() if value == "failure"),
        ),
        "cancelled_runs": count(
            "cancelled_runs",
            sum(1 for value in unique_runs.values() if value == "cancelled"),
        ),
        "timed_out_runs": count(
            "timed_out_runs",
            sum(1 for value in unique_runs.values() if value == "timed_out"),
        ),
        "action_required_runs": count(
            "action_required_runs",
            sum(1 for value in unique_runs.values() if value == "action_required"),
        ),
        "failed_job_logs_collected": count("failed_job_logs_collected"),
        "records_emitted": count("records_emitted", len(records)),
        "truncated": source.get("truncated") is True,
    }


def _pareto(active_root_causes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total_score = sum(int(item["priority_score"]) for item in active_root_causes)
    cumulative = 0
    result = []
    for index, item in enumerate(active_root_causes[:10]):
        previous = cumulative
        cumulative += int(item["priority_score"])
        percentage = round((cumulative * 100 / total_score), 2) if total_score else 0.0
        result.append({
            "rank": index + 1,
            "category": item["category"],
            "fingerprint": item["fingerprint"],
            "priority_score": item["priority_score"],
            "frequency_score": item["frequency_score"],
            "impact_score": item["impact_score"],
            "occurrences": item["occurrences"],
            "incident_count": item["incident_count"],
            "repositories": item["repositories"],
            "workflows": item["workflows"],
            "severity": item["severity"],
            "cumulative_priority_percent": percentage,
            "pareto_tier": "top_80" if previous < total_score * 0.8 else "long_tail",
            "remediation_hint": item["remediation_hint"],
        })
    return result


def _actionable_backlog(
    pareto: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_fingerprint = {item["fingerprint"]: item for item in groups}
    backlog = []
    for item in pareto:
        group = by_fingerprint[item["fingerprint"]]
        needs_observability = group["category"] == "unclassified_failure"
        fingerprint = group["fingerprint"]
        acceptance = [
            f"Reproduzir ou confirmar o fingerprint {fingerprint} no SHA corrente, com evidência sanitizada.",
            (
                "Adicionar código de erro/causa estável no produtor antes de inferir a correção."
                if needs_observability
                else "Corrigir a causa primária sem desabilitar gate, teste ou controle."
            ),
            "Adicionar teste de regressão ou controle equivalente que detecte a recorrência.",
            "Executar o maior E2E autorizado e vincular a evidência ao SHA corrigido.",
            "Reexecutar a análise na janela seguinte e comprovar ausência de incidente ativo para o fingerprint.",
        ]
        signature = str(group["signature"]).replace("\n", " ")[:160]
        backlog.append({
            "backlog_id": f"failure-{fingerprint[:12]}",
            "rank": item["rank"],
            "priority": "P1" if item["pareto_tier"] == "top_80" else "P2",
            "status": "needs_observability" if needs_observability else "ready",
            "category": group["category"],
            "fingerprint": fingerprint,
            "title": f"{group['category']}: {signature}",
            "priority_score": group["priority_score"],
            "frequency_score": group["frequency_score"],
            "impact_score": group["impact_score"],
            "severity": group["severity"],
            "repositories": group["repositories"],
            "workflows": group["workflows"],
            "run_ids": group["run_ids"],
            "head_shas": group["head_shas"],
            "first_seen": group["first_seen"],
            "last_seen": group["last_seen"],
            "sample": group["sample"],
            "recommended_action": group["remediation_hint"],
            "acceptance_criteria": acceptance,
        })
    return backlog


def analyze_failure_records(
    records: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
    collection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    materialized = list(records)
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in materialized:
        if not isinstance(raw, dict):
            raise ValueError("record_must_be_object")
        _validate_record(raw)
        category, signature = classify_record(raw)
        meta = CATEGORY_META[category]
        fingerprint = hashlib.sha256(f"{category}|{signature}".encode("utf-8")).hexdigest()
        key = (category, fingerprint)
        group = groups.setdefault(
            key,
            {
                "category": category,
                "classification": _classification(meta),
                "fingerprint": fingerprint,
                "signature": signature[:700],
                "root_cause": bool(meta["root_cause"]),
                "control": bool(meta.get("control", False)),
                "noise": bool(meta["noise"]),
                "severity": meta["severity"],
                "remediation_hint": meta["hint"],
                "occurrences": 0,
                "repositories": set(),
                "workflows": set(),
                "logical_incidents": {},
                "head_shas": set(),
                "run_ids": [],
                "recovery_run_ids": set(),
                "first_seen": None,
                "last_seen": None,
                "sample": "",
            },
        )
        group["occurrences"] += 1
        group["repositories"].add(_text(raw.get("repository")))
        group["workflows"].add(_text(raw.get("workflow")))
        incident_id = _logical_incident_id(raw, fingerprint)
        was_recovered = group["logical_incidents"].get(incident_id, False)
        group["logical_incidents"][incident_id] = (
            was_recovered or raw.get("recovery_observed") is True
        )
        recovery_run_id = _text(raw.get("recovery_run_id"))
        if recovery_run_id:
            group["recovery_run_ids"].add(recovery_run_id)
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
        recovery_run_ids = sorted(group.pop("recovery_run_ids"))
        active_incidents = sum(1 for recovered in logical_incidents.values() if not recovered)
        recovered_incidents = len(logical_incidents) - active_incidents
        impact_score = _impact_score(group["severity"], len(repositories), len(workflows))
        group["workflows"] = workflows
        group["repositories"] = repositories
        group["incident_count"] = len(logical_incidents)
        group["active_incident_count"] = active_incidents
        group["recovered_incident_count"] = recovered_incidents
        group["active"] = active_incidents > 0
        group["status"] = "active" if active_incidents > 0 else "recovered"
        group["head_shas"] = head_shas[:10]
        group["recovery_run_ids"] = recovery_run_ids[:5]
        group["frequency_score"] = len(logical_incidents)
        group["impact_score"] = impact_score
        group["priority_score"] = int(group["frequency_score"] * impact_score)
        serial.append(group)

    serial.sort(
        key=lambda item: (
            not item["root_cause"],
            not item["active"],
            item["noise"],
            -item["priority_score"],
            -item["occurrences"],
            item["category"],
            item["fingerprint"],
        )
    )
    root_causes = [
        item for item in serial
        if item["root_cause"] and not item["control"] and not item["noise"]
    ]
    active_root_causes = [item for item in root_causes if item["active"]]
    recovered_root_causes = [item for item in root_causes if not item["active"]]
    controls = [item for item in serial if item["control"] and not item["noise"]]
    cascades = [
        item for item in serial
        if not item["root_cause"] and not item["control"] and not item["noise"]
    ]
    noise = [item for item in serial if item["noise"]]
    unverified_cancellations = [
        item for item in cascades if item["category"] == "unverified_cancellation"
    ]
    pareto = _pareto(active_root_causes)
    backlog = _actionable_backlog(pareto, active_root_causes)
    when = generated_at or datetime.now(UTC).isoformat()
    collection_summary = _collection_summary(collection, materialized)

    return {
        "schema_version": REPORT_SCHEMA,
        "generated_at": when,
        "collection": collection_summary,
        "records_analyzed": len(materialized),
        "summary": {
            "active_root_causes": len(active_root_causes),
            "recovered_root_causes": len(recovered_root_causes),
            "controls": len(controls),
            "cascades": len(cascades),
            "expected_cancellations": sum(
                item["occurrences"]
                for item in noise
                if item["category"] == "concurrency_cancelled"
            ),
            "unverified_cancellations": sum(
                item["occurrences"] for item in unverified_cancellations
            ),
            "actionable_backlog_items": len(backlog),
        },
        "root_cause_groups": root_causes,
        "active_root_cause_groups": active_root_causes,
        "recovered_root_cause_groups": recovered_root_causes,
        "control_groups": controls,
        "cascade_groups": cascades,
        "noise_groups": noise,
        "unverified_cancellation_groups": unverified_cancellations,
        "pareto": pareto,
        "actionable_backlog": backlog,
    }


def _markdown_cell(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def render_backlog_markdown(report: dict[str, Any]) -> str:
    collection = report["collection"]
    summary = report["summary"]
    lines = [
        "# Failure intelligence backlog",
        "",
        f"- Generated at: `{_markdown_cell(report['generated_at'])}`",
        f"- Repository: `{_markdown_cell(collection['repository']) or 'not-provided'}`",
        f"- Window: `{_markdown_cell(collection['window_start']) or 'unknown'}` to `{_markdown_cell(collection['window_end']) or 'unknown'}`",
        f"- Runs in window: {collection['runs_in_window']} ({collection['failure_runs']} failed, {collection['cancelled_runs']} cancelled, {collection['successful_runs']} successful)",
        f"- Signals analyzed: {report['records_analyzed']}",
        f"- Active root causes: {summary['active_root_causes']}; recovered: {summary['recovered_root_causes']}",
        f"- Expected cancellations: {summary['expected_cancellations']}; unverified cancellations: {summary['unverified_cancellations']}",
        "",
        "## Pareto",
        "",
    ]
    if report["pareto"]:
        lines.extend([
            "| Rank | Fingerprint | Cause | Frequency | Impact | Score | Cumulative |",
            "| ---: | --- | --- | ---: | ---: | ---: | ---: |",
        ])
        for item in report["pareto"]:
            lines.append(
                f"| {item['rank']} | `{item['fingerprint'][:12]}` | "
                f"{_markdown_cell(item['category'])} | {item['frequency_score']} | "
                f"{item['impact_score']} | {item['priority_score']} | "
                f"{item['cumulative_priority_percent']:.2f}% |"
            )
    else:
        lines.append("_No active root cause is eligible for the Pareto in this window._")

    lines.extend(["", "## Actionable backlog", ""])
    if report["actionable_backlog"]:
        for item in report["actionable_backlog"]:
            lines.extend([
                f"### {item['priority']} · {_markdown_cell(item['title'])}",
                "",
                f"- ID: `{item['backlog_id']}`",
                f"- Fingerprint: `{item['fingerprint']}`",
                f"- Status: `{item['status']}`",
                f"- Evidence runs: {', '.join(item['run_ids']) or 'none'}",
                f"- Recommended action: {_markdown_cell(item['recommended_action'])}",
                "- Acceptance criteria:",
            ])
            lines.extend(f"  - [ ] {_markdown_cell(value)}" for value in item["acceptance_criteria"])
            lines.append("")
    else:
        lines.append("_No actionable item: controls, cascades, expected cancellations and recovered causes stay out of the bug backlog._")

    lines.extend([
        "",
        "## Excluded from bug backlog",
        "",
        f"- Controls: {summary['controls']}",
        f"- Cascades: {summary['cascades']}",
        f"- Expected cancellations/noise: {summary['expected_cancellations']}",
        f"- Unverified cancellations awaiting diagnosis: {summary['unverified_cancellations']}",
        f"- Recovered root causes: {summary['recovered_root_causes']}",
        "",
    ])
    return "\n".join(lines)


def dump_report(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
