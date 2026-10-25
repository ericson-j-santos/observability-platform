#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from observability_platform.failure_analysis import (
    analyze_failure_records,
    dump_report,
    render_backlog_markdown,
)


def load_analysis_input(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    raw = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, list):
        return payload, None
    if isinstance(payload, dict):
        records = payload.get("records")
        if not isinstance(records, list):
            raise SystemExit("input_collection_records_must_be_array")
        collection = {key: value for key, value in payload.items() if key != "records"}
        return records, collection
    if payload is not None:
        raise SystemExit("input_json_must_be_array_or_collection_object")

    records = []
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"input_jsonl_invalid:{number}") from exc
        if not isinstance(item, dict):
            raise SystemExit(f"input_jsonl_object_required:{number}")
        records.append(item)
    return records, None


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backlog-output", type=Path)
    args = parser.parse_args()
    if args.backlog_output and args.output.resolve() == args.backlog_output.resolve():
        raise SystemExit("output_paths_must_differ")

    records, collection = load_analysis_input(args.input)
    report = analyze_failure_records(records, collection=collection)
    _write_text(args.output, dump_report(report))
    if args.backlog_output:
        _write_text(args.backlog_output, render_backlog_markdown(report))

    print(json.dumps({
        "status": "FAILURE_ANALYSIS_OK",
        "schema_version": report["schema_version"],
        "records_analyzed": report["records_analyzed"],
        "active_root_causes": report["summary"]["active_root_causes"],
        "recovered_root_causes": report["summary"]["recovered_root_causes"],
        "cascade_groups": len(report["cascade_groups"]),
        "expected_cancellations": report["summary"]["expected_cancellations"],
        "unverified_cancellations": report["summary"]["unverified_cancellations"],
        "actionable_backlog_items": len(report["actionable_backlog"]),
        "output": str(args.output),
        "backlog_output": str(args.backlog_output) if args.backlog_output else "",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
