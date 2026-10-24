#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from observability_platform.failure_analysis import analyze_failure_records, dump_report


def load_records(path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8")
    stripped = raw.lstrip()
    if stripped.startswith("["):
        payload = json.loads(raw)
        if not isinstance(payload, list):
            raise SystemExit("input_json_must_be_array")
        return payload
    records = []
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise SystemExit(f"input_jsonl_object_required:{number}")
        records.append(item)
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze_failure_records(load_records(args.input))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(dump_report(report), encoding="utf-8")
    print(json.dumps({
        "status": "FAILURE_ANALYSIS_OK",
        "records_analyzed": report["records_analyzed"],
        "root_cause_groups": len(report["root_cause_groups"]),
        "cascade_groups": len(report["cascade_groups"]),
        "noise_groups": len(report["noise_groups"]),
        "output": str(args.output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
