#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from observability_platform.github_actions_collector import collect_github_actions_run_data


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-runs", type=int, default=300)
    parser.add_argument("--max-failed-jobs", type=int, default=80)
    parser.add_argument("--since-hours", type=int, default=24)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()

    collection = collect_github_actions_run_data(
        repository=args.repository,
        token=os.environ.get(args.token_env, ""),
        max_runs=args.max_runs,
        max_failed_jobs=args.max_failed_jobs,
        since_hours=args.since_hours,
    )
    _write_json(args.output, collection)
    print(json.dumps({
        "status": "GITHUB_ACTIONS_FAILURE_COLLECTION_OK",
        "schema_version": collection["schema_version"],
        "runs_scanned": collection["runs_scanned"],
        "runs_in_window": collection["runs_in_window"],
        "failure_runs": collection["failure_runs"],
        "cancelled_runs": collection["cancelled_runs"],
        "records": len(collection["records"]),
        "truncated": collection["truncated"],
        "output": str(args.output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
