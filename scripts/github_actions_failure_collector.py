#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from observability_platform.github_actions_collector import collect_github_actions_failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-runs", type=int, default=100)
    parser.add_argument("--max-failed-jobs", type=int, default=40)
    parser.add_argument("--since-hours", type=int, default=24)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()

    records = collect_github_actions_failures(
        repository=args.repository,
        token=os.environ.get(args.token_env, ""),
        max_runs=args.max_runs,
        max_failed_jobs=args.max_failed_jobs,
        since_hours=args.since_hours,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": "GITHUB_ACTIONS_FAILURE_COLLECTION_OK",
        "records": len(records),
        "output": str(args.output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
