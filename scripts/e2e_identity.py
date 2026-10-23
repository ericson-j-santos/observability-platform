#!/usr/bin/env python3
"""Bind E2E evidence to the actual, clean checkout without exposing Git output."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def validate_identity(repository: str, sha: str) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise RuntimeError("repository_invalid")
    if not SHA_RE.fullmatch(sha):
        raise RuntimeError("sha_must_be_full_40_chars")


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("checkout_git_unavailable") from exc
    if result.returncode != 0:
        raise RuntimeError("checkout_git_failed")
    return result.stdout.strip()


def verify_checkout(repository: str, sha: str, *, root: Path = ROOT) -> str:
    validate_identity(repository, sha)
    root = root.resolve()
    observed_root = Path(_git(root, "rev-parse", "--show-toplevel")).resolve()
    if observed_root != root:
        raise RuntimeError("checkout_root_mismatch")
    observed_sha = _git(root, "rev-parse", "HEAD").lower()
    if observed_sha != sha.lower():
        raise RuntimeError("checkout_sha_mismatch")

    origin = _git(root, "remote", "get-url", "origin").removesuffix(".git").lower()
    expected_repository = repository.lower()
    allowed_origins = {
        f"https://github.com/{expected_repository}",
        f"git@github.com:{expected_repository}",
        f"ssh://git@github.com/{expected_repository}",
    }
    if origin not in allowed_origins:
        raise RuntimeError("checkout_repository_mismatch")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=no"):
        raise RuntimeError("checkout_tracked_changes")
    return observed_sha


def prepare_evidence_path(output: Path, *, root: Path = ROOT) -> Path:
    """Invalidate only an untracked JSON output inside the dedicated artifact tree."""
    root = root.resolve()
    output = Path(os.path.abspath(output if output.is_absolute() else root / output))
    try:
        parts = output.relative_to(root).parts
    except ValueError as exc:
        raise RuntimeError("evidence_output_outside_artifacts") from exc
    if len(parts) < 3 or parts[:2] != ("artifacts", "e2e-platform") or output.suffix != ".json":
        raise RuntimeError("evidence_output_outside_artifacts")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError("evidence_output_symlink")
    if _git(root, "ls-files", "--", output.relative_to(root).as_posix()):
        raise RuntimeError("evidence_output_tracked")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    return output


def write_evidence(output: Path, evidence: dict[str, object]) -> None:
    """Publish the complete JSON atomically, cleaning up a failed temporary write."""
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=".evidence-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(evidence, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
