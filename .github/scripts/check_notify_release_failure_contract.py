#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PINNED_NOTIFY = "IvanLi-CN/oidrune/.github/workflows/notify.yml@e48822f99c6402a753ed86557ea029754cbab20b"
LEGACY_NOTIFY = "IvanLi-CN/github-workflows/.github/workflows/release-failure-telegram.yml"


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_yaml(path: Path) -> dict[str, Any]:
    ruby = (
        "require 'json'; "
        "require 'psych'; "
        "path = ARGV.fetch(0); "
        "data = Psych.safe_load(File.read(path), permitted_classes: [], permitted_symbols: [], aliases: false, filename: path); "
        "print JSON.generate(data)"
    )
    result = subprocess.run(["ruby", "-e", ruby, str(path)], check=False, capture_output=True, text=True)
    require(result.returncode == 0, f"{path.name}: unable to parse YAML via ruby: {result.stderr.strip()}")
    payload = json.loads(result.stdout)
    require(isinstance(payload, dict), f"{path.name}: workflow YAML must decode to an object")
    return payload


def mapping_get(mapping: dict[str, Any], key: str, default: Any = None) -> Any:
    if key in mapping:
        return mapping[key]
    if key == "on" and True in mapping:
        return mapping[True]
    if key == "on" and "true" in mapping:
        return mapping["true"]
    return default


def require_mapping(value: Any, where: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{where} must be an object")
    return value


def require_string_list(value: Any, where: str) -> list[str]:
    require(isinstance(value, list), f"{where} must be a list")
    require(all(isinstance(item, str) and item for item in value), f"{where} must contain non-empty strings")
    return value


def require_step(job: dict[str, Any], name: str, where: str) -> dict[str, Any]:
    steps = job.get("steps")
    require(isinstance(steps, list), f"{where}.steps must be a list")
    for step in steps:
        if isinstance(step, dict) and step.get("name") == name:
            return step
    raise ContractError(f"{where}: missing step {name!r}")


def step_run(step: dict[str, Any], where: str) -> str:
    run = step.get("run")
    require(isinstance(run, str) and run.strip(), f"{where}.run must be non-empty")
    return run


def require_summary(summary: Any, required: list[str], where: str) -> None:
    require(isinstance(summary, str) and summary.strip(), f"{where}.summary must be non-empty")
    for marker in required:
        require(marker in summary, f"{where}.summary must contain {marker!r}")


def validate_notify_workflow(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    require(LEGACY_NOTIFY not in source, "notify workflow still references the legacy shared Telegram workflow")
    require(source.count(PINNED_NOTIFY) == 2, "notify workflow must contain exactly two pinned Oidrune calls")
    require("gateway_url" not in source and "oidc_audience" not in source, "notify workflow must use Oidrune gateway defaults")
    require("SHOUTRRR_URL" not in source and "secrets:" not in source, "notify workflow must not pass the legacy Telegram secret")
    require(source.index("actual_patterns") < source.index("requested_patterns"), "target SHA precedence drifted")
    require("resolved_sha = fallback_head_sha" in source, "resolver fallback SHA drifted")
    require("if resolved_sha == fallback_head_sha and requested_sha" in source, "requested SHA fallback drifted")

    workflow = load_yaml(path)
    require(workflow.get("name") == "Notify failed release", "notify workflow name drifted")
    events = require_mapping(mapping_get(workflow, "on"), "notify-release-failure.yml.on")
    workflow_run = require_mapping(events.get("workflow_run"), "notify-release-failure.yml.on.workflow_run")
    require(require_string_list(workflow_run.get("workflows"), "workflow_run.workflows") == ["Release"], "workflow_run.workflows drifted")
    require(require_string_list(workflow_run.get("types"), "workflow_run.types") == ["completed"], "workflow_run.types drifted")
    require(require_string_list(workflow_run.get("branches"), "workflow_run.branches") == ["main"], "workflow_run.branches drifted")
    require("workflow_dispatch" in events, "workflow_dispatch smoke trigger is missing")
    require(workflow.get("permissions") == {}, "workflow-level permissions must remain empty")

    jobs = require_mapping(workflow.get("jobs"), "notify-release-failure.yml.jobs")
    require(set(jobs) == {"resolve_release_context", "notify_failure", "smoke_test"}, "notify workflow jobs drifted")
    resolver = require_mapping(jobs["resolve_release_context"], "resolve_release_context")
    require(resolver.get("if") == "${{ github.event_name == 'workflow_run' && github.event.workflow_run.conclusion == 'failure' }}", "failure filter drifted")
    require(resolver.get("permissions") == {"actions": "read"}, "resolver permissions drifted")
    resolve_step = require_step(resolver, "Resolve failed release metadata", "resolve_release_context")
    resolve_run = step_run(resolve_step, "resolve_release_context.resolve")
    resolve_env = require_mapping(resolve_step.get("env"), "resolve_release_context.resolve.env")
    for marker in ("RELEASE_TARGET_SHA", "RELEASE_REQUESTED_SHA"):
        require(marker in resolve_run, f"resolver must retain {marker}")
    for key in ("REPOSITORY", "RUN_ID", "RUN_ATTEMPT", "RUN_EVENT", "HEAD_BRANCH", "HEAD_SHA"):
        require(key in resolve_env, f"resolver env must retain {key}")

    failure = require_mapping(jobs["notify_failure"], "notify_failure")
    smoke = require_mapping(jobs["smoke_test"], "smoke_test")
    require(failure.get("permissions") == {"id-token": "write"}, "failure notification must grant id-token write")
    require(smoke.get("permissions") == {"id-token": "write"}, "smoke notification must grant id-token write")
    require(failure.get("uses") == PINNED_NOTIFY, "failure notification pin drifted")
    require(smoke.get("uses") == PINNED_NOTIFY, "smoke notification pin drifted")
    require(failure.get("if") == "${{ github.event_name == 'workflow_run' && github.event.workflow_run.conclusion == 'failure' }}", "failure notification condition drifted")
    require(smoke.get("if") == "${{ github.event_name == 'workflow_dispatch' }}", "smoke notification condition drifted")
    require(failure.get("needs") == ["resolve_release_context"], "failure notification dependency drifted")

    failure_with = require_mapping(failure.get("with"), "notify_failure.with")
    smoke_with = require_mapping(smoke.get("with"), "smoke_test.with")
    require(set(failure_with) == {"outcome", "on_gateway_failure", "summary"}, "failure notification Oidrune inputs drifted")
    require(set(smoke_with) == {"outcome", "on_gateway_failure", "summary"}, "smoke notification Oidrune inputs drifted")
    require(failure_with.get("outcome") == "${{ github.event.workflow_run.conclusion }}", "failure outcome wiring drifted")
    require(smoke_with.get("outcome") == "failure", "smoke outcome drifted")
    require(failure_with.get("on_gateway_failure") == "fail", "failure handoff failure policy drifted")
    require(smoke_with.get("on_gateway_failure") == "fail", "smoke handoff failure policy drifted")
    require_summary(
        failure_with.get("summary"),
        [
            "🚨 FAILURE: tavreg-hikari release notification",
            "Project: tavreg-hikari",
            "Repository: ${{ github.repository }}",
            "Status:",
            "Title:",
            "Target SHA:",
            "${{ needs.resolve_release_context.outputs.head_sha }}",
            "Run URL:",
            "Ref:",
            "Run attempt:",
            "Actor:",
            "Event:",
            "Details:",
        ],
        "notify_failure.with",
    )
    require_summary(
        smoke_with.get("summary"),
        [
            "🧪 SMOKE: tavreg-hikari release notifier",
            "Project: tavreg-hikari",
            "Repository: ${{ github.repository }}",
            "Status: failure",
            "Title: Release notifier smoke",
            "Smoke: release-alert-smoke",
            "Target SHA:",
            "Run URL:",
            "Ref:",
            "Run attempt:",
            "Actor:",
            "Event: workflow_dispatch",
            "Details: manual notifier smoke test",
        ],
        "smoke_test.with",
    )


def validate_release_markers(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    require("echo \"RELEASE_REQUESTED_SHA=${target_sha}\"" in source, "release requested SHA marker drifted")
    require("echo \"RELEASE_TARGET_SHA=${TARGET_SHA}\"" in source, "release target SHA marker drifted")
    require("if [ \"${{ github.event_name }}\" = \"workflow_dispatch\" ]; then" in source, "release manual dispatch path drifted")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate tavreg-hikari release notifier contract.")
    parser.add_argument("--repo-root", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.repo_root or Path(__file__).resolve().parents[2]).resolve()
    try:
        validate_notify_workflow(root / ".github" / "workflows" / "notify-release-failure.yml")
        validate_release_markers(root / ".github" / "workflows" / "release.yml")
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        print(f"[notify-release-failure-contract] {exc}", file=sys.stderr)
        return 1
    print("[notify-release-failure-contract] release notifier contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
