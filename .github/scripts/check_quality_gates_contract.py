#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

EXPECTED_REQUIRED_CHECKS = {
    "Validate PR labels",
    "Typecheck & Quality Gates",
    "Bun Tests",
    "Web Build",
    "Storybook Build",
    "Fingerprint Browser Install (macOS)",
    "Fingerprint Browser Install (Linux)",
    "Docker Smoke",
    "Review Policy Gate",
}
EXPECTED_PR_TYPES = {"opened", "reopened", "synchronize", "ready_for_review", "edited"}
EXPECTED_LABEL_TYPES = EXPECTED_PR_TYPES | {"labeled", "unlabeled"}
EXPECTED_REVIEW_TYPES = {"submitted", "dismissed", "edited"}


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate tavreg-hikari quality gates contract.")
    parser.add_argument("--repo-root", default="")
    parser.add_argument("--declaration", default="")
    parser.add_argument("--metadata-script", default="")
    return parser.parse_args()


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("metadata_gate", path)
    if spec is None or spec.loader is None:
        raise ContractError(f"Unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_yaml(path: Path) -> dict[str, Any]:
    ruby = (
        "require 'json'; "
        "require 'psych'; "
        "path = ARGV.fetch(0); "
        "data = Psych.safe_load(File.read(path), permitted_classes: [], permitted_symbols: [], aliases: false, filename: path); "
        "print JSON.generate(data)"
    )
    result = subprocess.run(["ruby", "-e", ruby, str(path)], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ContractError(f"{path.name}: unable to parse YAML via ruby: {result.stderr.strip()}")
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
    normalized: list[str] = []
    for index, item in enumerate(value):
        require(isinstance(item, str) and item, f"{where}[{index}] must be a non-empty string")
        normalized.append(item)
    return normalized


def require_string_set(value: Any, where: str) -> set[str]:
    return set(require_string_list(value, where))


def workflow_jobs(workflow: dict[str, Any], where: str) -> dict[str, Any]:
    return require_mapping(workflow.get("jobs"), f"{where}.jobs")


def job_by_name(workflow: dict[str, Any], job_name: str, where: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for job_id, raw_job in workflow_jobs(workflow, where).items():
        job = require_mapping(raw_job, f"{where}.jobs.{job_id}")
        if job.get("name") == job_name:
            matches.append(job)
    require(len(matches) == 1, f"{where}: expected exactly one job named {job_name!r}")
    return matches[0]


def workflow_named_jobs(workflow: dict[str, Any], where: str) -> set[str]:
    names: set[str] = set()
    for job_id, raw_job in workflow_jobs(workflow, where).items():
        job = require_mapping(raw_job, f"{where}.jobs.{job_id}")
        name = job.get("name")
        require(isinstance(name, str) and name, f"{where}.jobs.{job_id}.name must be a non-empty string")
        names.add(name)
    return names


def step_named(job: dict[str, Any], step_name: str, where: str) -> dict[str, Any]:
    steps = job.get("steps")
    require(isinstance(steps, list), f"{where}.steps must be a list")
    for index, step in enumerate(steps):
        if isinstance(step, dict) and step.get("name") == step_name:
            return step
    raise ContractError(f"{where}: missing step {step_name!r}")


def step_run_text(step: dict[str, Any], where: str) -> str:
    run = step.get("run")
    require(isinstance(run, str) and run.strip(), f"{where}.run must be a non-empty string")
    return run


def step_script_text(step: dict[str, Any], where: str) -> str:
    with_cfg = require_mapping(step.get("with"), f"{where}.with")
    script = with_cfg.get("script")
    require(isinstance(script, str) and script.strip(), f"{where}.with.script must be a non-empty string")
    return script


def require_run_contains(step: dict[str, Any], needle: str, where: str) -> None:
    run = step_run_text(step, where)
    require(needle in run, f"{where}.run must contain {needle!r}")


def require_script_contains(step: dict[str, Any], needle: str, where: str) -> None:
    script = step_script_text(step, where)
    require(needle in script, f"{where}.with.script must contain {needle!r}")


def event_config(workflow: dict[str, Any], event_name: str, where: str) -> dict[str, Any]:
    on_section = require_mapping(mapping_get(workflow, "on"), f"{where}.on")
    config = mapping_get(on_section, event_name)
    require(isinstance(config, dict), f"{where}.on.{event_name} must be an object")
    return config


def validate_declaration(payload: dict[str, Any]) -> None:
    require(payload.get("schema_version") == 1, "quality-gates.json: schema_version must be 1")
    require(payload.get("implementation_profile") == "final", "quality-gates.json: implementation_profile must be 'final'")
    policy = require_mapping(payload.get("policy"), "quality-gates.json.policy")
    require(policy.get("baseline_policy") == "explicit-waiver-required", "quality-gates.json: baseline_policy drifted")
    require(policy.get("require_signed_commits") is True, "quality-gates.json: require_signed_commits must be true")

    branch = require_mapping(policy.get("branch_protection"), "quality-gates.json.policy.branch_protection")
    require(branch.get("protected_branches") == ["main"], "quality-gates.json: protected_branches drifted")
    require(branch.get("require_pull_request") is True, "quality-gates.json: require_pull_request must be true")
    require(branch.get("disallow_direct_pushes") is True, "quality-gates.json: disallow_direct_pushes must be true")
    require(branch.get("disallow_branch_deletions") is True, "quality-gates.json: disallow_branch_deletions must be true")
    require(branch.get("disallow_force_pushes") is True, "quality-gates.json: disallow_force_pushes must be true")
    require(branch.get("allow_merge_commits") is True, "quality-gates.json: allow_merge_commits must be true")
    require(branch.get("require_merge_queue") is False, "quality-gates.json: require_merge_queue must be false")
    require(branch.get("required_reviewers") == [], "quality-gates.json: required_reviewers must stay empty")

    status_checks = require_mapping(branch.get("required_status_checks"), "quality-gates.json.policy.branch_protection.required_status_checks")
    require(status_checks.get("strict") is True, "quality-gates.json: required_status_checks.strict must be true")
    integrations = require_mapping(status_checks.get("integrations"), "quality-gates.json.policy.branch_protection.required_status_checks.integrations")
    require(set(integrations) == EXPECTED_REQUIRED_CHECKS, "quality-gates.json: required check integrations drifted")
    for key, value in integrations.items():
        require(isinstance(value, int), f"quality-gates.json: integration id for {key!r} must be an integer")

    required_checks = require_string_set(payload.get("required_checks"), "quality-gates.json.required_checks")
    informational_checks = require_string_set(payload.get("informational_checks"), "quality-gates.json.informational_checks")
    require(required_checks == EXPECTED_REQUIRED_CHECKS, "quality-gates.json: required_checks drifted")
    require(not informational_checks, "quality-gates.json: informational_checks must stay empty")
    require(required_checks.isdisjoint(informational_checks), "quality-gates.json: required/informational overlap")

    review = require_mapping(policy.get("review_policy"), "quality-gates.json.policy.review_policy")
    require(review.get("mode") == "conditional-required", "quality-gates.json: review_policy.mode drifted")
    require(review.get("required_approvals") == 1, "quality-gates.json: review_policy.required_approvals drifted")
    require(review.get("exempt_repository_owner") is True, "quality-gates.json: exempt_repository_owner must be true")
    require(set(require_string_list(review.get("exempt_author_permissions"), "quality-gates.json.policy.review_policy.exempt_author_permissions")) == {"admin", "maintain"}, "quality-gates.json: exempt_author_permissions drifted")
    require(set(require_string_list(review.get("allowed_reviewer_permissions"), "quality-gates.json.policy.review_policy.allowed_reviewer_permissions")) == {"write", "maintain", "admin"}, "quality-gates.json: allowed_reviewer_permissions drifted")
    enforcement = require_mapping(review.get("enforcement"), "quality-gates.json.policy.review_policy.enforcement")
    require(enforcement.get("mode") == "required-check", "quality-gates.json: review_policy.enforcement.mode drifted")
    require(enforcement.get("check_name") == "Review Policy Gate", "quality-gates.json: review_policy.enforcement.check_name drifted")

    pr_workflows = require_string_list([entry.get("workflow") for entry in payload.get("expected_pr_workflows", [])], "quality-gates.json.expected_pr_workflows.workflow_names")
    main_workflows = require_string_list([entry.get("workflow") for entry in payload.get("expected_main_workflows", [])], "quality-gates.json.expected_main_workflows.workflow_names")
    release_workflows = require_string_list([entry.get("workflow") for entry in payload.get("expected_release_workflows", [])], "quality-gates.json.expected_release_workflows.workflow_names")
    require(set(pr_workflows) == {"Label Gate", "CI PR", "Review Policy"}, "quality-gates.json: expected_pr_workflows drifted")
    require(set(main_workflows) == {"CI Main"}, "quality-gates.json: expected_main_workflows drifted")
    require(set(release_workflows) == {"Release"}, "quality-gates.json: expected_release_workflows drifted")


def validate_metadata_policy(module: Any) -> None:
    require(set(module.ALLOWED_INTENT_LABELS) == {"type:patch", "type:minor", "type:major", "type:docs", "type:skip"}, "metadata_gate.ALLOWED_INTENT_LABELS drifted")
    require(set(module.ALLOWED_CHANNEL_LABELS) == {"channel:stable", "channel:rc"}, "metadata_gate.ALLOWED_CHANNEL_LABELS drifted")
    require(module.REVIEW_REQUIRED_APPROVALS == 1, "metadata_gate.REVIEW_REQUIRED_APPROVALS drifted")
    require(set(module.REVIEW_EXEMPT_PERMISSIONS) == {"admin", "maintain"}, "metadata_gate.REVIEW_EXEMPT_PERMISSIONS drifted")
    require(set(module.REVIEW_ALLOWED_PERMISSIONS) == {"write", "maintain", "admin"}, "metadata_gate.REVIEW_ALLOWED_PERMISSIONS drifted")


def validate_label_gate(workflow: dict[str, Any]) -> None:
    require(workflow.get("name") == "Label Gate", "label-gate.yml: workflow name drifted")
    pull_request = event_config(workflow, "pull_request", "label-gate.yml")
    require(set(require_string_list(pull_request.get("branches"), "label-gate.yml.on.pull_request.branches")) == {"main"}, "label-gate.yml: pull_request.branches drifted")
    require(set(require_string_list(pull_request.get("types"), "label-gate.yml.on.pull_request.types")) == EXPECTED_LABEL_TYPES, "label-gate.yml: pull_request.types drifted")
    require(workflow_named_jobs(workflow, "label-gate.yml") == {"Validate PR labels"}, "label-gate.yml: named jobs drifted")
    job = job_by_name(workflow, "Validate PR labels", "label-gate.yml")
    require(job.get("if") == "${{ github.event.pull_request.base.ref == 'main' }}", "label-gate.yml: job.if drifted")
    step = step_named(job, "Evaluate PR labels", "label-gate.yml.jobs.validate-pr-labels")
    require_run_contains(step, "metadata_gate.py label", "label-gate.yml.jobs.validate-pr-labels.steps['Evaluate PR labels']")


def validate_review_policy(workflow: dict[str, Any]) -> None:
    require(workflow.get("name") == "Review Policy", "review-policy.yml: workflow name drifted")
    pull_request = event_config(workflow, "pull_request", "review-policy.yml")
    review = event_config(workflow, "pull_request_review", "review-policy.yml")
    require(set(require_string_list(pull_request.get("branches"), "review-policy.yml.on.pull_request.branches")) == {"main"}, "review-policy.yml: pull_request.branches drifted")
    require(set(require_string_list(pull_request.get("types"), "review-policy.yml.on.pull_request.types")) == EXPECTED_PR_TYPES, "review-policy.yml: pull_request.types drifted")
    require(set(require_string_list(review.get("types"), "review-policy.yml.on.pull_request_review.types")) == EXPECTED_REVIEW_TYPES, "review-policy.yml: pull_request_review.types drifted")
    require(workflow_named_jobs(workflow, "review-policy.yml") == {"Review Policy Gate"}, "review-policy.yml: named jobs drifted")
    job = job_by_name(workflow, "Review Policy Gate", "review-policy.yml")
    step = step_named(job, "Evaluate review policy", "review-policy.yml.jobs.review-policy")
    require_run_contains(step, "metadata_gate.py review", "review-policy.yml.jobs.review-policy.steps['Evaluate review policy']")


def validate_ci_pr(workflow: dict[str, Any]) -> None:
    require(workflow.get("name") == "CI PR", "ci-pr.yml: workflow name drifted")
    pull_request = event_config(workflow, "pull_request", "ci-pr.yml")
    require(set(require_string_list(pull_request.get("branches"), "ci-pr.yml.on.pull_request.branches")) == {"main"}, "ci-pr.yml: pull_request.branches drifted")
    require(set(require_string_list(pull_request.get("types"), "ci-pr.yml.on.pull_request.types")) == EXPECTED_PR_TYPES, "ci-pr.yml: pull_request.types drifted")
    require(
        workflow_named_jobs(workflow, "ci-pr.yml")
        == {
            "Typecheck & Quality Gates",
            "Bun Tests",
            "Web Build",
            "Storybook Build",
            "Fingerprint Browser Install (macOS)",
            "Fingerprint Browser Install (Linux)",
            "Docker Smoke",
        },
        "ci-pr.yml: named jobs drifted",
    )

    typecheck = job_by_name(workflow, "Typecheck & Quality Gates", "ci-pr.yml")
    require_run_contains(step_named(typecheck, "Run typecheck", "ci-pr.yml.jobs.typecheck-quality-gates"), "bun run typecheck", "ci-pr.yml Typecheck step")
    require_run_contains(step_named(typecheck, "Check quality-gates scripts", "ci-pr.yml.jobs.typecheck-quality-gates"), "py_compile", "ci-pr.yml Check quality-gates scripts")
    require_run_contains(step_named(typecheck, "Quality-gates contract check", "ci-pr.yml.jobs.typecheck-quality-gates"), "check_quality_gates_contract.py", "ci-pr.yml Quality-gates contract check")
    require_run_contains(step_named(typecheck, "Quality-gates live rules check", "ci-pr.yml.jobs.typecheck-quality-gates"), "check_live_quality_gates.py", "ci-pr.yml Quality-gates live rules check")

    tests = job_by_name(workflow, "Bun Tests", "ci-pr.yml")
    require_run_contains(step_named(tests, "Run bun test", "ci-pr.yml.jobs.bun-tests"), "bun test", "ci-pr.yml Bun Tests")

    web_build = job_by_name(workflow, "Web Build", "ci-pr.yml")
    require_run_contains(step_named(web_build, "Build web app", "ci-pr.yml.jobs.web-build"), "bun run web:build", "ci-pr.yml Web Build")

    storybook = job_by_name(workflow, "Storybook Build", "ci-pr.yml")
    require_run_contains(step_named(storybook, "Build Storybook", "ci-pr.yml.jobs.storybook-build"), "bun run build-storybook", "ci-pr.yml Storybook Build")

    macos_install = job_by_name(workflow, "Fingerprint Browser Install (macOS)", "ci-pr.yml")
    require_run_contains(
        step_named(macos_install, "Install fingerprint browser", "ci-pr.yml.jobs.fingerprint-browser-install-macos"),
        "install-fingerprint-browser.sh --platform macos",
        "ci-pr.yml Fingerprint Browser Install (macOS) install",
    )
    require_run_contains(
        step_named(macos_install, "Smoke fingerprint browser", "ci-pr.yml.jobs.fingerprint-browser-install-macos"),
        "smoke-fingerprint-browser.mjs .tools/Chromium.app/Contents/MacOS/Chromium",
        "ci-pr.yml Fingerprint Browser Install (macOS) smoke",
    )

    linux_install = job_by_name(workflow, "Fingerprint Browser Install (Linux)", "ci-pr.yml")
    require(linux_install.get("container") == "mcr.microsoft.com/playwright:v1.58.2-noble", "ci-pr.yml: linux fingerprint install must run in playwright container")
    require_run_contains(
        step_named(linux_install, "Install fingerprint browser", "ci-pr.yml.jobs.fingerprint-browser-install-linux"),
        "install-fingerprint-browser.sh --platform linux",
        "ci-pr.yml Fingerprint Browser Install (Linux) install",
    )
    require_run_contains(
        step_named(linux_install, "Smoke fingerprint browser", "ci-pr.yml.jobs.fingerprint-browser-install-linux"),
        "smoke-fingerprint-browser.mjs .tools/fingerprint-browser/linux/chrome",
        "ci-pr.yml Fingerprint Browser Install (Linux) smoke",
    )

    docker = job_by_name(workflow, "Docker Smoke", "ci-pr.yml")
    step = step_named(docker, "Smoke test image", "ci-pr.yml.jobs.docker-smoke")
    require_run_contains(step, ".github/scripts/smoke-test-image.sh", "ci-pr.yml Docker Smoke")


def validate_ci_main(workflow: dict[str, Any]) -> None:
    require(workflow.get("name") == "CI Main", "ci-main.yml: workflow name drifted")
    push = event_config(workflow, "push", "ci-main.yml")
    require(set(require_string_list(push.get("branches"), "ci-main.yml.on.push.branches")) == {"main"}, "ci-main.yml: push.branches drifted")
    require(
        workflow_named_jobs(workflow, "ci-main.yml")
        == {
            "Typecheck & Quality Gates",
            "Bun Tests",
            "Web Build",
            "Storybook Build",
            "Fingerprint Browser Install (macOS)",
            "Fingerprint Browser Install (Linux)",
            "Docker Smoke",
            "Release Snapshot",
        },
        "ci-main.yml: named jobs drifted",
    )
    macos_install = job_by_name(workflow, "Fingerprint Browser Install (macOS)", "ci-main.yml")
    require_run_contains(
        step_named(macos_install, "Install fingerprint browser", "ci-main.yml.jobs.fingerprint-browser-install-macos"),
        "install-fingerprint-browser.sh --platform macos",
        "ci-main.yml Fingerprint Browser Install (macOS) install",
    )
    linux_install = job_by_name(workflow, "Fingerprint Browser Install (Linux)", "ci-main.yml")
    require(linux_install.get("container") == "mcr.microsoft.com/playwright:v1.58.2-noble", "ci-main.yml: linux fingerprint install must run in playwright container")
    require_run_contains(
        step_named(linux_install, "Install fingerprint browser", "ci-main.yml.jobs.fingerprint-browser-install-linux"),
        "install-fingerprint-browser.sh --platform linux",
        "ci-main.yml Fingerprint Browser Install (Linux) install",
    )
    release_snapshot = job_by_name(workflow, "Release Snapshot", "ci-main.yml")
    needs = release_snapshot.get("needs")
    require(
        isinstance(needs, list)
        and set(needs)
        == {
            "typecheck-quality-gates",
            "bun-tests",
            "web-build",
            "storybook-build",
            "fingerprint-browser-install-macos",
            "fingerprint-browser-install-linux",
            "docker-smoke",
        },
        "ci-main.yml: release-snapshot.needs drifted",
    )
    require_run_contains(step_named(release_snapshot, "Ensure immutable release snapshot", "ci-main.yml.jobs.release-snapshot"), "release_snapshot.py ensure", "ci-main.yml Release Snapshot")


def validate_release(workflow: dict[str, Any]) -> None:
    require(workflow.get("name") == "Release", "release.yml: workflow name drifted")
    workflow_run = event_config(workflow, "workflow_run", "release.yml")
    workflow_dispatch = event_config(workflow, "workflow_dispatch", "release.yml")
    require(set(require_string_list(workflow_run.get("workflows"), "release.yml.on.workflow_run.workflows")) == {"CI Main"}, "release.yml: workflow_run.workflows drifted")
    require(set(require_string_list(workflow_run.get("types"), "release.yml.on.workflow_run.types")) == {"completed"}, "release.yml: workflow_run.types drifted")
    require(set(require_string_list(workflow_run.get("branches"), "release.yml.on.workflow_run.branches")) == {"main"}, "release.yml: workflow_run.branches drifted")
    inputs = require_mapping(workflow_dispatch.get("inputs"), "release.yml.on.workflow_dispatch.inputs")
    commit_sha = require_mapping(inputs.get("commit_sha"), "release.yml.on.workflow_dispatch.inputs.commit_sha")
    require(commit_sha.get("required") is True, "release.yml: workflow_dispatch.commit_sha.required drifted")
    require(commit_sha.get("type") == "string", "release.yml: workflow_dispatch.commit_sha.type drifted")
    require(workflow_named_jobs(workflow, "release.yml") == {"Release Meta (snapshot + tags)", "Build + Smoke + Push Candidate", "Release Publish"}, "release.yml: named jobs drifted")

    meta = job_by_name(workflow, "Release Meta (snapshot + tags)", "release.yml")
    require_run_contains(step_named(meta, "Load immutable release snapshot", "release.yml.jobs.release-meta"), "release_snapshot.py export", "release.yml Load snapshot")
    build = job_by_name(workflow, "Build + Smoke + Push Candidate", "release.yml")
    require_run_contains(step_named(build, "Smoke test image", "release.yml.jobs.build-candidate"), ".github/scripts/smoke-test-image.sh", "release.yml Build + Smoke + Push Candidate")
    publish = job_by_name(workflow, "Release Publish", "release.yml")
    require_script_contains(step_named(publish, "Create GitHub Release", "release.yml.jobs.release-publish"), "github.rest.repos.createRelease", "release.yml Create GitHub Release")
    require_script_contains(step_named(publish, "Upsert PR release version comment", "release.yml.jobs.release-publish"), "tavreg-hikari-release-version-comment", "release.yml PR release version comment")


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root or Path(__file__).resolve().parents[2]).resolve()
    declaration_path = Path(args.declaration).resolve() if args.declaration else repo_root / ".github" / "quality-gates.json"
    metadata_path = Path(args.metadata_script).resolve() if args.metadata_script else repo_root / ".github" / "scripts" / "metadata_gate.py"

    try:
        declaration = json.loads(declaration_path.read_text())
        require(isinstance(declaration, dict), "quality-gates.json must decode to an object")
        validate_declaration(declaration)
        module = load_module(metadata_path)
        validate_metadata_policy(module)
        validate_label_gate(load_yaml(repo_root / ".github" / "workflows" / "label-gate.yml"))
        validate_review_policy(load_yaml(repo_root / ".github" / "workflows" / "review-policy.yml"))
        validate_ci_pr(load_yaml(repo_root / ".github" / "workflows" / "ci-pr.yml"))
        validate_ci_main(load_yaml(repo_root / ".github" / "workflows" / "ci-main.yml"))
        validate_release(load_yaml(repo_root / ".github" / "workflows" / "release.yml"))
    except ContractError as exc:
        print(f"[quality-gates-contract] {exc}", file=sys.stderr)
        return 1

    print("[quality-gates-contract] metadata workflow contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
