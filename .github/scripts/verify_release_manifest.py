#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ALLOWED_INDEX_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}


class ValidationError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a published image tag resolves to an image index / manifest list with explicit platform metadata."
    )
    parser.add_argument("--ref", action="append", default=[], help="Image reference to inspect. May be repeated.")
    parser.add_argument("--expected-platform", default="linux/amd64")
    parser.add_argument("--anonymous", action="store_true", help="Inspect using an empty DOCKER_CONFIG.")
    parser.add_argument("--max-attempts", type=int, default=1)
    parser.add_argument("--retry-delay-seconds", type=float, default=0.0)
    parser.add_argument(
        "--raw-file",
        default="",
        help="Read a pre-fetched raw manifest JSON from a local file instead of inspecting a remote ref. Requires exactly one --ref.",
    )
    return parser.parse_args()


def parse_expected_platform(value: str) -> tuple[str, str]:
    parts = [segment.strip() for segment in value.split("/") if segment.strip()]
    if len(parts) != 2:
        raise ValidationError(f"Expected platform must be <os>/<arch>, got: {value!r}")
    return parts[0], parts[1]


def inspect_raw_manifest(ref: str, *, anonymous: bool) -> dict[str, Any]:
    env = dict(os.environ)
    env.pop("DOCKER_AUTH_CONFIG", None)
    with tempfile.TemporaryDirectory(prefix="verify-release-manifest-") as tmpdir:
        if anonymous:
            env["DOCKER_CONFIG"] = tmpdir
        command = ["docker", "buildx", "imagetools", "inspect", "--raw", ref]
        result = subprocess.run(command, check=False, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or "docker buildx imagetools inspect failed"
            raise ValidationError(f"{ref}: unable to inspect raw manifest: {detail}")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{ref}: docker buildx imagetools inspect did not return valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValidationError(f"{ref}: raw manifest must decode to an object")
    return payload


def load_raw_manifest_from_file(raw_file: str, *, ref: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(raw_file).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"{ref}: raw manifest file not found: {raw_file}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{ref}: raw manifest file is not valid JSON: {raw_file}") from exc
    if not isinstance(payload, dict):
        raise ValidationError(f"{ref}: raw manifest file must decode to an object")
    return payload


def verify_platform_descriptor(payload: dict[str, Any], *, ref: str, expected_os: str, expected_arch: str) -> None:
    media_type = payload.get("mediaType")
    if media_type not in ALLOWED_INDEX_MEDIA_TYPES:
        raise ValidationError(
            f"{ref}: expected top-level mediaType to be an image index / manifest list, got {media_type!r}"
        )

    manifests = payload.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ValidationError(f"{ref}: manifest index is missing non-empty manifests[]")

    available_platforms: set[str] = set()
    for entry in manifests:
        if not isinstance(entry, dict):
            continue
        platform = entry.get("platform")
        if not isinstance(platform, dict):
            continue
        os_name = platform.get("os")
        arch = platform.get("architecture")
        if isinstance(os_name, str) and isinstance(arch, str):
            available_platforms.add(f"{os_name}/{arch}")
            if os_name == expected_os and arch == expected_arch:
                return

    rendered_platforms = ", ".join(sorted(available_platforms)) or "(none)"
    raise ValidationError(
        f"{ref}: manifests[] is missing expected platform {expected_os}/{expected_arch}; available={rendered_platforms}"
    )


def main() -> int:
    args = parse_args()
    refs: list[str] = [ref.strip() for ref in args.ref if ref and ref.strip()]
    if not refs:
        print("verify_release_manifest.py: at least one --ref is required", file=sys.stderr)
        return 1
    if args.max_attempts < 1:
        print("verify_release_manifest.py: --max-attempts must be >= 1", file=sys.stderr)
        return 1
    if args.raw_file and len(refs) != 1:
        print("verify_release_manifest.py: --raw-file requires exactly one --ref", file=sys.stderr)
        return 1

    try:
        expected_os, expected_arch = parse_expected_platform(args.expected_platform)
        for ref in refs:
            for attempt in range(1, args.max_attempts + 1):
                try:
                    payload = (
                        load_raw_manifest_from_file(args.raw_file, ref=ref)
                        if args.raw_file
                        else inspect_raw_manifest(ref, anonymous=args.anonymous)
                    )
                    verify_platform_descriptor(payload, ref=ref, expected_os=expected_os, expected_arch=expected_arch)
                    mode = "anonymous" if args.anonymous else "authenticated"
                    print(f"[verify-release-manifest] ok {ref} ({mode}) -> {expected_os}/{expected_arch}")
                    break
                except ValidationError:
                    if args.raw_file or attempt >= args.max_attempts:
                        raise
                    if args.retry_delay_seconds > 0:
                        time.sleep(args.retry_delay_seconds)
        return 0
    except ValidationError as exc:
        print(f"verify_release_manifest.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
