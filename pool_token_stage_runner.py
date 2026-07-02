#!/usr/bin/env python3
"""Stage wrappers for the live pool/token workflow chain."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from pool_token_target_registry import DEFAULT_REGISTRY_PATH, active_target, load_registry, write_json


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def collect_live_context(registry_path: str = str(DEFAULT_REGISTRY_PATH)) -> Path:
    target = active_target(load_registry(registry_path))
    live_context_path = Path(target["paths"]["live_context"])
    live_context_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "live_context_scanner.py",
        "--url",
        target["explorer_url"],
        "--default-chain",
        target["chain"],
        "--protocol",
        target["protocol"],
        "--out",
        str(live_context_path),
    ]
    _run(command)
    setup_live_context = Path("setup/live_context.json")
    setup_live_context.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(live_context_path, setup_live_context)
    return live_context_path


def match_primitives(registry_path: str = str(DEFAULT_REGISTRY_PATH)) -> Path:
    target = active_target(load_registry(registry_path))
    live_context_path = Path(target["paths"]["live_context"])
    matches_path = Path(target["paths"]["primitive_matches"])
    matches_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "run_match_exploit_primitives.py",
        "--live-context",
        str(live_context_path),
        "--blueprint",
        target["blueprint_path"],
        "--out",
        str(matches_path),
    ]
    _run(command)
    setup_matches = Path("setup/primitive_matches.json")
    setup_matches.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(matches_path, setup_matches)
    return matches_path


def generate_probe_manifest(registry_path: str = str(DEFAULT_REGISTRY_PATH)) -> Path:
    target = active_target(load_registry(registry_path))
    live_context_path = Path(target["paths"]["live_context"])
    matches_path = Path(target["paths"]["primitive_matches"])
    manifest_path = Path(target["paths"]["probe_manifest"])
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "run_generate_pool_token_probe_manifest.py",
        "--matches",
        str(matches_path),
        "--live-context",
        str(live_context_path),
        "--out",
        str(manifest_path),
    ]
    _run(command)
    setup_manifest = Path("probes/probe_manifest.json")
    setup_manifest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(manifest_path, setup_manifest)
    return manifest_path


def materialize_scanner_seed(registry_path: str = str(DEFAULT_REGISTRY_PATH)) -> Path:
    target = active_target(load_registry(registry_path))
    seed_path = Path("scanned") / f"pool_token_seed__{target['chain']}__{target['address']}.json"
    related_targets = []
    live_context_path = Path(target["paths"]["live_context"])
    if live_context_path.exists():
        try:
            live_context = json.loads(live_context_path.read_text(encoding="utf-8"))
            if isinstance(live_context.get("related_targets"), list):
                related_targets = live_context["related_targets"]
        except (json.JSONDecodeError, OSError):
            related_targets = []
    seed = {
        "schema_version": "pool-token-scanner-seed-v1",
        "target": {
            "protocol": target["protocol"],
            "label": target["label"],
            "target_type": target["target_type"],
            "chain": target["chain"],
            "chain_id": target["chain_id"],
            "address": target["address"],
            "explorer_url": target["explorer_url"],
        },
        "artifacts": {
            "audit_seed": target["paths"]["audit_seed"],
            "live_context": target["paths"]["live_context"],
            "primitive_matches": target["paths"]["primitive_matches"],
            "probe_manifest": target["paths"]["probe_manifest"],
        },
        "related_targets": related_targets,
        "instruction": "Use the active live pool/token blueprint plus primitive matches. Return only candidates that need local proof; do not mark anything validated.",
    }
    return write_json(seed_path, seed)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a live pool/token stage wrapper.")
    parser.add_argument(
        "stage",
        choices=("collect-live-context", "match-primitives", "generate-probe-manifest", "materialize-scanner-seed"),
    )
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY_PATH))
    args = parser.parse_args()

    if args.stage == "collect-live-context":
        path = collect_live_context(args.registry)
    elif args.stage == "match-primitives":
        path = match_primitives(args.registry)
    elif args.stage == "generate-probe-manifest":
        path = generate_probe_manifest(args.registry)
    else:
        path = materialize_scanner_seed(args.registry)
    print(f"{args.stage}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
