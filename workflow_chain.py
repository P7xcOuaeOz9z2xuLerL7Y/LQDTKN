import argparse
import glob
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class Stage:
    output_globs: tuple[str, ...]
    remaining_globs: tuple[str, ...] = ()
    final_message: str = ""


STAGES = {
    "0.0": Stage(
        output_globs=("setup/target_registry.json", "setup/active_target.json", "targets/*/*/audit_seed.json"),
        final_message="Target intake complete. Run stage 0.1 to collect live context.",
    ),
    "0.1": Stage(
        output_globs=("setup/live_context.json", "targets/*/*/live_context.json"),
        remaining_globs=("setup/active_target.json",),
        final_message="Live context collected. Run stage 0.2 to match SlowMist-derived exploit primitives.",
    ),
    "0.2": Stage(
        output_globs=("setup/primitive_matches.json", "targets/*/*/primitive_matches.json"),
        remaining_globs=("setup/live_context.json",),
        final_message="Primitive matching complete. Run stage 0.3 to generate local proof probes.",
    ),
    "0.3": Stage(
        output_globs=("probes/probe_manifest.json", "targets/*/*/probe_manifest.json"),
        remaining_globs=("setup/primitive_matches.json",),
        final_message="Probe manifest generated. Run stage 0.4 to materialize a DeepWiki scanner seed, or run local probes first.",
    ),
    "0.4": Stage(
        output_globs=("scanned/pool_token_seed__*.json",),
        remaining_globs=("probes/probe_manifest.json",),
        final_message="Pool/token scanner seed ready. Continue with Workflow 7 scanner.",
    ),
    "1": Stage(output_globs=("scope/*.json",)),
    "2": Stage(output_globs=("scope_questions/*.json",), remaining_globs=("scope/*.json",)),
    "3": Stage(output_globs=("question/*.json",), remaining_globs=("scope_questions/*.json",)),
    "4": Stage(output_globs=("automation/*.json",), remaining_globs=("question/*.json",)),
    "5": Stage(
        output_globs=(
            "needs_local_proof/*.md",
            "needs_local_proof/*.json",
            "deepwiki_candidates/*.md",
            "deepwiki_candidates/*.json",
            "deepwiki_unknown/*.md",
            "deepwiki_unknown/*.json",
            "audited/*.md",
        ),
        remaining_globs=("automation/*.json",),
        final_message="DeepWiki reports are staged. Run Workflow 6 proof gate on needs_local_proof/ and deepwiki_candidates/ before local proof.",
    ),
    "6": Stage(
        output_globs=("validated_questions/*.json",),
        remaining_globs=(
            "needs_local_proof/*.md",
            "needs_local_proof/*.json",
            "deepwiki_candidates/*.md",
            "deepwiki_candidates/*.json",
        ),
    ),
    "7": Stage(output_globs=("validated_questions/*.json",), remaining_globs=("scanned/*.md", "scanned/*.json")),
    "8": Stage(
        output_globs=(
            "needs_local_proof/*.md",
            "needs_local_proof/*.json",
            "deepwiki_candidates/*.md",
            "deepwiki_candidates/*.json",
            "deepwiki_unknown/*.md",
            "deepwiki_unknown/*.json",
            "validated/*.md",
        ),
        remaining_globs=("validated_questions/*.json",),
        final_message="Validation reports are staged. Run local proof before submission.",
    ),
}


def _matches(patterns: Iterable[str]) -> list[str]:
    found: list[str] = []
    for pattern in patterns:
        found.extend(glob.glob(pattern))
    return sorted(set(found))


def verify_stage(stage_id: str) -> bool:
    stage = STAGES[stage_id]
    outputs = _matches(stage.output_globs)
    if outputs:
        print(f"Stage {stage_id} verified with {len(outputs)} output item(s).")
        for item in outputs[:10]:
            print(f"  - {item}")
        if len(outputs) > 10:
            print(f"  ... {len(outputs) - 10} more")
        return True

    print(f"Stage {stage_id} did not produce expected outputs.")
    print("Expected one of:")
    for pattern in stage.output_globs:
        print(f"  - {pattern}")
    return False


def has_remaining(stage_id: str) -> bool:
    stage = STAGES[stage_id]
    if not stage.remaining_globs:
        return False
    remaining = _matches(stage.remaining_globs)
    print(f"Stage {stage_id} remaining input count: {len(remaining)}")
    return bool(remaining)


def dispatch_workflow(workflow: str, ref: str, smoke_limit: str = "", chain_next: bool = True) -> None:
    token = os.environ.get("PAT_TOKEN") or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token:
        raise RuntimeError("PAT_TOKEN, GH_TOKEN, or GITHUB_TOKEN is required to dispatch the next workflow")
    if not repository:
        raise RuntimeError("GITHUB_REPOSITORY is required to dispatch the next workflow")

    payload = {
        "ref": ref,
        "inputs": {
            "smoke_limit": smoke_limit,
            "chain_next": "true" if chain_next else "false",
        },
    }
    url = f"https://api.github.com/repos/{repository}/actions/workflows/{workflow}/dispatches"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status not in (200, 201, 202, 204):
                raise RuntimeError(f"Unexpected dispatch status {response.status}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Workflow dispatch failed: HTTP {exc.code}: {body}") from exc
    print(f"Dispatched {workflow} on {ref} with smoke_limit={smoke_limit!r} chain_next={chain_next}.")


def advance(stage_id: str, same_workflow: Optional[str], next_workflow: Optional[str], ref: str, smoke_limit: str) -> int:
    if not verify_stage(stage_id):
        return 1

    target = same_workflow if same_workflow and has_remaining(stage_id) else next_workflow
    if target:
        dispatch_workflow(target, ref=ref, smoke_limit=smoke_limit, chain_next=True)
    else:
        message = STAGES[stage_id].final_message
        if message:
            print(message)
        print(f"Stage {stage_id} chain complete.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify and advance the DeepWiki GitHub workflow chain.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--stage", required=True, choices=sorted(STAGES))

    advance_parser = subparsers.add_parser("advance")
    advance_parser.add_argument("--stage", required=True, choices=sorted(STAGES))
    advance_parser.add_argument("--same-workflow", default="")
    advance_parser.add_argument("--next-workflow", default="")
    advance_parser.add_argument("--ref", default=os.environ.get("GITHUB_REF_NAME", "master"))
    advance_parser.add_argument("--smoke-limit", default=os.environ.get("BOT_SMOKE_LIMIT", ""))

    args = parser.parse_args()
    if args.command == "verify":
        return 0 if verify_stage(args.stage) else 1
    if args.command == "advance":
        return advance(
            args.stage,
            same_workflow=args.same_workflow or None,
            next_workflow=args.next_workflow or None,
            ref=args.ref,
            smoke_limit=args.smoke_limit,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
