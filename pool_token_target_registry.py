#!/usr/bin/env python3
"""Target intake and registry helpers for live pool/token audit workflows."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from live_context_scanner import CHAIN_CONFIGS, addr_norm, is_address, parse_scope_item


REGISTRY_SCHEMA = "pool-token-target-registry-v1"
AUDIT_SEED_SCHEMA = "pool-token-audit-seed-v1"
DEFAULT_REGISTRY_PATH = Path("setup") / "target_registry.json"
DEFAULT_ACTIVE_TARGET_PATH = Path("setup") / "active_target.json"


class TargetRegistryError(ValueError):
    pass


def normalize_target(target: str, default_chain: Optional[str] = None) -> Dict[str, str]:
    chain, address = parse_scope_item(target)
    chain = chain or default_chain
    if not chain:
        raise TargetRegistryError("Target chain is required for raw addresses")
    if chain not in CHAIN_CONFIGS:
        raise TargetRegistryError(f"Unsupported chain: {chain}")
    if not address or not is_address(address):
        raise TargetRegistryError(f"Invalid target address: {target}")
    return {"chain": chain, "chain_id": str(CHAIN_CONFIGS[chain].chain_id), "address": addr_norm(address)}


def target_dir(chain: str, address: str) -> str:
    return f"targets/{chain}/{addr_norm(address)}"


def explorer_url(chain: str, address: str) -> str:
    address = addr_norm(address)
    if chain == "bsc":
        return f"https://bscscan.com/address/{address}"
    if chain == "ethereum":
        return f"https://etherscan.io/address/{address}"
    if chain == "arbitrum":
        return f"https://arbiscan.io/address/{address}"
    if chain == "base":
        return f"https://basescan.org/address/{address}"
    if chain == "optimism":
        return f"https://optimistic.etherscan.io/address/{address}"
    return address


def build_target_record(
    *,
    target: str,
    default_chain: Optional[str],
    protocol: str,
    label: str,
    target_type: str,
    blueprint_path: str,
) -> Dict[str, Any]:
    normalized = normalize_target(target, default_chain=default_chain)
    chain = normalized["chain"]
    address = normalized["address"]
    root = target_dir(chain, address)
    display_label = label or protocol or address

    return {
        "schema_version": "pool-token-target-v1",
        "active": True,
        "protocol": protocol or display_label,
        "label": display_label,
        "target_type": target_type,
        "chain": chain,
        "chain_id": normalized["chain_id"],
        "address": address,
        "source": target,
        "explorer_url": explorer_url(chain, address),
        "blueprint_path": blueprint_path,
        "paths": {
            "target_dir": root,
            "audit_seed": f"{root}/audit_seed.json",
            "live_context": f"{root}/live_context.json",
            "primitive_matches": f"{root}/primitive_matches.json",
            "probe_manifest": f"{root}/probe_manifest.json",
            "deepwiki_brief": f"{root}/deepwiki_brief.md",
        },
        "workflow": {
            "0.0_intake_target": "complete",
            "0.1_collect_live_context": "pending",
            "0.2_match_exploit_primitives": "pending",
            "0.3_generate_probe_manifest": "pending",
            "1_generate_questions": "pending",
        },
    }


def empty_registry() -> Dict[str, Any]:
    return {"schema_version": REGISTRY_SCHEMA, "active_target": "", "targets": []}


def load_registry(path: str | os.PathLike[str] = DEFAULT_REGISTRY_PATH) -> Dict[str, Any]:
    registry_path = Path(path)
    if not registry_path.exists():
        return empty_registry()
    with registry_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise TargetRegistryError("Target registry must be a JSON object")
    if data.get("schema_version") != REGISTRY_SCHEMA:
        raise TargetRegistryError(f"Unsupported target registry schema: {data.get('schema_version')}")
    targets = data.get("targets")
    if not isinstance(targets, list):
        raise TargetRegistryError("Target registry must contain a targets list")
    return data


def upsert_target(registry: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
    key = f"{record['chain']}:{record['address']}"
    out = dict(registry)
    targets: List[Dict[str, Any]] = []
    replaced = False

    for existing in registry.get("targets", []):
        if not isinstance(existing, dict):
            continue
        existing_key = f"{existing.get('chain')}:{existing.get('address')}"
        if existing_key == key:
            targets.append(record)
            replaced = True
        else:
            updated = dict(existing)
            updated["active"] = False
            targets.append(updated)

    if not replaced:
        targets.append(record)

    out["schema_version"] = REGISTRY_SCHEMA
    out["active_target"] = key
    out["targets"] = targets
    return out


def active_target(registry: Dict[str, Any]) -> Dict[str, Any]:
    active_key = registry.get("active_target")
    targets = [target for target in registry.get("targets", []) if isinstance(target, dict)]
    for target in targets:
        if f"{target.get('chain')}:{target.get('address')}" == active_key:
            return target
    for target in targets:
        if target.get("active"):
            return target
    raise TargetRegistryError("No active target found")


def audit_seed(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": AUDIT_SEED_SCHEMA,
        "protocol": record["protocol"],
        "label": record["label"],
        "target_type": record["target_type"],
        "chain": record["chain"],
        "chain_id": record["chain_id"],
        "address": record["address"],
        "explorer_url": record["explorer_url"],
        "blueprint_path": record["blueprint_path"],
        "paid_impact_focus": [
            "live pool liquidity extraction",
            "token-side pool drain",
            "LP or vault share extraction",
            "reward extraction",
            "approval or permit drain",
        ],
        "required_next_artifacts": [
            record["paths"]["live_context"],
            record["paths"]["primitive_matches"],
            record["paths"]["probe_manifest"],
        ],
        "deepwiki_boundary": "Seed only. DeepWiki candidates still need exact live context, primitive matching, and local proof.",
    }


def write_json(path: str | os.PathLike[str], payload: Dict[str, Any]) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out.resolve()


def write_target_artifacts(
    record: Dict[str, Any],
    registry_path: str | os.PathLike[str] = DEFAULT_REGISTRY_PATH,
    active_target_path: str | os.PathLike[str] = DEFAULT_ACTIVE_TARGET_PATH,
) -> Dict[str, Path]:
    registry = upsert_target(load_registry(registry_path), record)
    paths = {
        "registry": write_json(registry_path, registry),
        "active_target": write_json(active_target_path, record),
        "audit_seed": write_json(record["paths"]["audit_seed"], audit_seed(record)),
    }
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Register a live pool/token/vault target for the audit workflow.")
    parser.add_argument("--target", required=True, help="Explorer URL or raw address.")
    parser.add_argument("--default-chain", choices=sorted(CHAIN_CONFIGS), help="Required for raw addresses.")
    parser.add_argument("--protocol", default="", help="Protocol/project name.")
    parser.add_argument("--label", default="", help="Human-readable target label.")
    parser.add_argument(
        "--target-type",
        default="pool_or_token",
        choices=("pool", "token", "vault", "reward_pool", "bridge", "locker", "pool_or_token"),
    )
    parser.add_argument("--blueprint-path", default="blueprints/live_pool_token_bug_bounty.json")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY_PATH))
    parser.add_argument("--active-target", default=str(DEFAULT_ACTIVE_TARGET_PATH))
    args = parser.parse_args()

    record = build_target_record(
        target=args.target,
        default_chain=args.default_chain,
        protocol=args.protocol,
        label=args.label,
        target_type=args.target_type,
        blueprint_path=args.blueprint_path,
    )
    paths = write_target_artifacts(record, registry_path=args.registry, active_target_path=args.active_target)
    print(f"Registered {record['chain']}:{record['address']}")
    for name, path in paths.items():
        print(f"{name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
