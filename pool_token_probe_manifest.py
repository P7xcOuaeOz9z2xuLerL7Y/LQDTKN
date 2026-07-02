#!/usr/bin/env python3
"""Generate local proof probe manifests from pool/token primitive matches."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_MATCHES_PATH = Path("setup") / "primitive_matches.json"
DEFAULT_LIVE_CONTEXT_PATH = Path("setup") / "live_context.json"
DEFAULT_OUTPUT_PATH = Path("probes") / "probe_manifest.json"


PROBE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "reserve_desync_sync_skim_burn": {
        "probe_type": "fork",
        "required_live_fields": ["amm_pair.reserves", "amm_pair.pair_token_balances", "amm_pair.reserve_balance_deltas"],
        "setup": [
            "fork at or after live_context.block_number",
            "snapshot pair getReserves() and token0/token1 balanceOf(pair)",
            "fund attacker with enough token/native balance for candidate transfer or swap path",
        ],
        "transaction_sequence": [
            "execute the smallest attacker-controlled token transfer, hook, burn, fee, rebase, or maintenance trigger that can affect pair balances",
            "if available and attacker-callable, call skim() or sync(); otherwise route through the real router/pair swap path",
            "attempt the profitable swap or withdrawal path",
        ],
        "expected_assertions": [
            "attacker final token0/token1/native value is not greater than starting value plus fair market output",
            "cached reserves and live balances cannot be rewritten into a profitable skew by the attacker",
            "constant-product or pool-specific invariant does not become attacker-profitable after fees and loan repayment",
        ],
    },
    "token_hook_pair_balance_drain": {
        "probe_type": "fuzz_or_fork",
        "required_live_fields": ["contracts[].source_file", "amm_pair.token0", "amm_pair.token1", "events_discovered.Transfer"],
        "setup": [
            "identify every custom transfer, transferFrom, _transfer, _update, fee, tax, mint, burn, and rebase path",
            "bind pair/router addresses from live context",
        ],
        "transaction_sequence": [
            "fuzz zero-value transfer, self-transfer, pair transfer, router transfer, transferFrom, and fee-exempt branch inputs",
            "compare pair balances/reserves before and after each trigger",
            "route any balance-changing sequence into a swap or withdrawal attempt",
        ],
        "expected_assertions": [
            "no unprivileged token call can create extractable pair balance or reserve imbalance",
            "fee/tax/rebase/mint/burn branches cannot be steered by direct pair balance manipulation",
        ],
    },
    "forgeable_liquidity_add_detection": {
        "probe_type": "fork",
        "required_live_fields": ["amm_pair.reserves", "router_pair_dependency", "fee_tax_settings"],
        "setup": ["snapshot sell fee classification around the live pair and router"],
        "transaction_sequence": [
            "send dust quote/token amount directly to the pair",
            "perform sell path through router or pair",
            "compare fee charged and received output against baseline sell without dust transfer",
        ],
        "expected_assertions": ["direct pair transfers cannot forge add-liquidity classification or bypass value-protecting sell accounting"],
    },
    "lp_share_or_vault_share_inflation": {
        "probe_type": "unit_or_fork",
        "required_live_fields": ["totalAssets", "totalSupply", "deposit_withdraw_paths"],
        "setup": ["snapshot asset balance, totalAssets, totalSupply, and attacker share balance"],
        "transaction_sequence": [
            "test first depositor, dust deposit, donation, old deposit path, withdraw, redeem, and migration paths",
            "loop deposit/redeem around rounding boundaries",
        ],
        "expected_assertions": [
            "attacker cannot redeem more assets than their proportional share",
            "total share claims never exceed live backing assets",
        ],
    },
    "fake_lp_token_or_position_validation": {
        "probe_type": "unit_or_fork",
        "required_live_fields": ["factory", "token0", "token1", "lp_token_identity"],
        "setup": ["build fake LP/position/pool-id inputs and bind real factory/token pair identity"],
        "transaction_sequence": [
            "attempt withdraw/remove-liquidity with fake LP token, fake position, wrong pool id, wrong factory, and wrong token pair",
            "attempt same path with deprecated or inactive pool identifiers if present",
        ],
        "expected_assertions": ["withdrawal identity must bind factory, pair, LP/position owner, and token identities before value moves"],
    },
    "spot_price_or_oracle_flashloan_extraction": {
        "probe_type": "fork",
        "required_live_fields": ["oracle_source", "spot_pool_dependency", "price_used_for_value_movement"],
        "setup": ["select historical block with live liquidity and configure flash-loan or large swap funding"],
        "transaction_sequence": [
            "manipulate spot/reserve source inside the transaction or supported window",
            "call mint/redeem/borrow/liquidate/swap/claim path that consumes the manipulated price",
            "restore/reverse manipulation and compute net attacker value",
        ],
        "expected_assertions": ["net attacker profit after repayment and fees must be non-positive unless the protocol intentionally pays that value"],
    },
    "reward_accumulator_or_claim_replay": {
        "probe_type": "unit_or_fork",
        "required_live_fields": ["reward_balance", "reward_accumulator", "staking_total_supply", "claim_history"],
        "setup": ["snapshot funded rewards, caller stake/share, accumulator/index, and claimed flags"],
        "transaction_sequence": [
            "attempt zero-share claim, flash-stake claim, repeated claim, duplicate pool-id claim, and stale proof/signature claim",
            "claim before and after balance/share update boundaries",
        ],
        "expected_assertions": ["attacker claimed reward cannot exceed entitlement and total claims cannot exceed funded rewards"],
    },
    "permit_signature_or_approval_wrapper_drain": {
        "probe_type": "unit",
        "required_live_fields": ["permit_domain", "nonce_state", "allowance_paths", "wrapper_token"],
        "setup": ["construct invalid signatures, replayed signatures, wrong spender, wrong chain/domain, and address(0) recovery cases"],
        "transaction_sequence": [
            "call permit/approval wrapper with each invalid authorization case",
            "attempt transferFrom or withdrawFrom after any accepted approval",
        ],
        "expected_assertions": ["invalid authorization cannot create allowance or move user/protocol assets"],
    },
    "liquidity_locker_owner_override": {
        "probe_type": "unit_or_fork",
        "required_live_fields": ["locked_lp_balance", "unlock_time", "withdraw_authorization"],
        "setup": ["snapshot lock owner, unlock time, LP balance, and withdrawal recipient"],
        "transaction_sequence": [
            "attempt unprivileged mutation of fee, owner, recipient, unlock time, or emergency mode",
            "attempt withdraw before valid unlock conditions",
        ],
        "expected_assertions": ["locked or protocol-held LP cannot move before valid unlock and authorization conditions"],
    },
    "bridge_wrapped_supply_or_escrow_mismatch": {
        "probe_type": "unit_or_fork",
        "required_live_fields": ["escrow_balance", "wrapped_supply", "message_validation"],
        "setup": ["snapshot escrow backing, wrapped supply, message nonce, source chain, token, amount, recipient, and proof inputs"],
        "transaction_sequence": [
            "submit wrong source chain/channel, replayed nonce, wrong token, wrong amount, fake proof/message, and valid baseline message",
            "attempt redeem/release for each case",
        ],
        "expected_assertions": ["real escrowed assets cannot be released or wrapped assets minted without a valid bound message"],
    },
    "deprecated_pool_or_old_path_compatibility": {
        "probe_type": "fork",
        "required_live_fields": ["deprecated_contract_with_balance", "old_entrypoint", "withdraw_or_redeem_path"],
        "setup": ["snapshot old/deprecated contract balances, approvals, and callable legacy selectors"],
        "transaction_sequence": [
            "call old deposit/mint/migration entrypoints if still reachable",
            "redeem/withdraw through current or alternate path",
        ],
        "expected_assertions": ["old-path state cannot inflate current-path withdrawal value beyond live backing"],
    },
    "admin_role_bypass_to_mint_dump_or_withdraw": {
        "probe_type": "unit_or_fork",
        "required_live_fields": ["authorization_guard", "owner_or_admin", "mint_or_withdraw_path", "live_pool_for_dump"],
        "setup": ["identify exact authorization guard and value-moving privileged function"],
        "transaction_sequence": [
            "attempt guard bypass without owner/governance/key compromise",
            "if bypass succeeds, route minted/withdrawn assets into live pool/value path",
        ],
        "expected_assertions": ["unprivileged caller cannot bypass the guard or produce value-moving privileged state changes"],
    },
}


def read_json(path: str | os.PathLike[str]) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _target_identity(matches: Dict[str, Any], live_context: Dict[str, Any]) -> Dict[str, Any]:
    identity = matches.get("target_identity")
    if isinstance(identity, dict) and identity:
        return identity
    contracts = live_context.get("contracts") if isinstance(live_context.get("contracts"), list) else []
    first = contracts[0] if contracts and isinstance(contracts[0], dict) else {}
    return {
        "protocol": live_context.get("protocol", {}).get("name") if isinstance(live_context.get("protocol"), dict) else live_context.get("protocol", ""),
        "chain": live_context.get("chain", ""),
        "chain_id": live_context.get("chain_id", ""),
        "address": first.get("address", ""),
        "label": first.get("name", ""),
    }


def build_probe_manifest(matches: Dict[str, Any], live_context: Dict[str, Any]) -> Dict[str, Any]:
    matched_primitives = matches.get("matched_primitives")
    if not isinstance(matched_primitives, list):
        raise ValueError("primitive matches must contain matched_primitives list")

    target_identity = _target_identity(matches, live_context)
    probes: List[Dict[str, Any]] = []
    missing_templates: List[str] = []

    for index, primitive in enumerate(matched_primitives, 1):
        if not isinstance(primitive, dict):
            continue
        primitive_id = primitive.get("id")
        if not isinstance(primitive_id, str):
            continue
        template = PROBE_TEMPLATES.get(primitive_id)
        if not template:
            missing_templates.append(primitive_id)
            continue

        probes.append(
            {
                "id": f"P{index:03d}-{primitive_id}",
                "primitive_id": primitive_id,
                "primitive_title": primitive.get("title", ""),
                "primitive_score": primitive.get("score", 0),
                "target_identity": target_identity,
                "probe_type": template["probe_type"],
                "required_live_fields": template["required_live_fields"],
                "setup": template["setup"],
                "transaction_sequence": template["transaction_sequence"],
                "expected_assertions": template["expected_assertions"],
                "reject_if": primitive.get("reject_if_missing", []),
                "source_local_checks": primitive.get("local_checks", []),
            }
        )

    return {
        "schema_version": "pool-token-probe-manifest-v1",
        "target_identity": target_identity,
        "source_matches_schema": matches.get("schema_version", ""),
        "probe_count": len(probes),
        "probes": probes,
        "missing_templates": missing_templates,
        "completion": {
            "all_matched_primitives_have_templates": not missing_templates,
            "requires_execution": True,
            "note": "This manifest defines local proof tasks only; no finding is confirmed until a probe/test passes.",
        },
    }


def write_manifest(manifest: Dict[str, Any], path: str | os.PathLike[str]) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate local proof probe manifest from primitive matches.")
    parser.add_argument("--matches", default=os.environ.get("PRIMITIVE_MATCHES_PATH", str(DEFAULT_MATCHES_PATH)))
    parser.add_argument("--live-context", default=os.environ.get("LIVE_CONTEXT_PATH", str(DEFAULT_LIVE_CONTEXT_PATH)))
    parser.add_argument("--out", default=str(DEFAULT_OUTPUT_PATH))
    args = parser.parse_args()

    matches = read_json(args.matches)
    live_context = read_json(args.live_context)
    manifest = build_probe_manifest(matches, live_context)
    out = write_manifest(manifest, args.out)
    print(f"Wrote {manifest['probe_count']} probe(s) to {out}")
    if manifest["missing_templates"]:
        print(f"Missing templates: {', '.join(manifest['missing_templates'])}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
