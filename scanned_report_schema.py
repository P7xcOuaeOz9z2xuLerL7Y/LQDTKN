"""JSON contract for reports placed in or produced from the scanner flow."""

from __future__ import annotations

import json
from typing import Any, Dict


SCANNED_REPORT_CONTRACT: Dict[str, Any] = {
    "schema_version": "scanned-report-v1",
    "verdict": "REJECT | NEEDS_LOCAL_PROOF | HIGH_CONFIDENCE_CANDIDATE",
    "reject_if_not_paid_scope": True,
    "paid_scope_match": "fund_extraction | protocol_value_drain | reward_extraction | unfair_reward_access | none",
    "report_identity": {
        "title": "",
        "source_report_id": "",
        "source_url": "",
        "source_severity": "critical | high | unknown",
        "external_root_primitive": (
            "authorization_bypass | accounting_drift | state_transition_ordering | "
            "reward_accumulator_error | oracle_price_manipulation | rounding_precision | "
            "replay_nonce | reentrancy_callback | token_transfer_semantics | invariant_mismatch"
        ),
    },
    "target_protocol_gate": {
        "blueprint_protocol": "",
        "live_context_protocol": "",
        "live_context_source": "setup/live_context.json | inline | none",
        "context_matches_blueprint": False,
        "context_mismatch_reason": "",
    },
    "live_onchain_context": {
        "chain": "",
        "chain_id": "",
        "latest_block": "",
        "captured_at_utc": "",
        "commands_used": [
            {
                "purpose": "",
                "command": "",
                "expected_output_field": "",
                "observed_value": "",
            }
        ],
        "contracts": [
            {
                "name": "",
                "address": "",
                "source_file": "",
                "proxy": {
                    "is_proxy": False,
                    "implementation": "",
                    "admin": "",
                },
                "balances": {
                    "native": {"raw": "", "human": "", "usd": "unknown"},
                    "erc20": [],
                    "erc721": [],
                    "erc1155": [],
                },
                "critical_views": {},
                "critical_mappings_or_structs": {},
                "events_or_recent_activity": {},
                "dependencies": [],
            }
        ],
        "protocol_preconditions": [
            {
                "name": "",
                "required_for_exploit": True,
                "live_value": "",
                "why_it_matters": "",
            }
        ],
    },
    "candidate": {
        "claim": "",
        "exact_code_path": [
            {
                "file": "",
                "function": "",
                "symbols_or_lines": "",
            }
        ],
        "attacker_path": {
            "attacker_profile": "",
            "preconditions": [],
            "attacker_controlled_inputs": [],
            "call_sequence": [],
        },
        "value_extraction_model": {
            "asset_or_reward": "",
            "who_loses_value": "",
            "how_attacker_gains_value": "",
            "why_this_is_not_only_dos_or_griefing": "",
        },
        "existing_checks_reviewed": [],
        "why_checks_fail": "",
        "local_proof_required": {
            "test_type": "",
            "test_file_to_add": "",
            "setup": [],
            "expected_assertion": "",
            "failure_condition": "",
        },
    },
    "rejection_gates": {
        "unprivileged_trigger": False,
        "concrete_attacker_value_gain": False,
        "not_admin_or_governance": False,
        "not_pure_external_dependency": False,
        "not_expected_behavior": False,
        "not_duplicate_or_known_issue": False,
        "not_stale_live_context": False,
    },
    "rejection_reason": "",
}


def scanned_report_contract_json() -> str:
    return json.dumps(SCANNED_REPORT_CONTRACT, indent=2)
