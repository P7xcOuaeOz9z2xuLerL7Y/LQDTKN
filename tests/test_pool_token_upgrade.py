import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bot_blueprint import load_blueprint
from incident_primitives import build_matches, load_primitive_bank, match_primitives, primitive_ids
from live_context_scanner import (
    CHAIN_CONFIGS,
    COMMON_TOKENS,
    annotate_pool_related_tokens,
    append_pool_token_contexts,
    collect_amm_pair_context,
    collect_curve_like_context,
    collect_liquidity_pool_context,
    collect_v3_pool_context,
    infer_audit_focus,
    infer_risk_notes,
    parse_scope_item,
    summarize_related_targets,
)
from pool_token_probe_manifest import build_probe_manifest
from pool_token_stage_runner import materialize_scanner_seed
from pool_token_target_registry import (
    active_target,
    build_target_record,
    load_registry,
    normalize_target,
    write_target_artifacts,
)
import workflow_chain


REPO_ROOT = Path(__file__).resolve().parents[1]
POOL_BLUEPRINT = REPO_ROOT / "blueprints" / "live_pool_token_bug_bounty.json"
PRIMITIVE_BANK = REPO_ROOT / "intelligence" / "slowmist_pool_token_exploit_primitives.json"


def sample_live_pool_context():
    return {
        "protocol": {"name": "Example Pool Token"},
        "chain": "bsc",
        "chain_id": 56,
        "target": {
            "label": "EXM/USDT Pancake pair",
            "address": "0x1111111111111111111111111111111111111111",
        },
        "contracts": [
            {
                "name": "ExampleToken",
                "address": "0x2222222222222222222222222222222222222222",
                "source_file": "contracts/ExampleToken.sol",
                "views": {
                    "owner": "0x0000000000000000000000000000000000000000",
                    "decimals": 18,
                    "totalSupply": "1000000000000000000000000000",
                },
                "risk_notes": [
                    "custom _update and transferFrom paths interact with pair balance",
                    "fee/tax settings can affect Pancake pair reserves",
                ],
            },
            {
                "name": "PancakePair",
                "address": "0x3333333333333333333333333333333333333333",
                "views": {
                    "token0": "0x2222222222222222222222222222222222222222",
                    "token1": "0x55d398326f99059ff775485246999027b3197955",
                    "getReserves": ["1000000000000000000000", "5000000000", 123],
                    "totalSupply": "1000000000000000000",
                },
                "events_discovered": {
                    "Sync": {"count_sampled": 3},
                    "Skim": {"count_sampled": 1},
                    "Transfer": {"count_sampled": 8},
                },
                "balances": {
                    "erc20": [
                        {"symbol": "EXM", "human_balance": "1000", "decimals": 18},
                        {"symbol": "USDT", "human_balance": "5000", "decimals": 18},
                    ]
                },
            },
        ],
        "live_context_signals": [
            "pair_reserves",
            "token_balances",
            "sync_or_skim_events",
            "custom_transfer_logic",
            "pool_token_balance",
            "fee_tax_settings",
            "router_pair_dependency",
        ],
    }


class PoolTokenBlueprintTests(unittest.TestCase):
    def test_live_pool_token_blueprint_loads_and_has_required_primitives(self):
        blueprint = load_blueprint(POOL_BLUEPRINT)
        bank = load_primitive_bank(PRIMITIVE_BANK)

        self.assertEqual(blueprint["project_name"], "Live Pool Token Bug Bounty")
        self.assertGreaterEqual(len(blueprint["target_scopes"]), 5)
        self.assertIn("incident_primitives", blueprint)
        self.assertTrue(set(blueprint["incident_primitives"]).issubset(primitive_ids(bank)))

    def test_primitive_bank_has_completeness_fields(self):
        bank = load_primitive_bank(PRIMITIVE_BANK)

        self.assertGreaterEqual(len(bank["primitives"]), 10)
        for primitive in bank["primitives"]:
            self.assertTrue(primitive["id"])
            self.assertTrue(primitive["keywords"])
            self.assertTrue(primitive["live_context_signals"])
            self.assertTrue(primitive["code_signals"])
            self.assertTrue(primitive["local_checks"])


class PrimitiveMatcherTests(unittest.TestCase):
    def test_matcher_ranks_pool_and_token_drain_primitives(self):
        blueprint = load_blueprint(POOL_BLUEPRINT)
        bank = load_primitive_bank(PRIMITIVE_BANK)
        matches = match_primitives(sample_live_pool_context(), bank, blueprint)
        ids = [item["id"] for item in matches["matched_primitives"]]

        self.assertEqual(matches["schema_version"], "primitive-matches-v1")
        self.assertIn("reserve_desync_sync_skim_burn", ids)
        self.assertIn("token_hook_pair_balance_drain", ids)
        self.assertGreaterEqual(
            ids.index("reserve_desync_sync_skim_burn"),
            0,
        )
        top = matches["matched_primitives"][0]
        self.assertGreaterEqual(top["score"], 5)
        self.assertTrue(top["local_checks"])
        self.assertTrue(matches["completion"]["requires_local_proof"])

    def test_cli_writes_matches_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live_context = root / "live_context.json"
            output = root / "primitive_matches.json"
            live_context.write_text(json.dumps(sample_live_pool_context()), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "run_match_exploit_primitives.py"),
                    "--live-context",
                    str(live_context),
                    "--bank",
                    str(PRIMITIVE_BANK),
                    "--blueprint",
                    str(POOL_BLUEPRINT),
                    "--out",
                    str(output),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=True,
            )

            self.assertIn("Wrote", result.stdout)
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed["schema_version"], "primitive-matches-v1")
            self.assertTrue(parsed["matched_primitives"])

    def test_build_matches_uses_blueprint_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            live_context = Path(tmp) / "live_context.json"
            live_context.write_text(json.dumps(sample_live_pool_context()), encoding="utf-8")

            matches = build_matches(live_context, bank_path=PRIMITIVE_BANK, blueprint_path=POOL_BLUEPRINT)

        self.assertEqual(matches["blueprint_project"], "Live Pool Token Bug Bounty")
        self.assertEqual(matches["target_identity"]["chain"], "bsc")


class PoolTokenProbeManifestTests(unittest.TestCase):
    def _matches(self):
        blueprint = load_blueprint(POOL_BLUEPRINT)
        bank = load_primitive_bank(PRIMITIVE_BANK)
        return match_primitives(sample_live_pool_context(), bank, blueprint)

    def test_probe_manifest_covers_every_matched_primitive(self):
        matches = self._matches()
        manifest = build_probe_manifest(matches, sample_live_pool_context())

        matched_ids = {item["id"] for item in matches["matched_primitives"]}
        probe_ids = {item["primitive_id"] for item in manifest["probes"]}

        self.assertEqual(manifest["schema_version"], "pool-token-probe-manifest-v1")
        self.assertEqual(matched_ids, probe_ids)
        self.assertTrue(manifest["completion"]["all_matched_primitives_have_templates"])
        for probe in manifest["probes"]:
            self.assertTrue(probe["required_live_fields"])
            self.assertTrue(probe["transaction_sequence"])
            self.assertTrue(probe["expected_assertions"])
            self.assertTrue(probe["source_local_checks"])

    def test_probe_manifest_cli_writes_output(self):
        matches = self._matches()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            matches_path = root / "primitive_matches.json"
            live_context_path = root / "live_context.json"
            output = root / "probe_manifest.json"
            matches_path.write_text(json.dumps(matches), encoding="utf-8")
            live_context_path.write_text(json.dumps(sample_live_pool_context()), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "run_generate_pool_token_probe_manifest.py"),
                    "--matches",
                    str(matches_path),
                    "--live-context",
                    str(live_context_path),
                    "--out",
                    str(output),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=True,
            )

            self.assertIn("Wrote", result.stdout)
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed["schema_version"], "pool-token-probe-manifest-v1")
            self.assertEqual(parsed["probe_count"], len(parsed["probes"]))


class PrimitivePromptTests(unittest.TestCase):
    def test_question_prompt_includes_primitive_snapshot_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            matches_path = Path(tmp) / "primitive_matches.json"
            matches_path.write_text(
                json.dumps(
                    {
                        "schema_version": "primitive-matches-v1",
                        "matched_primitives": [
                            {
                                "id": "reserve_desync_sync_skim_burn",
                                "title": "AMM reserve desync",
                                "local_checks": ["compare reserves with balances"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {
                    "BOT_BLUEPRINT_PATH": str(POOL_BLUEPRINT),
                    "PRIMITIVE_MATCHES_PATH": str(matches_path),
                },
                clear=False,
            ):
                import questions

                questions = importlib.reload(questions)
                prompt = questions.question_generator("'File Name: contracts/Token.sol -> Scope: Critical live liquidity extraction'")

        self.assertIn("SlowMist Primitive Match Snapshot", prompt)
        self.assertIn("reserve_desync_sync_skim_burn", prompt)
        self.assertIn("Use these matches as routing hints only", prompt)

    def test_scan_prompt_has_missing_primitive_generation_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            with patch.dict(
                os.environ,
                {
                    "BOT_BLUEPRINT_PATH": str(POOL_BLUEPRINT),
                    "PRIMITIVE_MATCHES_PATH": str(missing),
                },
                clear=False,
            ):
                import questions

                questions = importlib.reload(questions)
                prompt = questions.scan_format("External reserve desync report")

        self.assertIn("No primitive match file was found", prompt)
        self.assertIn("run_match_exploit_primitives.py", prompt)
        self.assertIn("External reserve desync report", prompt)


def word_uint(value):
    return "0x" + hex(value)[2:].rjust(64, "0")


def word_address(address):
    return "0x" + address[2:].lower().rjust(64, "0")


def word_bytes32(text):
    return "0x" + text.encode("utf-8").hex().ljust(64, "0")


class FakePairRpc:
    pair = "0x1111111111111111111111111111111111111111"
    token0 = "0x2222222222222222222222222222222222222222"
    token1 = "0x3333333333333333333333333333333333333333"
    factory = "0x4444444444444444444444444444444444444444"

    selectors = {
        "token0()": "0x0dfe1681",
        "token1()": "0xd21220a7",
        "getReserves()": "0x0902f1ac",
        "totalSupply()": "0x18160ddd",
        "factory()": "0xc45a0155",
        "kLast()": "0x7464fc3d",
        "balanceOf(address)": "0x70a08231",
        "decimals()": "0x313ce567",
        "symbol()": "0x95d89b41",
        "name()": "0x06fdde03",
    }

    def selector(self, signature):
        return self.selectors[signature]

    def eth_call(self, to, data, block="latest"):
        to = to.lower()
        sig = data[:10]
        if to == self.pair and sig == self.selectors["token0()"]:
            return word_address(self.token0)
        if to == self.pair and sig == self.selectors["token1()"]:
            return word_address(self.token1)
        if to == self.pair and sig == self.selectors["factory()"]:
            return word_address(self.factory)
        if to == self.pair and sig == self.selectors["getReserves()"]:
            return word_uint(1000)[0:66] + word_uint(5000)[2:] + word_uint(123)[2:]
        if to == self.pair and sig == self.selectors["totalSupply()"]:
            return word_uint(100)
        if to == self.pair and sig == self.selectors["kLast()"]:
            return word_uint(5_000_000)
        if sig == self.selectors["balanceOf(address)"]:
            if to == self.token0:
                return word_uint(1100)
            if to == self.token1:
                return word_uint(5000)
        if sig == self.selectors["decimals()"]:
            return word_uint(18)
        if sig == self.selectors["symbol()"]:
            return word_bytes32("T0" if to == self.token0 else "T1")
        if sig == self.selectors["name()"]:
            return word_bytes32("Token0" if to == self.token0 else "Token1")
        return None


class FakeV3Rpc(FakePairRpc):
    selectors = {
        **FakePairRpc.selectors,
        "liquidity()": "0x1a686502",
        "fee()": "0xddca3f43",
        "slot0()": "0x3850c7bd",
    }

    def eth_call(self, to, data, block="latest"):
        to = to.lower()
        sig = data[:10]
        if to == self.pair and sig == self.selectors["getReserves()"]:
            return None
        if to == self.pair and sig == self.selectors["liquidity()"]:
            return word_uint(123456)
        if to == self.pair and sig == self.selectors["fee()"]:
            return word_uint(2500)
        if to == self.pair and sig == self.selectors["slot0()"]:
            words = [
                word_uint(2**96)[2:],
                word_uint(100)[2:],
                word_uint(1)[2:],
                word_uint(2)[2:],
                word_uint(3)[2:],
                word_uint(0)[2:],
                word_uint(1)[2:],
            ]
            return "0x" + "".join(words)
        return super().eth_call(to, data, block=block)


class FakeCurveRpc(FakePairRpc):
    coins = [
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
    ]

    selectors = {
        **FakePairRpc.selectors,
        "coins(uint256)": "0x4903b0d1",
        "balances(uint256)": "0x4903b0d2",
        "get_virtual_price()": "0xbb7b8b80",
    }

    def eth_call(self, to, data, block="latest"):
        sig = data[:10]
        if sig == self.selectors["token0()"] or sig == self.selectors["token1()"] or sig == self.selectors["getReserves()"]:
            return None
        if sig == self.selectors["coins(uint256)"]:
            index = int(data[10:], 16)
            if index >= len(self.coins):
                return word_address("0x0000000000000000000000000000000000000000")
            return word_address(self.coins[index])
        if sig == self.selectors["balances(uint256)"]:
            index = int(data[10:], 16)
            return word_uint([1000, 2000][index])
        if sig == self.selectors["get_virtual_price()"]:
            return word_uint(10**18)
        return super().eth_call(to, data, block=block)


class LiveContextScannerUpgradeTests(unittest.TestCase):
    def test_bsc_scope_parsing_and_common_tokens(self):
        chain, address = parse_scope_item("https://bscscan.com/address/0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa")

        self.assertEqual(chain, "bsc")
        self.assertEqual(address, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(CHAIN_CONFIGS["bsc"].chain_id, 56)
        self.assertTrue(any(token["symbol"] == "WBNB" for token in COMMON_TOKENS["bsc"]))

    def test_collect_amm_pair_context_decodes_reserves_and_balance_delta(self):
        pair = collect_amm_pair_context(FakePairRpc(), FakePairRpc.pair)

        self.assertTrue(pair["is_pair_like"])
        self.assertEqual(pair["standard"], "uniswap_v2_like")
        self.assertEqual(pair["token0"]["address"], FakePairRpc.token0)
        self.assertEqual(pair["reserves"]["reserve0_raw"], "1000")
        self.assertEqual(pair["reserves"]["reserve1_raw"], "5000")
        self.assertEqual(pair["pair_token_balances"]["token0_raw"], "1100")
        self.assertEqual(pair["reserve_balance_deltas"]["token0_balance_minus_reserve0_raw"], "100")
        self.assertIn("pair_reserves", pair["primitive_signals"])

    def test_collect_v3_pool_context_decodes_liquidity_and_slot0(self):
        pool = collect_v3_pool_context(FakeV3Rpc(), FakeV3Rpc.pair)

        self.assertTrue(pool["is_pool_like"])
        self.assertEqual(pool["standard"], "uniswap_v3_like")
        self.assertEqual(pool["liquidity_raw"], "123456")
        self.assertEqual(pool["fee"], 2500)
        self.assertEqual(pool["slot0"]["sqrt_price_x96"], str(2**96))
        self.assertIn("concentrated_liquidity", pool["primitive_signals"])

    def test_collect_curve_like_context_decodes_multi_asset_pool(self):
        pool = collect_curve_like_context(FakeCurveRpc(), FakeCurveRpc.pair)

        self.assertTrue(pool["is_pool_like"])
        self.assertEqual(pool["standard"], "curve_like")
        self.assertEqual(len(pool["coins"]), 2)
        self.assertEqual(pool["balances_raw"], ["1000", "2000"])
        self.assertEqual(pool["virtual_price_raw"], str(10**18))

    def test_collect_liquidity_pool_context_reports_detected_standards(self):
        context = collect_liquidity_pool_context(FakeV3Rpc(), FakeV3Rpc.pair)

        self.assertTrue(context["is_pool_like"])
        self.assertIn("uniswap_v3_like", context["detected_standards"])
        self.assertIn("slot0_price", context["primitive_signals"])

    def test_pair_context_adds_risk_notes_and_audit_focus(self):
        contract = {
            "balances": {"erc20": []},
            "views": {},
            "events_discovered": {},
            "amm_pair": collect_amm_pair_context(FakePairRpc(), FakePairRpc.pair),
            "liquidity_pool": collect_liquidity_pool_context(FakePairRpc(), FakePairRpc.pair),
        }

        notes = infer_risk_notes(contract)
        focus = infer_audit_focus(contract)

        self.assertTrue(any("Liquidity pool detected" in note for note in notes))
        self.assertTrue(any("V2-style pair" in note for note in notes))
        self.assertTrue(any("protocol-specific liquidity pool" in item for item in focus))
        self.assertTrue(any("reserve/balance desync" in item for item in focus))

    def test_pair_related_tokens_marks_onc_as_primary_suspect_and_usdt_as_counter_asset(self):
        contract = {
            "address": FakePairRpc.pair,
            "liquidity_pool": {
                "is_pool_like": True,
                "adapters": [
                    {
                        "standard": "uniswap_v2_like",
                        "token0": {
                            "address": "0x9999999999999999999999999999999999999999",
                            "symbol": "ONC",
                            "name": "ONC Token",
                            "decimals": 18,
                        },
                        "token1": {
                            "address": "0x55d398326f99059ff775485246999027b3197955",
                            "symbol": "USDT",
                            "name": "Tether USD",
                            "decimals": 18,
                        },
                    }
                ],
            },
        }

        refs = annotate_pool_related_tokens("bsc", contract)
        related = summarize_related_targets([contract])

        self.assertEqual(len(refs), 2)
        self.assertEqual(contract["pool_related_tokens"]["primary_suspect_tokens"][0]["symbol"], "ONC")
        self.assertEqual(contract["pool_related_tokens"]["counter_assets"][0]["symbol"], "USDT")
        self.assertEqual(related[0]["pool_address"], FakePairRpc.pair)

    def test_append_pool_token_contexts_scans_only_non_common_pair_token(self):
        pool_contract = {
            "address": FakePairRpc.pair,
            "liquidity_pool": {
                "is_pool_like": True,
                "adapters": [
                    {
                        "standard": "uniswap_v2_like",
                        "token0": {
                            "address": "0x9999999999999999999999999999999999999999",
                            "symbol": "ONC",
                            "name": "ONC Token",
                            "decimals": 18,
                        },
                        "token1": {
                            "address": "0x55d398326f99059ff775485246999027b3197955",
                            "symbol": "USDT",
                            "name": "Tether USD",
                            "decimals": 18,
                        },
                    }
                ],
            },
        }
        calls = []

        def fake_builder(**kwargs):
            calls.append(kwargs["address"])
            return {
                "name": "ONCToken",
                "address": kwargs["address"],
                "balances": {"erc20": []},
                "views": {"owner": "0x0000000000000000000000000000000000000000"},
                "events_discovered": {},
                "amm_pair": {"is_pair_like": False},
                "liquidity_pool": {"is_pool_like": False},
                "risk_notes": [],
                "audit_focus": [],
                "_meta": {},
            }

        expanded = append_pool_token_contexts(
            client=FakePairRpc(),
            chain_cfg=CHAIN_CONFIGS["bsc"],
            protocol="ONC",
            contracts=[pool_contract],
            latest_block=123,
            sample_window_blocks=10,
            max_view_calls=1,
            max_event_samples=1,
            max_events=1,
            max_erc20_tokens=1,
            discover_transfer_tokens=False,
            include_nft_scan=False,
            include_dependencies=False,
            mapping_time_budget_s=0.0,
            etherscan_api_key=None,
            max_expansions=4,
            context_builder=fake_builder,
        )

        self.assertEqual(calls, ["0x9999999999999999999999999999999999999999"])
        self.assertEqual(len(expanded), 1)
        self.assertEqual(expanded[0]["_meta"]["target_role"], "pool_underlying_token")
        self.assertEqual(expanded[0]["_meta"]["pool_parent"], FakePairRpc.pair)
        self.assertIn("token-side pool drain", expanded[0]["audit_focus"][0])


class PoolTokenTargetRegistryTests(unittest.TestCase):
    def test_normalize_target_accepts_bscscan_url_and_raw_address(self):
        from_url = normalize_target("https://bscscan.com/address/0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa")
        from_raw = normalize_target("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", default_chain="bsc")

        self.assertEqual(from_url["chain"], "bsc")
        self.assertEqual(from_url["address"], "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(from_raw["chain_id"], "56")
        self.assertEqual(from_raw["address"], "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

    def test_intake_writes_registry_active_target_and_audit_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry_path = root / "setup" / "target_registry.json"
            active_path = root / "setup" / "active_target.json"
            record = build_target_record(
                target="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                default_chain="bsc",
                protocol="Example",
                label="Example Pool",
                target_type="pool",
                blueprint_path="blueprints/live_pool_token_bug_bounty.json",
            )

            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                paths = write_target_artifacts(record, registry_path=registry_path, active_target_path=active_path)
                registry = load_registry(registry_path)
                active = active_target(registry)
            finally:
                os.chdir(old_cwd)

            self.assertTrue(paths["registry"].exists())
            self.assertTrue(paths["active_target"].exists())
            self.assertTrue(paths["audit_seed"].exists())
            self.assertEqual(active["address"], "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            seed = json.loads(paths["audit_seed"].read_text(encoding="utf-8"))
            self.assertEqual(seed["schema_version"], "pool-token-audit-seed-v1")
            self.assertIn("live pool liquidity extraction", seed["paid_impact_focus"])

    def test_materialize_scanner_seed_from_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry_path = root / "setup" / "target_registry.json"
            active_path = root / "setup" / "active_target.json"
            record = build_target_record(
                target="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                default_chain="bsc",
                protocol="Example",
                label="Example Pool",
                target_type="pool",
                blueprint_path="blueprints/live_pool_token_bug_bounty.json",
            )

            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                write_target_artifacts(record, registry_path=registry_path, active_target_path=active_path)
                live_context_path = Path(record["paths"]["live_context"])
                live_context_path.parent.mkdir(parents=True, exist_ok=True)
                live_context_path.write_text(
                    json.dumps(
                        {
                            "related_targets": [
                                {
                                    "address": "0x9999999999999999999999999999999999999999",
                                    "symbol": "ONC",
                                    "target_role": "primary_suspect_token",
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                seed_path = materialize_scanner_seed(registry_path)
            finally:
                os.chdir(old_cwd)

            self.assertTrue(seed_path.exists())
            parsed = json.loads(seed_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed["schema_version"], "pool-token-scanner-seed-v1")
            self.assertEqual(parsed["target"]["chain"], "bsc")
            self.assertEqual(parsed["related_targets"][0]["symbol"], "ONC")


class PoolTokenWorkflowChainTests(unittest.TestCase):
    def test_zero_stage_verifiers_use_expected_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "setup").mkdir()
            (root / "targets" / "bsc" / "0xabc").mkdir(parents=True)
            (root / "setup" / "target_registry.json").write_text("{}", encoding="utf-8")
            (root / "setup" / "active_target.json").write_text("{}", encoding="utf-8")
            (root / "targets" / "bsc" / "0xabc" / "audit_seed.json").write_text("{}", encoding="utf-8")

            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                self.assertTrue(workflow_chain.verify_stage("0.0"))
                self.assertTrue(workflow_chain.has_remaining("0.1"))
                self.assertFalse(workflow_chain.verify_stage("0.2"))
            finally:
                os.chdir(old_cwd)

    def test_zero_stage_three_accepts_probe_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "probes").mkdir()
            (root / "targets" / "bsc" / "0xabc").mkdir(parents=True)
            (root / "probes" / "probe_manifest.json").write_text("{}", encoding="utf-8")
            (root / "targets" / "bsc" / "0xabc" / "probe_manifest.json").write_text("{}", encoding="utf-8")

            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                self.assertTrue(workflow_chain.verify_stage("0.3"))
            finally:
                os.chdir(old_cwd)

    def test_zero_stage_workflow_files_reference_expected_stage_ids(self):
        expected = {
            "0.0_intake_live_pool_token_target.yml": "--stage 0.0",
            "0.1_collect_live_pool_token_context.yml": "--stage 0.1",
            "0.2_match_pool_token_primitives.yml": "--stage 0.2",
            "0.3_generate_pool_token_probe_manifest.yml": "--stage 0.3",
            "0.4_materialize_pool_token_scanner_seed.yml": "--stage 0.4",
        }

        for filename, stage_arg in expected.items():
            path = REPO_ROOT / ".github" / "workflows" / filename
            self.assertTrue(path.exists(), filename)
            content = path.read_text(encoding="utf-8")
            self.assertIn(stage_arg, content)
            self.assertIn("chain_next", content)


if __name__ == "__main__":
    unittest.main()
