import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

import questions
import workflow_chain
from bot_blueprint import load_blueprint
from bot_runtime import batch_limit, smoke_enabled, smoke_limit
from deepwiki_triage import classify_deepwiki_response, parse_json_response, save_deepwiki_response
from proof_gate_schema import PROOF_GATE_CONTRACT
from scanned_report_schema import SCANNED_REPORT_CONTRACT


class BlueprintPromptTests(unittest.TestCase):
    def test_default_blueprint_preserves_deepwiki_memory(self):
        blueprint = load_blueprint()

        self.assertEqual(blueprint["repo_name"], "623_sable_active_pool")
        self.assertIn("src/ActivePool.sol", blueprint["scope_files"])
        self.assertEqual(len(blueprint["target_scopes"]), 2)
        self.assertTrue(any("fund extraction" in scope.lower() for scope in blueprint["target_scopes"]))
        self.assertTrue(any("reward extraction" in scope.lower() for scope in blueprint["target_scopes"]))

    def test_audit_prompt_uses_triage_verdicts_not_final_validation(self):
        prompt = questions.audit_format(
            "[File: src/ActivePool.sol] [Function: sendBNB] Can an attacker over-withdraw?"
        )

        self.assertIn("## DeepWiki Automation Boundary", prompt)
        self.assertIn("REJECT", prompt)
        self.assertIn("NEEDS_LOCAL_PROOF", prompt)
        self.assertIn("HIGH_CONFIDENCE_CANDIDATE", prompt)
        self.assertIn("## Local Proof Required", prompt)
        self.assertNotIn("Audit Report\n\n## Title", prompt)

    def test_question_generator_includes_blueprint_and_local_proof_language(self):
        prompt = questions.question_generator(
            "'File Name: src/ActivePool.sol -> Scope: Critical Fund extraction or protocol value drain'"
        )

        self.assertIn("DeepWiki Memory Blueprint", prompt)
        self.assertIn("Known rejection memory", prompt)
        self.assertIn("Local proof idea", prompt)
        self.assertIn("src/Interfaces/IActivePool.sol", prompt)

    def test_repository_rotation_ignores_stale_other_protocol_urls(self):
        repo_data = """
[
  "https://deepwiki.com/example/midnight--001",
  "https://deepwiki.com/example/623_sable_active_pool--001",
  "https://deepwiki.com/example/623_sable_active_pool--002"
]
"""
        with patch("questions.os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=repo_data)):
                urls = questions.load_repository_urls()

        self.assertEqual(
            urls,
            [
                "https://deepwiki.com/example/623_sable_active_pool--001",
                "https://deepwiki.com/example/623_sable_active_pool--002",
            ],
        )

    def test_scanner_prompt_expands_external_reports_into_scenarios(self):
        prompt = questions.scan_format("External high severity reward-accumulator report")

        self.assertIn("Scanner Intelligence Rules", prompt)
        self.assertIn("fund extraction / protocol value drain", prompt)
        self.assertIn("reward extraction / unfair reward access", prompt)
        self.assertIn("Do not stop after the first weak mapping", prompt)

    def test_scanner_prompt_requires_json_and_live_context_gate(self):
        prompt = questions.scan_format("External critical accounting report")

        self.assertIn("Scanned Report JSON Contract", prompt)
        self.assertIn('"schema_version": "scanned-report-v1"', prompt)
        self.assertIn("Output only valid JSON", prompt)
        self.assertIn("stale live context does not match active blueprint", prompt)
        self.assertIn("python3 live_context_scanner.py --from-questions", prompt)

    def test_scanned_report_contract_only_allows_paid_scope_families(self):
        self.assertTrue(SCANNED_REPORT_CONTRACT["reject_if_not_paid_scope"])
        self.assertIn("fund_extraction", SCANNED_REPORT_CONTRACT["paid_scope_match"])
        self.assertIn("reward_extraction", SCANNED_REPORT_CONTRACT["paid_scope_match"])
        self.assertIn("live_onchain_context", SCANNED_REPORT_CONTRACT)

    def test_proof_gate_prompt_asks_exact_live_state_question(self):
        with tempfile.TemporaryDirectory() as tmp:
            live_context = Path(tmp) / "live_context.json"
            live_context.write_text('{"protocol": {"name": "Sable"}, "contracts": []}', encoding="utf-8")

            with patch.dict(os.environ, {"LIVE_CONTEXT_PATH": str(live_context)}, clear=False):
                prompt = questions.proof_gate_format("candidate overclaims rewards")

        self.assertIn("DEEPWIKI EXACT PROOF GATE", prompt)
        self.assertIn("Does this exact current protocol, with current live state", prompt)
        self.assertIn('"schema_version": "proof-gate-v1"', prompt)
        self.assertIn("Output only valid JSON", prompt)
        self.assertIn('"protocol": {"name": "Sable"}', prompt)

    def test_proof_gate_contract_tracks_hard_gates(self):
        hard_gates = PROOF_GATE_CONTRACT["hard_gates"]

        self.assertIn("concrete_fund_or_reward_gain", hard_gates)
        self.assertIn("gain_is_beyond_entitlement", hard_gates)
        self.assertIn("not_dos_grief_or_liveness_only", hard_gates)
        self.assertIn("local_proof_required", PROOF_GATE_CONTRACT)


class DeepWikiTriageTests(unittest.TestCase):
    def test_classifies_known_verdicts(self):
        self.assertEqual(classify_deepwiki_response("#NoVulnerability found"), "reject")
        self.assertEqual(
            classify_deepwiki_response("## Verdict\nNEEDS_LOCAL_PROOF\n\n## Local Proof Required"),
            "needs_local_proof",
        )
        self.assertEqual(
            classify_deepwiki_response("## Verdict\nHIGH_CONFIDENCE_CANDIDATE"),
            "high_confidence_candidate",
        )
        self.assertEqual(
            classify_deepwiki_response('{"verdict": "NEEDS_LOCAL_PROOF", "paid_scope_match": "fund_extraction"}'),
            "needs_local_proof",
        )
        self.assertEqual(classify_deepwiki_response("plausible but legacy text"), "unknown")

    def test_save_routes_candidates_without_using_validated_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {
                "DEEPWIKI_CANDIDATE_DIR": str(root / "deepwiki_candidates"),
                "NEEDS_LOCAL_PROOF_DIR": str(root / "needs_local_proof"),
                "REJECTED_BY_DEEPWIKI_DIR": str(root / "rejected_by_deepwiki"),
            }

            with patch.dict(os.environ, env, clear=False):
                path = save_deepwiki_response(
                    "## Verdict\nNEEDS_LOCAL_PROOF\n\n## Local Proof Required\nassert x",
                    "https://deepwiki.com/example/query",
                )

            self.assertIsNotNone(path)
            assert path is not None
            self.assertEqual(path.parent.name, "needs_local_proof")
            content = path.read_text(encoding="utf-8")
            self.assertIn("deepwiki_source_url", content)
            self.assertIn("deepwiki_verdict: needs_local_proof", content)
            self.assertFalse((root / "validated").exists())

    def test_save_preserves_json_outputs_as_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {"NEEDS_LOCAL_PROOF_DIR": str(root / "needs_local_proof")}
            content = '{"verdict": "NEEDS_LOCAL_PROOF", "paid_scope_match": "reward_extraction"}'

            with patch.dict(os.environ, env, clear=False):
                path = save_deepwiki_response(content, "https://deepwiki.com/example/json", prefix="scan")

            self.assertIsNotNone(path)
            assert path is not None
            self.assertEqual(path.suffix, ".json")
            parsed = parse_json_response(path.read_text(encoding="utf-8"))
            self.assertIsNotNone(parsed)
            assert parsed is not None
            self.assertEqual(parsed["deepwiki_verdict"], "needs_local_proof")
            self.assertEqual(parsed["deepwiki_source_url"], "https://deepwiki.com/example/json")

    def test_rejects_are_not_saved_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"REJECTED_BY_DEEPWIKI_DIR": str(Path(tmp) / "rejected_by_deepwiki")}

            with patch.dict(os.environ, env, clear=False):
                path = save_deepwiki_response(
                    "## Verdict\nREJECT\n\n## Rejection Reason\nexpected behavior",
                    "https://deepwiki.com/example/reject",
                )

            self.assertIsNone(path)
            self.assertFalse((Path(tmp) / "rejected_by_deepwiki").exists())


class RuntimeLimitTests(unittest.TestCase):
    def test_smoke_limit_defaults_to_full_batch(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(smoke_limit())
            self.assertFalse(smoke_enabled())
            self.assertEqual(batch_limit(25), 25)

    def test_smoke_limit_overrides_batch_size(self):
        with patch.dict(os.environ, {"BOT_SMOKE_LIMIT": "2"}, clear=True):
            self.assertEqual(smoke_limit(), 2)
            self.assertTrue(smoke_enabled())
            self.assertEqual(batch_limit(25), 2)

    def test_smoke_limit_rejects_invalid_values(self):
        with patch.dict(os.environ, {"BOT_SMOKE_LIMIT": "0"}, clear=True):
            with self.assertRaises(ValueError):
                smoke_limit()


class WorkflowChainTests(unittest.TestCase):
    def test_stage_verifier_and_remaining_inputs_use_expected_globs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scope").mkdir()
            (root / "scope" / "one.json").write_text("[]", encoding="utf-8")

            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                self.assertTrue(workflow_chain.verify_stage("1"))
                self.assertTrue(workflow_chain.has_remaining("2"))
                self.assertFalse(workflow_chain.verify_stage("2"))
            finally:
                os.chdir(old_cwd)

    def test_stage_seven_accepts_json_scanner_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scanned").mkdir()
            (root / "scanned" / "external-report.json").write_text("{}", encoding="utf-8")

            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                self.assertTrue(workflow_chain.has_remaining("7"))
            finally:
                os.chdir(old_cwd)

    def test_stage_six_uses_staged_candidate_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "needs_local_proof").mkdir()
            (root / "needs_local_proof" / "candidate.json").write_text("{}", encoding="utf-8")

            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                self.assertTrue(workflow_chain.has_remaining("6"))
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
