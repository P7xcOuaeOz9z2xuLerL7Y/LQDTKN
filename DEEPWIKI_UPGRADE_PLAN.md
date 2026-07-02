# DeepWiki Bot Upgrade Plan

## Goal

Keep DeepWiki as the real-time source-reasoning engine, but stop treating DeepWiki output as final validation. DeepWiki should produce structured candidates and local proof tasks. The local repo proves or rejects them with code review and runnable tests.

## Final Pipeline

1. Scope files and paid impact classes are loaded from a project blueprint.
2. DeepWiki receives the blueprint as memory in every generation, audit, validation, and analog-scan prompt.
3. DeepWiki returns one of three verdicts:
   - `REJECT`
   - `NEEDS_LOCAL_PROOF`
   - `HIGH_CONFIDENCE_CANDIDATE`
4. The automation routes outputs into staging folders:
   - `deepwiki_candidates/`
   - `needs_local_proof/`
   - `rejected_by_deepwiki/` when `SAVE_REJECTED_DEEPWIKI=1`
   - `deepwiki_unknown/`
5. Nothing goes directly to `validated/`.
6. A local proof pass reviews the cited code, checks expected behavior and prior reports, writes/runs the PoC, then promotes only passing findings.

## GitHub Smoke Mode

The numbered GitHub workflows now accept optional manual dispatch inputs:

```text
smoke_limit
chain_next
```

When set, the same workflow path runs with `BOT_SMOKE_LIMIT=<value>`.

Smoke mode is for proving the workflow alignment before a full run:

- process only a small number of scope files, questions, reports, or scanner inputs;
- still commit/push the intermediate files needed by the next numbered workflow;
- do not recursively dispatch the same workflow again;
- verify that DeepWiki responses land in staging folders instead of `validated/`.

For a first smoke pass, use `smoke_limit=1` through workflows 1 to 5, then inspect `needs_local_proof/`, `deepwiki_candidates/`, and `deepwiki_unknown/`.

When `chain_next=true`, each workflow verifies its expected output and dispatches either:

- the same workflow again if that stage still has input remaining; or
- the next numbered workflow when the stage is complete.

The chain controller is `workflow_chain.py`. Normal manual workflows still keep the old recursive behavior when `chain_next` is not enabled.

## Blueprint Strategy

The old hard-coded `questions.py` memory is now externalized in `blueprints/sable_fund_reward.json`.

This keeps the benefit of a DeepWiki memory blueprint while making it safer:

- project memory can be swapped with `BOT_BLUEPRINT_PATH`;
- stale protocol context is easier to detect;
- target scopes, known rejection memory, in-scope files, interfaces, invariants, and attack surfaces live in one structured file;
- tests can verify that the prompt is using the intended blueprint.

## DeepWiki Prompt Rules

DeepWiki cannot run Foundry/unit/fuzz tests during automation. The prompt now states this explicitly and forbids terms like confirmed, validated, proven, or submission-ready.

Every non-rejected candidate must include:

- paid scope match;
- exact file/function/symbol path;
- attacker preconditions and call sequence;
- why existing checks fail;
- expected-behavior, prior-report, README/NatSpec, and unsupported-assumption checks;
- exact local proof required.

## Scanner Upgrade

The scanner prompt should treat high/critical external reports as exploit primitives, not as one exact report to clone.

For each external report, DeepWiki must:

- extract the root primitive, such as authorization bypass, accounting drift, reward accumulator error, replay, reentrancy/callback, oracle/price manipulation, rounding, or state-ordering bug;
- search for adjacent scenarios across both paid bug families:
  - fund extraction / protocol value drain;
  - reward extraction / unfair reward access;
- try nearby code paths and equivalent accounting/reward invariants before rejecting;
- still reject anything without concrete attacker-controlled fund/reward gain under supported assumptions.

## Scanned Report JSON Arrangement

`scanned/` can now hold either legacy `.md` reports or structured `.json` reports. The preferred format is JSON because it gives DeepWiki a deterministic contract instead of free-form prose.

Every scanner output must match `scanned-report-v1` from `scanned_report_schema.py` and include:

- `verdict`: `REJECT`, `NEEDS_LOCAL_PROOF`, or `HIGH_CONFIDENCE_CANDIDATE`;
- `paid_scope_match`: only `fund_extraction`, `protocol_value_drain`, `reward_extraction`, `unfair_reward_access`, or `none`;
- `reject_if_not_paid_scope: true`;
- external report identity and root primitive;
- target protocol gate proving the live context matches the active blueprint;
- live on-chain context: chain, block, contracts, balances, proxy implementation/admin, critical views, mappings/structs, events, dependencies, and commands used;
- protocol preconditions that already exist on-chain and why each matters;
- exact code path, attacker path, value extraction model, existing checks reviewed, and local proof required;
- rejection gates that must all be true before anything can leave `REJECT`.

Mere high-severity issues are rejected unless they land in one of the two paid families:

- fund extraction / protocol value drain;
- reward extraction / unfair reward access.

The scanner must reject DoS, freeze, liveness, griefing, liquidation blockage, generic accounting noise, or theoretical issues unless the same path gives the attacker concrete value.

## Live Context Gate

Live context is useful only when it belongs to the current protocol. If `setup/live_context.json` is stale or describes another protocol, DeepWiki must reject instead of adapting that stale context.

Preferred commands:

```bash
python3 live_context_scanner.py --from-questions --protocol "Sable" --out setup/live_context.json
python3 live_context_scanner.py --scope-file scope_urls.json --protocol "Sable" --out setup/live_context.json
cast chain-id --rpc-url "$RPC_URL"
cast block latest --rpc-url "$RPC_URL"
cast balance <contract_address> --rpc-url "$RPC_URL"
cast call <contract_address> "functionName()(returnType)" --rpc-url "$RPC_URL"
cast storage <contract_address> <slot> --rpc-url "$RPC_URL"
cast logs --address <contract_address> --from-block <start> --to-block latest --rpc-url "$RPC_URL"
```

## Local Proof Gate

A candidate can move past staging only after local verification proves:

- cited code exists;
- claim is not expected behavior;
- claim is not a duplicate or prior known issue;
- paid impact is concrete;
- assumptions are supported by the target program;
- runnable test or deterministic proof passes.

## DeepWiki Exact Proof Gate

Workflow 6 is now the DeepWiki proof-gate workflow.

It asks one question for every staged candidate:

```text
Does this exact current protocol, with current live state, allow an unprivileged attacker to extract funds or rewards beyond entitlement?
```

Inputs:

- `needs_local_proof/*.md`
- `needs_local_proof/*.json`
- `deepwiki_candidates/*.md`
- `deepwiki_candidates/*.json`
- `setup/live_context.json` or `LIVE_CONTEXT_PATH`

Process:

1. `run_generate_proof_gate_pending.py` moves up to `BOT_SMOKE_LIMIT` or 25 candidates into `proof_gate_pending/`.
2. `run_proof_gate.py` sends each candidate plus live context into DeepWiki using `proof_gate_format()`.
3. DeepWiki must return `proof-gate-v1` JSON.
4. Workflow 8 collects the DeepWiki URLs and routes the JSON result into staging folders.

The proof gate still does not mark anything final. It converts noisy DeepWiki candidates into proof-ready local work items with exact live preconditions, code paths, attacker paths, and assertions.

Hard gates:

- current protocol only;
- live state supports the preconditions;
- unprivileged attacker;
- attacker-controlled trigger;
- exact code path exists;
- concrete fund or reward gain;
- gain is beyond entitlement;
- not DoS, grief, or liveness only;
- not admin/governance/key-compromise;
- not external dependency only;
- not expected behavior;
- not known duplicate.

## Current Implementation

- `bot_blueprint.py` loads and validates blueprint JSON.
- `questions.py` builds DeepWiki prompts from the active blueprint.
- `deepwiki_triage.py` classifies and routes DeepWiki responses.
- `automation.py` and `audit_validation.py` save DeepWiki outputs to staging folders.
- `bot_runtime.py` provides `BOT_SMOKE_LIMIT` support for GitHub smoke runs.
- `proof_gate_schema.py` defines the exact proof-gate JSON contract.
- `run_generate_proof_gate_pending.py` and `run_proof_gate.py` drive Workflow 6.
- `tests/test_deepwiki_upgrade.py` covers blueprint loading, prompt gates, verdict parsing, and staging behavior.
