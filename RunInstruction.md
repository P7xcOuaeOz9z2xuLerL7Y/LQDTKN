# RunInstruction

This repository runs a GitHub Actions chain for live pool, token, vault, reward, bridge, and locker targets. The current tested branch is `master`.

## Required Secrets

- `PAT_TOKEN`: GitHub personal access token with permission to dispatch workflows and push workflow artifacts back to this repository.

DeepWiki itself is accessed through the browser automation in workflows `7` and `8`. The repo does not currently require a separate DeepWiki API key.

## Standard Run Order

Run the workflows in this order:

1. `0.0 Intake Live Pool Token Target`
2. `0.1 Collect Live Pool Token Context`
3. `0.2 Match Pool Token Primitives`
4. `0.3 Generate Pool Token Probe Manifest`
5. `0.4 Materialize Pool Token Scanner Seed`
6. `7 Run Scanner Automation`
7. `8 Run Validation Report Automation`

If `chain_next` is set to `true`, the current workflow verifies its output and dispatches the next workflow automatically. For manual control, keep `chain_next=false` and run the next workflow yourself after checking the committed output.

## Workflow Inputs

### `target`

Use an explorer URL or raw contract address.

Examples:

- `0x8665A78ccC84D6Df2ACaA4b207d88c6Bc9b70Ec5`
- `https://bscscan.com/address/0x8665A78ccC84D6Df2ACaA4b207d88c6Bc9b70Ec5`

For a pair address, the machine treats the pair as the entry target, then expands into underlying token targets where possible.

### `default_chain`

Used only when `target` is a raw address.

Examples:

- `bsc`
- `eth`
- `base`
- `arbitrum`
- `optimism`

Changing `bsc` to `eth` works only if the scanner has chain config and explorer/RPC support for that chain. The chain value must match the real address network.

### `protocol`

Short project or token label for the run.

For `WKEYDAO/USDT` Pancake pair, use `wkeydao` if the likely vulnerable component is the WKEYDAO token. Use `pancakeswap` only when the DEX pair implementation itself is the audit target.

### `label`

Human-readable target label used in artifacts and DeepWiki prompts.

Example:

- `wkeydao Pancake pair`
- `ONC/USDT live pair`
- `Example reward pool`

This is needed so later outputs can be understood without re-opening the address.

### `target_type`

Use the closest target class:

- `pool`
- `token`
- `vault`
- `reward_pool`
- `bridge`
- `locker`
- `pool_or_token`

Changing `pool_or_token` to `reward_pool` works when the address is actually a reward pool. It changes the audit focus and primitive matching; it does not magically convert a pool address into a reward contract.

### `smoke_limit`

Optional small-run cap for testing.

Use:

- blank for full run
- `1` for smallest smoke run
- `2` or higher to process a few queued items

### `chain_next`

Set to:

- `false` to stop after this workflow
- `true` to verify output and dispatch the next workflow

Use `true` when the upstream workflow has already been tested and you want the chain to continue without manual clicks.

## Workflow Outputs

### `0.0 Intake Live Pool Token Target`

Purpose: normalize the input target and create the active target record.

Outputs:

- `setup/target_registry.json`
- `setup/active_target.json`
- `targets/<chain>/<address>/audit_seed.json`

Success means the machine knows the target chain, address, label, type, explorer URL, and blueprint path.

### `0.1 Collect Live Pool Token Context`

Purpose: collect live on-chain context for the active target.

Outputs:

- `setup/live_context.json`
- `targets/<chain>/<address>/live_context.json`

For a pair address, this stage detects token0/token1, reserves, balances, LP supply, and common counter assets. If one side is a common asset like USDT and the other is a project token, the project token is marked as the primary suspect token and scanned as an expanded target.

### `0.2 Match Pool Token Primitives`

Purpose: match live context against known hacked pool/token/liquidity primitives.

Outputs:

- `setup/primitive_matches.json`
- `targets/<chain>/<address>/primitive_matches.json`

Success means the machine has ranked relevant exploit classes such as reserve desync, token-side pair drain, LP/share inflation, approval/permit drain, reward replay, or oracle extraction.

### `0.3 Generate Pool Token Probe Manifest`

Purpose: convert matched primitives into local proof/probe instructions.

Outputs:

- `probes/probe_manifest.json`
- `targets/<chain>/<address>/probe_manifest.json`

Success means every matched primitive has required live fields, transaction sequence ideas, expected assertions, and local proof requirements.

### `0.4 Materialize Pool Token Scanner Seed`

Purpose: create the DeepWiki scanner seed.

Outputs:

- `scanned/pool_token_seed__<chain>__<address>.json`

Success means workflow `7` has a concrete scan input.

### `7 Run Scanner Automation`

Purpose: submit the scanner seed to DeepWiki.

Inputs it acts on:

- `scanned/*.json`
- `scanned/*.md`

Outputs:

- `validated_questions_pending/*.json`
- `validated_questions/*.json`
- `validation_pending/*.json`

Success means DeepWiki received the scan prompt and the resulting DeepWiki URL was saved for workflow `8`.

### `8 Run Validation Report Automation`

Purpose: open the DeepWiki result URL, copy DeepWiki's response, classify it, and persist the outcome.

Inputs it acts on:

- `validation_pending/*.json`
- `validated_questions/*.json`

Outputs can land in:

- `needs_local_proof/`: plausible candidate requiring local proof
- `deepwiki_candidates/`: stronger candidate, still requiring local proof
- `deepwiki_unknown/`: response could not be classified
- `rejected_by_deepwiki/`: DeepWiki rejected or found no usable candidate
- `validated/`: legacy final validation output if later stages promote it

Workflow `8` does not prove a vulnerability by itself. It triages DeepWiki's reasoning. A critical finding is not real until local proof confirms attacker reachability, current live state, and concrete value extraction.

## Tested WKEYDAO Pair Run

Test target:

- chain: `bsc`
- address: `0x8665A78ccC84D6Df2ACaA4b207d88c6Bc9b70Ec5`
- protocol: `wkeydao`
- label: `wkeydao Pancake pair`
- target_type: `pool`

Observed live context:

- pair: `0x8665a78ccc84d6df2acaa4b207d88c6bc9b70ec5`
- token0: `wkeyDAO`, `0x194b302a4b0a79795fb68e2adf1b8c9ec5ff8d1f`
- token1: `USDT`, `0x55d398326f99059ff775485246999027b3197955`
- primary suspect token: `wkeyDAO`
- counter asset: `USDT`
- pair USDT balance observed: about `431321.6433 USDT`
- expanded token source: `contracts/ERC20.sol`, Sourcify full match

Matched primitive examples:

- `reserve_desync_sync_skim_burn`
- `lp_share_or_vault_share_inflation`
- `admin_role_bypass_to_mint_dump_or_withdraw`
- `permit_signature_or_approval_wrapper_drain`
- `token_hook_pair_balance_drain`

Important note: an earlier workflow `8` result was saved under `rejected_by_deepwiki/` before the DeepWiki prompt was fixed to include the inline active target and live context. That earlier rejection should be treated as stale operational evidence, not as a meaningful security result for WKEYDAO.

## How Critical Findings Are Supposed To Surface

The machine can uncover a critical vulnerability only through this chain:

1. Live context identifies the real value-bearing contract and related token targets.
2. Primitive matching routes the target into known loss-producing exploit classes.
3. DeepWiki checks whether the current code and live state plausibly match one of those exploit classes.
4. Workflow `8` saves a candidate into `needs_local_proof/` or `deepwiki_candidates/`.
5. A local proof stage must then reproduce the attack path with current code/live assumptions.
6. Only after local proof shows unprivileged value extraction should anything become report-ready.

The current setup is now operational and prompt-aligned for pool/token targets, but critical discovery quality still depends on source availability. The next upgrade should persist verified source or decompiled code under `targets/<chain>/<address>/source/` and include those files directly in the DeepWiki seed so DeepWiki does not rely on stale indexed repository context.

## Troubleshooting

If workflow `7` shows success but you do not see obvious output, check:

- `validated_questions_pending/`
- `validated_questions/`
- `validation_pending/`

If workflow `8` shows success but no candidate appears, check:

- `rejected_by_deepwiki/`
- `deepwiki_unknown/`

A rejection means the workflow ran and DeepWiki did not produce a usable candidate. It does not mean the target is safe.

If a workflow says there are no files to process, the previous stage did not commit the expected directory, or the expected input was already consumed.

If DeepWiki mentions an unrelated project, old protocol, or stale live context, the run is not semantically valid. Rerun workflow `7` after confirming the prompt contains the current inline `Active Target Snapshot` and `Live Context Snapshot`.
