# Live Pool And Token Audit Upgrade Plan

## Current finding

This repo is already arranged around a DeepWiki blueprint contract:

- `bot_blueprint.py` loads one JSON blueprint.
- `questions.py` injects that blueprint into generation, triage, scanner, and proof-gate prompts.
- `scanned_report_schema.py` and `proof_gate_schema.py` force structured JSON outputs.
- local proof remains the final gate before anything is treated as validated.

The current default blueprint is still Sable-specific (`blueprints/sable_fund_reward.json`), and `setup/live_context.json` is not aligned to live pool/token bounty hunting. The upgrade should not be another hard-coded protocol profile. It should become a reusable live-liquidity machine.

## SlowMist evidence summary

Source checked: `https://hacked.slowmist.io/` on 2026-07-01.

SlowMist currently lists 2,172 total hack events and about $37.88B in total losses. I fetched the 109-page public index and filtered for pool, liquidity, LP, AMM, DEX, swap, reserve, token, mint, burn, vault, share, reward, oracle, and flash-loan language. 934 of 2,172 events matched that pool/token/liquidity surface.

Overlapping incident buckets from the filtered set:

- token mint, burn, transfer, fee, tax, or hook behavior: 454
- flash-loan, price, reserve, or oracle manipulation: 303
- admin, owner, deployer, governance, or key path that ends in token/liquidity dump: 263
- LP share, vault share, deposit, withdraw, or redemption accounting: 211
- bridge, wrapped-token, IBC, escrow, or vault liquidity path: 144
- reward, claim, dividend, staking, or harvest accounting: 142
- reserve, `sync`, `skim`, burn-from-pair, or AMM desync path: 113
- frontend, approval, permit, signature, or drainer path: 54

Recent high-signal examples:

- LABUBU/OLPC: token `_update` logic burned pool balances and desynced PancakeSwap V2 reserves.
- Little Boy Plus: zero-value `transferFrom` triggered unauthorized harvest/mint into the LP pair.
- DIP: token transfer logic plus `skim`/`sync` manipulated a PancakeSwap pool.
- DTXT/USDT: forgeable liquidity-addition detection let large sells bypass fees.
- BYToken: public auto-burn maintenance burned tokens from the pair and rewrote reserves.
- SKP: token logic moved extra tokens out of the LP, then `sync` pushed reserves into a drainable state.
- Haedal Vault: old deposit path minted inflated LP shares, then new path redeemed excess assets.
- Raydium: deprecated AMM allowed fake LP mint validation to withdraw from inactive pools.
- Lixir Finance: broken EIP-2612 permit on LP wrapper vault tokens allowed unauthorized withdrawal.
- DxSale: legacy liquidity locker override/backdating drained old locked LPs.

## Target machine arrangement

Keep this repo as the automation/control-plane repo. Put live targets and DeepWiki-indexed audit packages into deterministic folders.

```text
blueprints/
  live_pool_token_bug_bounty.json       # reusable DeepWiki memory blueprint
  <target>.json                         # target-specific override when needed

intelligence/
  slowmist_pool_token_exploit_primitives.json
  slowmist_ingestion_status.json
  primitives/
    reserve_desync.json
    lp_share_inflation.json
    token_hook_drain.json
    reward_overclaim.json
    approval_permit_drain.json

setup/
  live_context.json                     # active target live state only
  target_registry.json                  # queued pool/token/vault targets

targets/
  <chain>/<target-address>/
    audit_seed.json
    source_or_decompiled/
    live_context.json
    primitive_matches.json
    deepwiki_brief.md

probes/
  <chain>/<target-address>/
    probe_manifest.json
    raw_results.json
    call_matrix.md
    state_diff_summary.md

runs/
  <timestamp>-<target>/
    candidate_queue.json
    proof_cursor.json
    local_test_results.json
```

## Blueprint contract

The blueprint should tell DeepWiki that the only paid target is attacker-controlled value extraction from live liquidity, live token balances, or live reward/claim state.

Core paid families:

- pool reserve drain or AMM invariant break
- LP/vault/share over-mint, over-redeem, or fake-share withdrawal
- token hook, transfer tax, mint, burn, rebase, fee, or `sync`/`skim` desync drain
- oracle/spot-price/flash-loan manipulation when it extracts real pool/vault/lending value
- reward, dividend, staking, harvest, or emission overclaim
- permit/signature/approval bug that moves LP wrappers, vault shares, pool tokens, or user assets
- bridge/wrapped-token mint/redeem/escrow mismatch that drains real assets
- admin/owner/governance/key paths only when the contract had an on-chain preventable authorization invariant

Reject by default:

- pure key compromise with no protocol-side prevention rule
- pure rug/scam reputation issues without a concrete vulnerable on-chain value path
- DoS/freeze/liveness without extraction
- theoretical price movement without an attacker ending with more assets than they paid for
- stale third-party dependency assumptions that cannot be proven against live target state

## Live context JSON

`setup/live_context.json` must be regenerated per target and should contain:

- chain, chain id, latest block, RPC source, capture time
- target token, pool, vault, farm, locker, router, factory, oracle, bridge, and reward contracts
- native and ERC20 balances for every value-bearing contract
- pair reserves, `k`, token0/token1, decimals, fees, total LP supply, protocol-held LP, burned LP, locked LP
- token owner/admin, proxy implementation/admin, minter/burner roles, pausable/blacklist/tax controls
- transfer hooks, custom `_transfer`, `_update`, `transferFrom`, fee, tax, rebase, burn, mint, auto-liquidity, and auto-swap paths
- permit domain, nonce behavior, signature verification, approval scopes, known allowances
- vault/share total assets, total supply, exchange rate, deposit/withdraw/redeem limits
- reward accumulators, emission rate, last update, claim history, staking balances
- oracle feed/source, spot pool dependency, TWAP window, stale threshold, last update
- live transaction/event sample for swaps, mints, burns, syncs, skims, deposits, withdraws, claims, and role changes

If live context does not match the active blueprint target, DeepWiki must reject.

## Workflow order

1. `0_intake_target`: accept chain + token/pool/vault address, normalize explorer and RPC metadata.
2. `0.1_live_context`: collect balances, reserves, LP supply, roles, selectors, proxy slots, events, high-risk views, and protocol-specific liquidity-pool adapter data.
3. `0.2_primitive_match`: match the target against SlowMist-derived exploit primitives.
4. `1_generate_questions`: generate questions from the active blueprint plus primitive matches.
5. `2_deepwiki_triage`: ask DeepWiki for source-level candidate mapping only.
6. `3_exact_proof_gate`: ask the exact live-state extraction question using structured JSON.
7. `4_local_probe`: run fork/unit/invariant probes against the target or decompiled bundle.
8. `5_report_or_reject`: promote only runnable proof-passing findings.

## Implementation sequence

1. Add the reusable blueprint JSON without changing the default.
2. Add a SlowMist primitive bank JSON and an ingestion status file.
3. Extend `live_context_scanner.py` for BSC and pool/token-specific reads.
4. Add a primitive matcher that writes `primitive_matches.json`.
5. Update prompt/tests so DeepWiki sees SlowMist-derived primitive matches.
6. Add local fork-probe scaffolding for reserve/share/reward/permit paths.
7. Only after tests pass, switch `DEFAULT_BLUEPRINT_PATH` or set `BOT_BLUEPRINT_PATH` in workflows.

## Liquidity Pool Coverage

PancakeSwap is only one supported V2-style fork, not the boundary of the machine. The live-context layer should classify liquidity targets by adapter family:

- V2-style pair: Uniswap V2, PancakeSwap, SushiSwap, QuickSwap, Trader Joe V1-style forks, and clone factories.
- V3-style concentrated liquidity: Uniswap V3, PancakeSwap V3, Algebra-style pools, and similar CLMM designs.
- Curve-style stable-swap and multi-asset pools: `coins`, `balances`, virtual price, amplification/asset accounting follow-up.
- Balancer-style vault-managed pools: pool id, vault address, and follow-up Vault `getPoolTokens(poolId)` reads.
- Protocol-specific pools: if no adapter matches, keep generic source/decompiled/live-balance analysis and add a new adapter once the pool interface is known.

The scanner should treat `liquidity_pool.detected_standards` as routing data. It must still prove the exact invariant for the detected protocol family before anything is promoted.

## Next action

The safest first implementation slice is:

```bash
BOT_BLUEPRINT_PATH=blueprints/live_pool_token_bug_bounty.json python3 -m unittest tests/test_deepwiki_upgrade.py
```

Then add tests for the new blueprint fields before touching workflow defaults.
