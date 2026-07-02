import json
import os

from bot_blueprint import bullets, load_blueprint, numbered
from proof_gate_schema import proof_gate_contract_json
from scanned_report_schema import scanned_report_contract_json


BLUEPRINT = load_blueprint()
MAX_REPO = BLUEPRINT["max_repo"]
SOURCE_REPO = BLUEPRINT["source_repo"]
REPO_NAME = BLUEPRINT["repo_name"]
run_number = os.environ.get("GITHUB_RUN_NUMBER", "0")


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index."""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    valid_urls = []
    for url in data:
        if not isinstance(url, str) or not url.strip():
            continue
        repo_slug = url.rstrip("/").split("/")[-1].lower()
        expected_slug = REPO_NAME.lower()
        if repo_slug == expected_slug or repo_slug.startswith(f"{expected_slug}--"):
            valid_urls.append(url)
    return valid_urls


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"


scope_files = BLUEPRINT["scope_files"]
target_scopes = BLUEPRINT["target_scopes"]
scope_scan = []


def _blueprint_memory() -> str:
    interfaces = bullets(BLUEPRINT["context_interfaces"])
    invariants = bullets(BLUEPRINT["core_invariants"], indent="* ")
    surfaces = bullets(BLUEPRINT["high_value_surfaces"], indent="* ")
    impact_mapping = bullets(BLUEPRINT["impact_mapping"], indent="* ")
    rejection_memory = bullets(BLUEPRINT["known_rejection_memory"], indent="- ")

    return f"""## DeepWiki Memory Blueprint
Project: {BLUEPRINT["project_name"]}
Repository: {SOURCE_REPO}
Blueprint source: {BLUEPRINT["_path"]}
Paid impact focus: {BLUEPRINT["paid_impact_focus"]}

Protocol focus:
{BLUEPRINT["protocol_focus"]}

Live context hint:
Use live_context.json values if available: {BLUEPRINT["live_context_hint"]}.

Context-only interface files:
{interfaces}

Use interface files only to understand ABI, selectors, structs, events, return values, and cross-contract expectations. Do not treat them as vulnerability target scope files. Only prove bugs through deployed concrete contracts that hold, move, mint, burn, account for, or distribute funds/rewards.

Core invariants:
{invariants}

High-value attack surfaces:
{surfaces}

Impact mapping:
{impact_mapping}

Known rejection memory:
{rejection_memory}
"""


def _deepwiki_limitation_gate() -> str:
    return """## DeepWiki Automation Boundary
DeepWiki can reason over indexed code and citations, but it cannot run Foundry/unit/fuzz tests during this automation pass.
Therefore, do not call any finding locally validated, confirmed, proven, or submission-ready.
Only output one of these verdicts:
- REJECT: fails scope, impact, reachability, expected-behavior, duplicate, or assumption gates.
- NEEDS_LOCAL_PROOF: plausible but cannot be promoted until local code review and a runnable test confirm it.
- HIGH_CONFIDENCE_CANDIDATE: strong source-level candidate with exact local proof plan, still not final until local test passes.
"""


def _live_context_snapshot(max_chars: int = 30000) -> str:
    live_context_path = os.environ.get("LIVE_CONTEXT_PATH", "setup/live_context.json")
    if not os.path.exists(live_context_path):
        return f"""## Live Context Snapshot
No live context file was found at `{live_context_path}`.
For non-REJECT output, list the exact live commands needed and mark missing preconditions.
"""

    try:
        with open(live_context_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except OSError as exc:
        return f"""## Live Context Snapshot
Could not read `{live_context_path}`: {exc}
For non-REJECT output, list the exact live commands needed and mark missing preconditions.
"""

    if len(content) > max_chars:
        content = content[:max_chars] + "\n...TRUNCATED..."

    return f"""## Live Context Snapshot
Source: {live_context_path}

```json
{content}
```
"""


def _active_target_snapshot(max_chars: int = 12000) -> str:
    active_target_path = os.environ.get("ACTIVE_TARGET_PATH", "setup/active_target.json")
    if not os.path.exists(active_target_path):
        return f"""## Active Target Snapshot
No active target file was found at `{active_target_path}`.
For non-REJECT output, identify the exact target address and chain from the scanner input and mark missing target registry as a proof precondition.
"""

    try:
        with open(active_target_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except OSError as exc:
        return f"""## Active Target Snapshot
Could not read `{active_target_path}`: {exc}
For non-REJECT output, identify the exact target address and chain from the scanner input and mark missing target registry as a proof precondition.
"""

    if len(content) > max_chars:
        content = content[:max_chars] + "\n...TRUNCATED..."

    return f"""## Active Target Snapshot
Source: {active_target_path}

```json
{content}
```
"""


def _primitive_matches_snapshot(max_chars: int = 20000) -> str:
    primitive_matches_path = os.environ.get("PRIMITIVE_MATCHES_PATH", "setup/primitive_matches.json")
    if not os.path.exists(primitive_matches_path):
        return f"""## SlowMist Primitive Match Snapshot
No primitive match file was found at `{primitive_matches_path}`.
Generate one after live context collection with:
`python3 run_match_exploit_primitives.py --live-context setup/live_context.json --out setup/primitive_matches.json`

DeepWiki may still use the blueprint incident primitives, but every non-REJECT output must list the missing primitive-match command as a required setup step.
"""

    try:
        with open(primitive_matches_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except OSError as exc:
        return f"""## SlowMist Primitive Match Snapshot
Could not read `{primitive_matches_path}`: {exc}
Every non-REJECT output must list this as a missing precondition.
"""

    if len(content) > max_chars:
        content = content[:max_chars] + "\n...TRUNCATED..."

    return f"""## SlowMist Primitive Match Snapshot
Source: {primitive_matches_path}

```json
{content}
```

Use these matches as routing hints only. They do not prove a vulnerability. A non-REJECT verdict still requires exact current code, exact live state, attacker triggerability, and local proof.
"""


def question_generator(target_file: str) -> str:
    """
    Generate DeepWiki-compatible audit/fuzzing questions for one target.

    target_file format:
    "'File Name: src/ActivePool.sol -> Scope: Critical Fund extraction or protocol value drain'"
    """

    prompt = f"""
```
Generate {BLUEPRINT["paid_impact_focus"]} security audit/fuzzing questions for this exact {BLUEPRINT["target_label"]} target:

{target_file}

{_blueprint_memory()}

{_primitive_matches_snapshot()}

Rules:
* Treat `File Name:` as the exact file/module.
* Treat `Scope:` as the ONLY paid impact to target.
* Assume full repo context is accessible.
* Do not ask for code or say anything is missing.
* Use exact Solidity symbols when possible.
* Attacker is unprivileged: {BLUEPRINT["attacker_profile"]}.
* Do not rely on admin compromise, malicious governance, leaked keys, impossible oracle values, pure external oracle failure, user mistakes, or unsupported third-party behavior.
* Reject DoS/freeze/liveness/griefing questions unless the same path gives the attacker direct fund or reward extraction.
* Generate 35 to 60 high-signal questions.
* At least 70% must be multi-step flow, invariant, fuzz, accounting, state-transition, or cross-module questions.
* Every question must be testable later by local PoC, unit test, fuzz test, invariant test, or differential test.
* Avoid generic checklist questions and repeated root causes.

Each question must include:
{numbered([
    "target function/module",
    "attacker action",
    "preconditions",
    "call sequence",
    "invariant tested",
    "scoped impact",
    "local proof idea"
])}

Output only valid Python. No markdown. No explanations.

questions = [
    "[File: {target_file}] [Function: symbol_or_module] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Local proof idea: add/run TEST_TYPE with PARAMETERS and assert EXPECTED_PROPERTY.",
]
```
"""
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a DeepWiki-compatible candidate triage prompt.
    """

    prompt = f"""# DEEPWIKI CANDIDATE TRIAGE PROMPT

## Question
{security_question}

{_blueprint_memory()}

{_primitive_matches_snapshot()}

{_deepwiki_limitation_gate()}

## Rules
- The referenced {REPO_NAME} file/path exists in the DeepWiki target. Do not say files are missing.
- Analyze only this question and only the scoped paid impact.
- Attacker is unprivileged: {BLUEPRINT["attacker_profile"]}.
- Ignore admin-only, governance-only, leaked-key, docs, style, gas-only, and best-practice issues.
- Privileged functions matter only if they create a later user-triggered exploit path.
- Do not rely on impossible oracle values, pure oracle failure, malicious token owner action, user mistake, or unsupported external dependency behavior.
- Reject DoS, griefing, liveness, temporary freeze, liquidation blockage, and generic severity claims unless the same reachable path lets the attacker extract funds/rewards or increase attacker-controlled value.
- Prefer REJECT over speculative reports.

## Required Source-Level Checks
All non-REJECT outputs must include:
1. Exact file/function/symbol references.
2. Clear root cause and broken accounting/security assumption.
3. Reachable exploit path: preconditions -> attacker call/data -> trigger -> bad state/result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete paid-scope impact with realistic likelihood.
6. No obvious rejection reason from SECURITY, RESEARCHER, README, NatSpec, prior reports, known issues, expected behavior, privileges, or scope exclusions.
7. A precise local proof plan with the test type, setup, call sequence, and expected assertion.

## Rejection Questions
Before output, internally answer:
- Can a normal external user trigger this?
- Does the code actually behave as claimed?
- Is the impact caused by this protocol, not by an external dependency alone?
- Is the fund/reward extraction concrete, not hypothetical?
- Is this expected protocol behavior or public market competition?
- Is this stale input/retry behavior without permanent fund/reward loss?
- Is this already documented or previously reported?
- What exact local test would prove or disprove it?

## Output
If rejected, output exactly:

## Verdict
REJECT

## Rejection Reason
[one concise reason]

If plausible, output exactly:

## Verdict
NEEDS_LOCAL_PROOF

## Paid Scope Match
[fund_extraction | reward_extraction | protocol_value_drain | none]

## Exact Code Path
file:
function:
symbols/lines:

## Attacker Path
preconditions:
attacker-controlled inputs:
call sequence:

## Why Existing Checks Fail
[source-level reasoning]

## Rejection Checks
expected behavior checked:
prior report checked:
README/NatSpec checked:
unsupported assumption checked:

## Local Proof Required
test type:
test file to add:
test setup:
expected assertion:
failure condition:

If source-level evidence is unusually strong, use HIGH_CONFIDENCE_CANDIDATE as the verdict, but still include Local Proof Required and do not call it confirmed.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for model-written claims.
    """
    prompt = f"""# DEEPWIKI CLAIM VALIDATION PROMPT

## Security Claim
{report}

{_blueprint_memory()}

{_primitive_matches_snapshot()}

{_deepwiki_limitation_gate()}

## Rules
- Validate only the submitted claim.
- Check SECURITY/RESEARCHER/README/NatSpec if available for scope, exclusions, expected behavior, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves a larger paid-scope impact.
- Reject admin-only, owner-only, trusted-operator, leaked-key, best-practice, docs/style, gas-only, and purely theoretical issues.
- Reject if the exploit requires unrealistic assumptions, victim mistakes, missing external context, or unsupported protocol behavior.
- A valid candidate must be triggerable by an unprivileged user, unless the claim proves privilege escalation from a user path.
- The final impact must match fund extraction, protocol value drain, reward extraction, or unfair reward access, not just a generic code bug.
- Reject DoS, freeze, liveness, griefing, liquidation blockage, or accounting-desync-only claims unless they directly let the attacker extract funds/rewards.
- Prefer REJECT over speculative candidates.

## Required Validation Checks
All non-REJECT outputs must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken security/accounting assumption.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete in-scope paid impact with realistic likelihood.
6. Reproducible local proof path: unit PoC, fork test, invariant/fuzz test, or exact manual steps.
7. No obvious rejection reason from SECURITY, known issues, privileges, prior reports, expected behavior, or scope exclusions.

## Output
If rejected, output exactly:

## Verdict
REJECT

## Rejection Reason
[one concise reason]

If plausible, output exactly:

## Verdict
NEEDS_LOCAL_PROOF

## Paid Scope Match
[fund_extraction | reward_extraction | protocol_value_drain | none]

## Exact Code Path
file:
function:
symbols/lines:

## Attacker Path
preconditions:
attacker-controlled inputs:
call sequence:

## Why Existing Checks Fail
[source-level reasoning]

## Rejection Checks
expected behavior checked:
prior report checked:
README/NatSpec checked:
unsupported assumption checked:

## Local Proof Required
test type:
test file to add:
test setup:
expected assertion:
failure condition:

If source-level evidence is unusually strong, use HIGH_CONFIDENCE_CANDIDATE as the verdict, but still include Local Proof Required and do not call it confirmed.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a cross-project analog scan prompt.
    """
    scanned_contract = scanned_report_contract_json()
    prompt = f"""# DEEPWIKI ANALOG SCAN PROMPT

## External Report
{report}

{_blueprint_memory()}

{_active_target_snapshot()}

{_live_context_snapshot()}

{_primitive_matches_snapshot()}

{_deepwiki_limitation_gate()}

## Access Rules
- Treat in-scope files as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.

## Objective
Find whether the same vulnerability class can occur in in-scope code as fund extraction, protocol value drain, reward extraction, or unfair reward access.
Use the external report as a hint, not as proof.
Return only a strict JSON object that follows the contract below.

## Scanned Report JSON Contract
{scanned_contract}

## Live On-Chain Context Rules
- Treat the inline Active Target Snapshot and Live Context Snapshot in this prompt as the source of truth for this run.
- Do not use older DeepWiki-indexed `setup/live_context.json`, `setup/active_target.json`, repository memory, or previous protocol names if they conflict with the inline snapshots above.
- If the inline live context target address, chain, protocol label, contracts, or related token expansion conflicts with the inline active target, set `target_protocol_gate.context_matches_blueprint=false`, set `rejection_gates.not_stale_live_context=false`, and return `verdict="REJECT"` with `rejection_reason="inline live context does not match active target"`.
- If inline live context is missing, do not invent balances, addresses, structs, mappings, events, or state. Put `live_context_source="none"` and list the exact commands needed to gather them.
- Prefer observed on-chain state over generic assumptions: balances, token decimals, pool liabilities, trove state, reward accumulators, staking totals, oracle configuration, proxy implementation/admin, mappings, structs, recent events, and dependency addresses.
- Every non-REJECT output must include the exact command(s) or JSON source field(s) used for each material live precondition.
- Do not promote a candidate when the exploit only works under a hypothetical state that is not present or not reachable from the observed live protocol state.

## Useful Live Context Commands
- `python3 live_context_scanner.py --from-questions --protocol "{BLUEPRINT["project_name"]}" --out setup/live_context.json`
- `python3 live_context_scanner.py --scope-file scope_urls.json --protocol "{BLUEPRINT["project_name"]}" --out setup/live_context.json`
- `cast chain-id --rpc-url "$RPC_URL"`
- `cast block latest --rpc-url "$RPC_URL"`
- `cast balance <contract_address> --rpc-url "$RPC_URL"`
- `cast call <contract_address> "functionName()(returnType)" --rpc-url "$RPC_URL"`
- `cast storage <contract_address> <slot> --rpc-url "$RPC_URL"`
- `cast logs --address <contract_address> --from-block <start> --to-block latest --rpc-url "$RPC_URL"`

## Scanner Intelligence Rules
- First extract the external report's root primitive: authorization bypass, accounting drift, state-transition ordering, reward accumulator error, oracle/price manipulation, rounding/precision, replay/nonce, reentrancy/callback, token transfer semantics, or invariant mismatch.
- Then search for the same primitive across both paid bug families:
  1. fund extraction / protocol value drain;
  2. reward extraction / unfair reward access.
- Consider adjacent scenarios, not only exact copies: same primitive in a different function, same accounting invariant in a different pool, same reward timing issue in a different accumulator, same transfer/order bug in a different asset path.
- Do not stop after the first weak mapping. If the first mapping is rejected, try the next closest paid-impact mapping before returning REJECT.
- Still reject anything that cannot produce concrete attacker-controlled fund/reward gain under supported protocol assumptions.

## Method
1. Classify vuln type only if it can cause fund extraction or reward extraction.
2. Map to this current protocol with the external report to find a valid paid-scope candidate.
3. Prove source-level root cause with exact file/function/symbol references.
4. Bind the candidate to existing live on-chain state and protocol preconditions.
5. Confirm concrete fund/reward extraction impact plus realistic likelihood.
6. Define the exact local test needed to prove or disprove it.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Trusted-role compromise required.
- Theoretical-only issue with no fund/reward extraction impact.
- DoS, freeze, liveness, griefing, or liquidation blockage without attacker value extraction.
- Impact or likelihood missing.
- Expected behavior, duplicate, unsupported assumption, or prior-report overlap.
- The live context is stale, for a different protocol, or insufficient for a required precondition.

## Output
Output only valid JSON. No markdown. No prose before or after the JSON.
Use `verdict="REJECT"` unless every `rejection_gates` field can truthfully be set to true.
"""
    return prompt


def proof_gate_format(report: str) -> str:
    """
    Generate the final DeepWiki proof-gate prompt for staged candidates.
    """
    proof_contract = proof_gate_contract_json()
    prompt = f"""# DEEPWIKI EXACT PROOF GATE

## Candidate Report
{report}

{_blueprint_memory()}

{_live_context_snapshot()}

{_primitive_matches_snapshot()}

{_deepwiki_limitation_gate()}

## One Question
Does this exact current protocol, with current live state, allow an unprivileged attacker to extract funds or rewards beyond entitlement?

Answer only that question.

## Proof-Gate JSON Contract
{proof_contract}

## Rules
- Use the active blueprint as the current protocol identity.
- Use live context only if it matches the active blueprint/project/source repo.
- If live context belongs to another protocol, return `verdict="REJECT"` and set `active_protocol.context_matches_blueprint=false`.
- If a required live value is missing, do not invent it. Put the command needed in `live_preconditions[].command_if_missing`.
- A non-REJECT verdict requires concrete attacker value gain in one of the paid categories only.
- Reject mere High severity, DoS, freeze, liveness, griefing, liquidation blockage, accounting noise, or theoretical paths unless the same path transfers excess funds/rewards to the attacker.
- Reject if the attack depends on admin/governance compromise, leaked keys, unsupported external dependency behavior, impossible oracle values, or user mistakes.
- Reject if the source code path, attacker path, and live preconditions cannot all be stated precisely.
- Prefer `NEEDS_LOCAL_PROOF` over `HIGH_CONFIDENCE_CANDIDATE` unless the source-level evidence is unusually strong.
- Never call the candidate confirmed, validated, proven, or submission-ready.

## Required Reasoning
Before output, check:
1. Which exact current protocol file/function is involved?
2. Which live balance/state/struct/mapping/reward/accounting value makes the exploit reachable now?
3. Who is the unprivileged attacker?
4. What input or call sequence does the attacker control?
5. What asset or reward does the attacker get?
6. Why is that value beyond entitlement?
7. Which guard/check should stop it and why does it fail?
8. What local unit/fork/invariant/fuzz test would prove or reject it?

## Output
Output only valid JSON. No markdown. No prose before or after the JSON.
Use `verdict="REJECT"` unless every required hard gate can truthfully be set to true.
"""
    return prompt
