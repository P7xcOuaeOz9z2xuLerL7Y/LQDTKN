#!/usr/bin/env python3
"""SlowMist-derived exploit primitive loading and target matching."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from bot_blueprint import load_blueprint


DEFAULT_BANK_PATH = Path("intelligence") / "slowmist_pool_token_exploit_primitives.json"
DEFAULT_MATCHES_PATH = Path("setup") / "primitive_matches.json"


class PrimitiveError(ValueError):
    pass


def _read_json(path: str | os.PathLike[str]) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise PrimitiveError(f"{path} must contain a JSON object")
    return data


def load_primitive_bank(path: str | os.PathLike[str] = DEFAULT_BANK_PATH) -> Dict[str, Any]:
    bank = _read_json(path)
    primitives = bank.get("primitives")
    if not isinstance(primitives, list) or not primitives:
        raise PrimitiveError("Primitive bank must contain a non-empty primitives list")

    seen: set[str] = set()
    for primitive in primitives:
        if not isinstance(primitive, dict):
            raise PrimitiveError("Every primitive must be an object")
        primitive_id = primitive.get("id")
        if not isinstance(primitive_id, str) or not primitive_id.strip():
            raise PrimitiveError("Every primitive needs a non-empty id")
        if primitive_id in seen:
            raise PrimitiveError(f"Duplicate primitive id: {primitive_id}")
        seen.add(primitive_id)
        for key in ("title", "bucket", "keywords", "live_context_signals", "code_signals", "local_checks"):
            if key not in primitive:
                raise PrimitiveError(f"Primitive {primitive_id} missing {key}")
    return bank


def primitive_ids(bank: Dict[str, Any]) -> set[str]:
    return {primitive["id"] for primitive in bank.get("primitives", [])}


def _walk_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_values(child)
    elif value is not None:
        yield str(value)


def context_text(*payloads: Any) -> str:
    return "\n".join(_walk_values(payloads)).lower()


def _match_terms(text: str, terms: Iterable[str]) -> List[str]:
    matched: List[str] = []
    for term in terms:
        if not isinstance(term, str) or not term:
            continue
        pattern = re.escape(term.lower())
        if re.search(pattern, text):
            matched.append(term)
    return matched


def _target_identity(live_context: Dict[str, Any]) -> Dict[str, Any]:
    protocol = live_context.get("protocol") if isinstance(live_context.get("protocol"), dict) else {}
    target = live_context.get("target") if isinstance(live_context.get("target"), dict) else {}
    contracts = live_context.get("contracts") if isinstance(live_context.get("contracts"), list) else []
    first_contract = contracts[0] if contracts and isinstance(contracts[0], dict) else {}

    return {
        "protocol": protocol.get("name") or live_context.get("project_name") or "",
        "chain": live_context.get("chain") or target.get("chain") or "",
        "chain_id": live_context.get("chain_id") or target.get("chain_id") or "",
        "address": target.get("address") or first_contract.get("address") or "",
        "label": target.get("label") or first_contract.get("name") or "",
    }


def match_primitives(
    live_context: Dict[str, Any],
    bank: Dict[str, Any],
    blueprint: Dict[str, Any],
    *,
    min_score: int = 2,
) -> Dict[str, Any]:
    text = context_text(live_context)
    blueprint_ids = set(blueprint.get("incident_primitives", []))
    matched: List[Dict[str, Any]] = []
    unmatched: List[Dict[str, Any]] = []

    for primitive in bank["primitives"]:
        primitive_id = primitive["id"]
        if blueprint_ids and primitive_id not in blueprint_ids:
            continue

        keyword_matches = _match_terms(text, primitive.get("keywords", []))
        signal_matches = _match_terms(text, primitive.get("live_context_signals", []))
        code_matches = _match_terms(text, primitive.get("code_signals", []))
        score = len(keyword_matches) + (2 * len(signal_matches)) + len(code_matches)

        row = {
            "id": primitive_id,
            "title": primitive["title"],
            "bucket": primitive["bucket"],
            "score": score,
            "matched_keywords": keyword_matches,
            "matched_live_context_signals": signal_matches,
            "matched_code_signals": code_matches,
            "local_checks": primitive.get("local_checks", []),
            "reject_if_missing": primitive.get("reject_if_missing", []),
        }
        if score >= min_score:
            matched.append(row)
        else:
            unmatched.append({"id": primitive_id, "title": primitive["title"], "score": score})

    matched.sort(key=lambda item: (-item["score"], item["id"]))
    unmatched.sort(key=lambda item: (-item["score"], item["id"]))

    return {
        "schema_version": "primitive-matches-v1",
        "source_bank": bank.get("source_url", ""),
        "bank_captured_at": bank.get("captured_at", ""),
        "blueprint_project": blueprint.get("project_name", ""),
        "blueprint_source_repo": blueprint.get("source_repo", ""),
        "target_identity": _target_identity(live_context),
        "match_threshold": min_score,
        "matched_primitives": matched,
        "unmatched_primitives": unmatched,
        "completion": {
            "has_live_context": bool(live_context),
            "has_matches": bool(matched),
            "requires_local_proof": True,
            "note": "Primitive matches are audit routing hints only; they are not vulnerability proof.",
        },
    }


def write_matches(matches: Dict[str, Any], path: str | os.PathLike[str]) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(matches, indent=2) + "\n", encoding="utf-8")
    return out


def build_matches(
    live_context_path: str | os.PathLike[str],
    *,
    bank_path: str | os.PathLike[str] = DEFAULT_BANK_PATH,
    blueprint_path: str | os.PathLike[str] | None = None,
    min_score: int = 2,
) -> Dict[str, Any]:
    live_context = _read_json(live_context_path)
    bank = load_primitive_bank(bank_path)
    blueprint = load_blueprint(blueprint_path)
    return match_primitives(live_context, bank, blueprint, min_score=min_score)


def main() -> int:
    parser = argparse.ArgumentParser(description="Match a live target context against SlowMist-derived exploit primitives.")
    parser.add_argument("--live-context", default=os.environ.get("LIVE_CONTEXT_PATH", "setup/live_context.json"))
    parser.add_argument("--bank", default=str(DEFAULT_BANK_PATH))
    parser.add_argument("--blueprint", default=os.environ.get("BOT_BLUEPRINT_PATH", ""))
    parser.add_argument("--out", default=str(DEFAULT_MATCHES_PATH))
    parser.add_argument("--min-score", type=int, default=2)
    args = parser.parse_args()

    matches = build_matches(
        args.live_context,
        bank_path=args.bank,
        blueprint_path=args.blueprint or None,
        min_score=args.min_score,
    )
    out = write_matches(matches, args.out)
    print(f"Wrote {len(matches['matched_primitives'])} primitive match(es) to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
