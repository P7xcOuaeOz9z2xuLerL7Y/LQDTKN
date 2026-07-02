import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List


DEFAULT_BLUEPRINT_PATH = Path(__file__).resolve().parent / "blueprints" / "sable_fund_reward.json"


class BlueprintError(ValueError):
    pass


def _require_list(data: Dict[str, Any], key: str) -> List[str]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise BlueprintError(f"Blueprint key '{key}' must be a non-empty list of strings")
    return value


def _require_string(data: Dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise BlueprintError(f"Blueprint key '{key}' must be a non-empty string")
    return value


def load_blueprint(path: str | os.PathLike[str] | None = None) -> Dict[str, Any]:
    blueprint_path = Path(path or os.environ.get("BOT_BLUEPRINT_PATH", DEFAULT_BLUEPRINT_PATH))
    with blueprint_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    required_strings = [
        "source_repo",
        "repo_name",
        "project_name",
        "target_label",
        "paid_impact_focus",
        "live_context_hint",
        "protocol_focus",
        "attacker_profile",
    ]
    for key in required_strings:
        _require_string(data, key)

    for key in [
        "scope_files",
        "target_scopes",
        "context_interfaces",
        "core_invariants",
        "high_value_surfaces",
        "impact_mapping",
        "known_rejection_memory",
    ]:
        _require_list(data, key)

    max_repo = data.get("max_repo", 10)
    if not isinstance(max_repo, int) or max_repo <= 0:
        raise BlueprintError("Blueprint key 'max_repo' must be a positive integer")

    data["_path"] = str(blueprint_path)
    return data


def bullets(items: Iterable[str], indent: str = "- ") -> str:
    return "\n".join(f"{indent}{item}" for item in items)


def numbered(items: Iterable[str], start: int = 1) -> str:
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items, start=start))
