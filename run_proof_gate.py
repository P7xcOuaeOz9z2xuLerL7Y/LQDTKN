import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_validation import Validator
from bot_runtime import batch_limit


def load_processed_reports():
    if not os.path.exists("proof_gate_processed.json"):
        return set()

    try:
        with open("proof_gate_processed.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            return {item.get("filename", "") for item in data if "filename" in item}
    except Exception as e:
        print(f"Error loading proof gate processed list: {e}")
        return set()


def save_processed_reports(processed_files):
    data = [{"filename": filename} for filename in sorted(processed_files)]
    with open("proof_gate_processed.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_candidate_reports():
    pending_dir = Path(os.environ.get("PROOF_GATE_PENDING_DIR", "proof_gate_pending"))
    return sorted(list(pending_dir.glob("*.md")) + list(pending_dir.glob("*.json")))


def main():
    candidate_files = get_candidate_reports()
    total = len(candidate_files)
    processed_files = load_processed_reports()

    print(f"Found {total} proof-gate candidate files")
    print(f"Already processed: {len(processed_files)}")

    processed_count = 0
    skipped_count = 0
    max_reports = batch_limit(25)

    for i, candidate_file in enumerate(candidate_files, 1):
        if candidate_file.name in processed_files:
            print(f"[{i}/{total}] Skipping already processed: {candidate_file.name}")
            skipped_count += 1
            continue

        print(f"\n[{i}/{total}] Proof-gating: {candidate_file.name}")

        try:
            content = candidate_file.read_text(encoding="utf-8")
            bot = Validator(teardown=True)
            bot.ask_proof_gate(candidate_file.name, content)
            processed_files.add(candidate_file.name)
            processed_count += 1

            if processed_count >= max_reports:
                break
        except Exception as e:
            print(f"Error processing {candidate_file.name}: {e}")
            continue

    save_processed_reports(processed_files)

    print("\n=== Proof Gate Summary ===")
    print(f"Total files: {total}")
    print(f"Processed: {processed_count}")
    print(f"Skipped: {skipped_count}")


if __name__ == "__main__":
    main()
