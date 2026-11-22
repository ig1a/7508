"""Local M1 content-detection diagnostic. No Ollama calls, no canary registry access.

Outputs aggregate results only; the benchmark intentionally does not read
`data/generated/canaries.jsonl` or write original inputs/secrets.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from model_backend import build_payload
from security_gateway.detection import HybridPayloadScanner

ROOT = Path(__file__).resolve().parents[1]


def run_benchmark(tasks_file: Path) -> dict:
    tasks = [json.loads(line) for line in tasks_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    scanner = HybridPayloadScanner()
    by_label: dict[str, Counter] = defaultdict(Counter)
    by_asset: dict[str, Counter] = defaultdict(Counter)
    by_presentation: dict[str, Counter] = defaultdict(Counter)
    errors: Counter = Counter()
    for task in tasks:
        texts = [{"role": "user", "content": turn["content"]} for turn in task["turns"]]
        result = scanner.scan(build_payload(texts))
        label = task["label"]
        for counter in (by_label[label], by_asset[task["asset"]], by_presentation[task["presentation"]]):
            counter["total"] += 1
            counter["flagged"] += bool(result.has_sensitive_data)
            counter["incomplete"] += not result.inspection_complete
        if not result.inspection_complete:
            errors[result.error_code or "UNKNOWN"] += 1
    return {
        "evaluation": "offline_payload_detection_no_model_calls",
        "tasks": len(tasks),
        "by_label": {key: dict(values) for key, values in sorted(by_label.items())},
        "by_asset": {key: dict(values) for key, values in sorted(by_asset.items())},
        "by_presentation": {key: dict(values) for key, values in sorted(by_presentation.items())},
        "incomplete_errors": dict(errors),
        "notes": [
            "flagged means M1 found a sensitive indicator, not proof of real-world confidentiality",
            "No canaries or task text are written to this file",
            "Provider receipt and live routing must be validated separately",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tasks", type=Path, default=ROOT / "data/generated/tasks.jsonl")
    parser.add_argument("--out", type=Path, default=ROOT / "reports/evaluation/M1_offline_validation.json")
    args = parser.parse_args()
    result = run_benchmark(args.tasks)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("Saved aggregate results:", args.out)


if __name__ == "__main__":
    main()
