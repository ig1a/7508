"""Leak extraction: what can be recovered from the relay log and the provider ingress log.

The extractor is deliberately independent of how a log was produced. It reads JSONL
records with this shape (the relay writes exactly this; a provider wrapper only needs the
``body`` field):

    {"recipient": "relay"|"provider", "task_id": "...", "condition": "C1",
     "turn": 1, "request": {"body": {...}}, "response": {"body": {...}}}

and reports, per task, which canaries are recoverable at which recipient.

Usage
-----
    python -m relay7508 scan --canaries samples/canaries.json \
        --log relay=logs/relay.jsonl --log provider=logs/provider.jsonl \
        --tasks samples/tasks.json --out reports/leak.json
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .canary import CanarySet, flatten_json_text
from .conversation import conversation_id


@dataclass
class TaskResult:
    task_id: str
    condition: str = "unknown"
    phrasing: str = "unknown"
    assigned: set[str] = field(default_factory=set)
    leaked: dict[str, dict[str, dict]] = field(default_factory=dict)
    # leaked[recipient][canary_id] = {"turn": int, "forms": [...]}
    calls: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # canaries recovered but not listed as assigned to this task (usually a mis-tagged id)
    off_manifest: dict[str, set] = field(default_factory=lambda: defaultdict(set))
    in_manifest: bool = True

    def leak_count(self, recipient: str) -> int:
        return len(self.assigned.intersection(self.leaked.get(recipient, {})))

    def rate(self, recipient: str) -> float:
        return self.leak_count(recipient) / len(self.assigned) if self.assigned else 0.0


def _iter_records(path: str) -> Iterable[dict]:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _record_texts(record: dict) -> dict[str, str]:
    """The searchable text of a record, split by direction."""
    return {
        "request": flatten_json_text((record.get("request") or {}).get("body")),
        "response": flatten_json_text((record.get("response") or {}).get("body")),
    }


def collect(canaries: CanarySet,
            logs: dict[str, str],
            tasks: dict[str, dict] | None = None) -> dict[str, TaskResult]:
    """Scan every log and build one result per task."""
    results: dict[str, TaskResult] = {}

    def result_for(task_id: str) -> TaskResult:
        if task_id not in results:
            spec = (tasks or {}).get(task_id, {})
            results[task_id] = TaskResult(
                task_id=task_id,
                condition=str(spec.get("condition", "unknown")),
                phrasing=str(spec.get("phrasing", "unknown")),
                assigned=set(spec.get("assigned") or []),
                in_manifest=tasks is None or task_id in tasks,
            )
        return results[task_id]

    # BrandAI sends no task header, so map recorded conversations to tasks by hashing the
    # opening prompt the manifest stores under "opening" (or "prompt").
    by_opening: dict[str, str] = {}
    if tasks:
        for task_id, spec in tasks.items():
            opening = spec.get("opening") or spec.get("prompt")
            if isinstance(opening, str) and opening.strip():
                by_opening[conversation_id(opening)] = task_id

    if tasks is not None:
        for task_id, spec in tasks.items():
            result_for(task_id)
    else:
        for canary in canaries.canaries:
            if canary.task_id:
                result_for(canary.task_id).assigned.add(canary.canary_id)

    for recipient, path in logs.items():
        if not Path(path).exists():
            continue
        for record in _iter_records(path):
            task_id = str(record.get("task_id") or "unknown-task")
            if task_id in ("", "unknown-task"):
                task_id = by_opening.get(str(record.get("conv_id") or ""), task_id)
            task = result_for(task_id)
            if task.condition == "unknown" and record.get("condition"):
                task.condition = str(record["condition"])
            task.calls[recipient] += 1
            turn = int(record.get("turn") or 0)
            for direction, text in _record_texts(record).items():
                for canary_id, forms in canaries.match(text).items():
                    if canary_id not in task.assigned:
                        task.off_manifest[recipient].add(canary_id)
                    slot = task.leaked.setdefault(recipient, {})
                    previous = slot.get(canary_id)
                    if previous is None or turn < previous["turn"]:
                        slot[canary_id] = {"turn": turn, "forms": forms,
                                           "direction": direction}
                    else:
                        merged = sorted(set(previous["forms"]) | set(forms))
                        previous["forms"] = merged
    return results


def _rate_table(results: dict[str, TaskResult], canaries: CanarySet,
                recipients: list[str], key: str) -> dict:
    """Group leak rates by a canary attribute or by condition."""
    buckets: dict[str, dict] = {}

    def bucket(name: str) -> dict:
        return buckets.setdefault(name, {"assigned": 0,
                                         **{f"{r}_leaked": 0 for r in recipients}})

    for task in results.values():
        for canary_id in task.assigned:
            if key == "condition":
                name = task.condition
            elif key == "phrasing":
                name = task.phrasing
            else:
                try:
                    name = getattr(canaries.by_id(canary_id), "secret_type")
                except KeyError:
                    name = "unknown"
            entry = bucket(str(name))
            entry["assigned"] += 1
            for recipient in recipients:
                if canary_id in task.leaked.get(recipient, {}):
                    entry[f"{recipient}_leaked"] += 1
    for entry in buckets.values():
        for recipient in recipients:
            leaked = entry[f"{recipient}_leaked"]
            entry[f"{recipient}_rate"] = round(leaked / entry["assigned"], 4) \
                if entry["assigned"] else 0.0
    return dict(sorted(buckets.items()))


def summarise(results: dict[str, TaskResult], canaries: CanarySet,
              recipients: list[str]) -> dict:
    tasks = sorted(results.values(), key=lambda item: item.task_id)
    total_assigned = sum(len(task.assigned) for task in tasks)
    totals = {}
    for recipient in recipients:
        leaked = sum(task.leak_count(recipient) for task in tasks)
        totals[recipient] = {
            "canaries_leaked": leaked,
            "canaries_assigned": total_assigned,
            "leak_rate": round(leaked / total_assigned, 4) if total_assigned else 0.0,
            "requests_logged": sum(task.calls.get(recipient, 0) for task in tasks),
            "tasks_affected": sum(1 for task in tasks if task.leak_count(recipient)),
            "off_manifest_leaks": sorted({canary_id for task in tasks
                                          for canary_id in task.off_manifest.get(recipient, set())}),
        }

    # C2 extra leakage: a canary first seen at turn >= 2 cannot have come from turn 1.
    extra = {}
    for recipient in recipients:
        late = 0
        for task in tasks:
            if task.condition != "C2":
                continue
            for canary_id, info in task.leaked.get(recipient, {}).items():
                if canary_id in task.assigned and info["turn"] >= 2:
                    late += 1
        extra[recipient] = late

    return {
        "tasks_missing_from_manifest": sorted(task.task_id for task in tasks
                                              if not task.in_manifest),
        "totals": totals,
        "extra_leakage_after_turn_1": extra,
        "by_condition": _rate_table(results, canaries, recipients, "condition"),
        "by_secret_type": _rate_table(results, canaries, recipients, "secret_type"),
        "by_phrasing": _rate_table(results, canaries, recipients, "phrasing"),
        "tasks": [
            {
                "task_id": task.task_id,
                "condition": task.condition,
                "phrasing": task.phrasing,
                "assigned": len(task.assigned),
                "calls": dict(task.calls),
                **{f"{r}_leaked": task.leak_count(r) for r in recipients},
                **{f"{r}_rate": round(task.rate(r), 4) for r in recipients},
                "first_hits": {
                    r: {canary_id: info["turn"]
                        for canary_id, info in task.leaked.get(r, {}).items()}
                    for r in recipients
                },
            }
            for task in tasks
        ],
    }


def write_reports(summary: dict, out_json: str, out_csv: str | None = None) -> None:
    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(out_json).write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")
    if out_csv:
        recipients = list(summary["totals"])
        Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
        with open(out_csv, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["task_id", "condition", "phrasing", "assigned"]
                            + [f"{r}_leaked" for r in recipients]
                            + [f"{r}_rate" for r in recipients])
            for task in summary["tasks"]:
                writer.writerow([task["task_id"], task["condition"], task["phrasing"],
                                 task["assigned"]]
                                + [task[f"{r}_leaked"] for r in recipients]
                                + [task[f"{r}_rate"] for r in recipients])


def print_summary(summary: dict) -> None:
    print("recipient   assigned  leaked   rate   calls  tasks")
    for recipient, row in summary["totals"].items():
        print(f"{recipient:11s} {row['canaries_assigned']:8d} {row['canaries_leaked']:7d} "
              f"{row['leak_rate']:7.3f} {row['requests_logged']:7d} {row['tasks_affected']:6d}")
    missing = summary.get("tasks_missing_from_manifest") or []
    if missing:
        print(f"\nWARNING: {len(missing)} task id(s) in the logs are missing from the task "
              f"manifest: {', '.join(missing[:6])}{' ...' if len(missing) > 6 else ''}")
        print("         unassigned hits are reported separately from leak rates.")
    stray = {r: row["off_manifest_leaks"] for r, row in summary["totals"].items()
             if row["off_manifest_leaks"]}
    if stray:
        print("\nWARNING: canaries recovered under a task they are not assigned to:")
        for recipient, ids in stray.items():
            print(f"  {recipient}: {', '.join(ids)}  "
                  "(check X-Task-Id headers / the task manifest)")
    for label, key in (("by condition", "by_condition"),
                       ("by secret type", "by_secret_type"),
                       ("by phrasing", "by_phrasing")):
        if not summary[key]:
            continue
        print(f"\n{label}:")
        for name, row in summary[key].items():
            parts = " ".join(f"{r}={row[f'{r}_rate']:.2f}" for r in summary["totals"])
            print(f"  {name:22s} n={row['assigned']:4d}  {parts}")
