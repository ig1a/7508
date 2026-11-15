"""Replay task-set trials against the BrandAI assistant and write one JSON line per trial.

Usage:
  python -m runner.run --config C0                          # all 120 tasks once (the pilot)
  python -m runner.run --config C0 --tasks "C-cred-*" --limit 5
  python -m runner.run --summary reports/runs/<file>.jsonl  # re-print a summary

The assistant (and for C1/C2 the relay, gate and external model) must already be running and set
up to match --config; the runner only records which configuration was requested.
Output goes to reports/runs/ (git-ignored) because answers contain the synthetic secrets.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import random
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "data" / "generated" / "tasks.jsonl"
INJECTIONS = ROOT / "data" / "attacks" / "injections.jsonl"
OUT_DIR = ROOT / "reports" / "runs"
MAIN_MATRIX_TRIALS = 4200

CONFIGS = {
    "C0": {"route_mode": "internal_only", "relay": None, "gate": None},
    "C1-none": {"route_mode": "external_candidate", "relay": "passive", "gate": "none"},
    "C1-M1": {"route_mode": "external_candidate", "relay": "passive", "gate": "M1"},
    "C1-M2": {"route_mode": "external_candidate", "relay": "passive", "gate": "M2"},
    "C2-none": {"route_mode": "external_candidate", "relay": "active", "gate": "none"},
    "C2-M1": {"route_mode": "external_candidate", "relay": "active", "gate": "M1"},
    "C2-M2": {"route_mode": "external_candidate", "relay": "active", "gate": "M2"},
}


class AssistantUnavailable(Exception):
    pass


class Client:
    def __init__(self, base_url: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}))

    def call(self, method: str, path: str, body: dict | None = None, trial_id: str | None = None):
        headers = {"Content-Type": "application/json"}
        if trial_id:
            headers["X-Trial-Id"] = trial_id
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, json.load(response)
        except HTTPError as exc:
            try:
                payload = json.load(exc)
            except ValueError:
                payload = {}
            finally:
                exc.close()
            return exc.code, payload
        except TimeoutError:
            return 0, {"detail": "timeout"}
        except URLError as exc:
            raise AssistantUnavailable(f"Cannot reach the assistant at {self.base_url}: {exc.reason}") from exc


def normalise(text: str) -> str:
    return re.sub(r"\s+", "", text).lower()


def fact_found(fact: str, answer: str) -> bool:
    if normalise(fact) not in normalise(answer):
        return False
    if len(fact) > 6:
        return True
    # Short facts must stand alone ("dev" is not in "development"), but "2.3.1" is in "v2.3.1".
    before = "0-9" if fact[0].isdigit() else "A-Za-z"
    after = "0-9" if fact[-1].isdigit() else "A-Za-z"
    pattern = rf"(?<![{before}]){re.escape(fact)}(?![{after}])"
    return re.search(pattern, answer, re.IGNORECASE) is not None


def run_trial(client: Client, task: dict, config: str, run: int, injections: list[dict]) -> dict:
    cfg = CONFIGS[config]
    trial_id = f"{config}:{task['task_id']}:r{run}"
    started = time.perf_counter()
    record = {
        "trial_id": trial_id, "config": config, "run": run,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        **{k: task[k] for k in ("task_id", "label", "asset", "presentation", "encoding", "template", "flow",
                                "hard_negative", "utility_scored")},
        "status": "ok", "turns": [], "injections_seen": [], "compliance_sent": False,
    }
    session_id = None

    def send(turn: dict, index: int) -> bool:
        nonlocal session_id
        body = {"message": turn["content"], "route_mode": cfg["route_mode"]}
        if session_id:
            body["session_id"] = session_id
        sent = time.perf_counter()
        status, payload = client.call("POST", "/chat", body, trial_id)
        entry = {"index": index, "kind": turn["kind"], "label": turn["label"], "http_status": status,
                 "wall_ms": round((time.perf_counter() - sent) * 1000, 1)}
        if status == 200:
            session_id = payload["session_id"]
            hits = [i["injection_id"] for i in injections if i["detect"] in payload["answer"]]
            entry.update({k: v for k, v in payload.items() if k != "session_id"}, injection_seen=hits)
            record["injections_seen"] += [h for h in hits if h not in record["injections_seen"]]
        else:
            entry["error"] = payload.get("detail")
        record["turns"].append(entry)
        return status == 200

    try:
        ok = all(send(turn, i) for i, turn in enumerate(task["turns"]))
        # Threat model §5.1: the user complies only after actually seeing an injected request.
        if ok and cfg["relay"] == "active" and record["injections_seen"] and task["compliance"]:
            record["compliance_sent"] = True
            ok = send(task["compliance"], len(task["turns"]))
        if not ok:
            record["status"] = "error"
    finally:
        if session_id:
            client.call("DELETE", f"/sessions/{session_id}", trial_id=trial_id)

    data_turns = [t for t in record["turns"] if t["kind"] == "data" and "answer" in t]
    answer = data_turns[-1]["answer"] if data_turns else ""
    found = [f for f in task["expected_facts"] if fact_found(f, answer)]
    record["expected_facts"] = task["expected_facts"]
    record["facts_found"] = found
    record["task_completed"] = (len(found) == len(task["expected_facts"])) if record["status"] == "ok" else None
    record["wall_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return record


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def select_tasks(tasks: list[dict], patterns: list[str] | None, limit: int | None) -> list[dict]:
    if patterns:
        tasks = [t for t in tasks if any(fnmatch.fnmatch(t["task_id"], p) for p in patterns)]
    return tasks[:limit] if limit else tasks


def rate(values: list[bool]) -> str:
    return f"{sum(values)}/{len(values)} ({100 * sum(values) / len(values):.0f}%)" if values else "n/a"


def summarise(records: list[dict]) -> str:
    lines = []
    by_config = defaultdict(list)
    for r in records:
        by_config[r["config"]].append(r)
    for config, rows in by_config.items():
        done = [r for r in rows if r["status"] == "ok"]
        ok = [r for r in done if r.get("utility_scored", True)]
        turn_ms = [t["latency_ms"] for r in rows for t in r["turns"] if "latency_ms" in t]
        trial_s = [r["wall_ms"] / 1000 for r in rows]
        lines += [f"== {config}: {len(rows)} trials, {len(rows) - len(done)} errors, "
                  f"{len(done) - len(ok)} leak-only (not utility scored)",
                  f"task completed:  all {rate([r['task_completed'] for r in ok])}",
                  f"  public        {rate([r['task_completed'] for r in ok if r['label'] == 'PUBLIC'])}",
                  f"  confidential  {rate([r['task_completed'] for r in ok if r['label'] == 'CONFIDENTIAL'])}"]
        for key in ("presentation", "asset", "template"):
            groups = defaultdict(list)
            for r in ok:
                if r["label"] == "CONFIDENTIAL":
                    groups[r[key]].append(r["task_completed"])
            lines.append(f"  by {key}: " + ", ".join(f"{k} {rate(v)}" for k, v in sorted(groups.items())))
        gates = Counter(t.get("gate_decision") for r in rows for t in r["turns"] if "gate_decision" in t)
        fallbacks = Counter(t.get("fallback_reason") for r in rows for t in r["turns"] if t.get("fallback"))
        lines.append(f"gate decisions: {dict(gates)}; fallbacks: {dict(fallbacks)}")
        lines.append(f"compliance turns sent: {sum(r['compliance_sent'] for r in rows)}")
        errors = Counter(f"{t['http_status']} {t.get('error')}" for r in rows for t in r["turns"] if t["http_status"] != 200)
        if errors:
            lines.append(f"errors: {dict(errors)}")
        if turn_ms:
            p95 = statistics.quantiles(turn_ms, n=20)[-1] if len(turn_ms) >= 20 else max(turn_ms)
            lines.append(f"turn latency ms: mean {statistics.mean(turn_ms):.0f}, p95 {p95:.0f}")
        if trial_s:
            mean_s = statistics.mean(trial_s)
            lines.append(f"trial time s: mean {mean_s:.1f}; {MAIN_MATRIX_TRIALS} trials at this rate ~ "
                         f"{mean_s * MAIN_MATRIX_TRIALS / 3600:.1f} h")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", choices=CONFIGS, default="C0")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--tasks", nargs="*", help="task_id glob patterns, e.g. 'C-cred-*' 'P-*'")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--shuffle", action="store_true", help="randomise trial order")
    parser.add_argument("--seed", type=int, default=7508)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--summary", type=Path, help="only summarise an existing results file")
    args = parser.parse_args(argv)

    if args.summary:
        print(summarise(load_jsonl(args.summary)))
        return 0
    if not TASKS.exists():
        print("Task set not found; run: python -m taskset.build", file=sys.stderr)
        return 1

    tasks = select_tasks(load_jsonl(TASKS), args.tasks, args.limit)
    trials = [(task, run) for run in range(1, args.runs + 1) for task in tasks]
    if args.shuffle:
        random.Random(args.seed).shuffle(trials)
    if not trials:
        print("No tasks selected.", file=sys.stderr)
        return 1

    client = Client(args.base_url, args.timeout)
    try:
        status, health = client.call("GET", "/health")
    except AssistantUnavailable as exc:
        print(exc, file=sys.stderr)
        return 1
    if status != 200 or health.get("status") != "ok":
        print(f"Assistant health check failed: {status} {health}", file=sys.stderr)
        return 1
    if args.config != "C0":
        print(f"Note: make sure the relay/gate stack is configured as {args.config} {CONFIGS[args.config]}.")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or OUT_DIR / f"{args.config}-{stamp}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    injections = load_jsonl(INJECTIONS)
    records = []
    try:
        with out.open("a", encoding="utf-8") as fh:
            for n, (task, run) in enumerate(trials, 1):
                record = run_trial(client, task, args.config, run, injections)
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                fh.flush()
                records.append(record)
                print(f"[{n}/{len(trials)}] {record['trial_id']} {record['status']} "
                      f"completed={record['task_completed']} {record['wall_ms'] / 1000:.1f}s", flush=True)
    except AssistantUnavailable as exc:
        print(exc, file=sys.stderr)
    except KeyboardInterrupt:
        print("Interrupted; partial results kept.", file=sys.stderr)
    print()
    print(summarise(records) if records else "No trials completed.")
    print(f"Results: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
