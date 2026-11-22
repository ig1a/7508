"""Command line entry point: ``python -m relay7508 <command>``.

    relay    run the logging forward proxy (passive or active mode)
    scan     extract leaked canaries from the relay / provider logs
    version  print the module version
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .canary import CanarySet
from .config import RelayConfig
from .relay import serve
from .scan import collect, print_summary, summarise, write_reports

__version__ = "0.1.0"


def _parse_logs(pairs: list[str]) -> dict[str, str]:
    logs: dict[str, str] = {}
    for item in pairs or []:
        if "=" not in item:
            raise SystemExit(f"--log must look like name=path, got {item!r}")
        name, path = item.split("=", 1)
        logs[name] = path
    return logs


def _load_tasks(path: str | None) -> dict | None:
    """Accept either ``{"t1": {...}}`` or ``{"tasks": [{"task_id": "t1", ...}]}``."""
    if not path:
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    rows = payload.get("tasks", payload) if isinstance(payload, dict) else payload
    if isinstance(rows, dict):
        return {str(key): dict(value, task_id=str(key)) for key, value in rows.items()}
    return {str(row["task_id"]): row for row in rows}


def cmd_relay(args: argparse.Namespace) -> int:
    config = RelayConfig.load(
        args.config,
        upstream=args.upstream,
        log=args.log,
        mode=args.mode,
        host=args.host,
        port=args.port,
    )
    serve(config)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    logs = _parse_logs(args.log)
    if not logs:
        raise SystemExit("at least one --log name=path is required")
    canaries = CanarySet.from_json(args.canaries)
    results = collect(canaries, logs, _load_tasks(args.tasks))
    summary = summarise(results, canaries, list(logs))
    write_reports(summary, args.out, args.csv)
    if not args.quiet:
        print_summary(summary)
        print(f"\nwrote {args.out}" + (f" and {args.csv}" if args.csv else ""))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="relay7508", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    relay = sub.add_parser("relay", help="run the logging forward proxy")
    relay.add_argument("--config", help="JSON config file (see relay7508/config.py)")
    relay.add_argument("--upstream", help="external provider base URL")
    relay.add_argument("--log", help="JSONL log path")
    relay.add_argument("--mode", choices=["passive", "active"], help="relay behaviour")
    relay.add_argument("--host", default=None)
    relay.add_argument("--port", type=int, default=None)
    relay.set_defaults(func=cmd_relay)

    scan = sub.add_parser("scan", help="extract leaked canaries from logs")
    scan.add_argument("--canaries", required=True, help="canary corpus JSON")
    scan.add_argument("--log", action="append", metavar="NAME=PATH",
                      help="repeatable, e.g. --log relay=logs/relay.jsonl")
    scan.add_argument("--tasks", help="task manifest JSON (assigned canaries, condition)")
    scan.add_argument("--out", default="reports/leak.json")
    scan.add_argument("--csv", help="optional per-task CSV")
    scan.add_argument("--quiet", action="store_true")
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
