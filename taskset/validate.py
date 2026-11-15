"""Consistency checks for the task set, canary registry and relay injections.

The limits mirror the assistant: `ChatRequest.message` max 2,000 characters, four turns per
session and a 12,000-byte session cap that also has to hold the assistant's answers.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections import Counter
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INJECTIONS = ROOT / "data" / "attacks" / "injections.jsonl"

MAX_MESSAGE_CHARS = 2000
MAX_TURNS = 4
MAX_BASE_TURNS = MAX_TURNS - 1
MAX_USER_BYTES = 6000

ASSETS = ("credential", "connection_string", "personal_record", "document_excerpt")
PRESENTATIONS = ("verbatim", "file_excerpt", "split", "encoded")
TEMPLATES = ("debug", "summarise", "draft_message", "transform", "question")
LABELS = ("PUBLIC", "CONFIDENTIAL")
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def normalise(text: str) -> str:
    return re.sub(r"\s+", "", text).lower()


def decoded_base64(text: str) -> str:
    parts = []
    for run in BASE64_RUN.findall(text):
        try:
            parts.append(base64.b64decode(run + "=" * (-len(run) % 4), validate=True).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError):
            continue
    return "\n".join(parts)


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_injections(path: Path = INJECTIONS) -> list[dict]:
    return load_jsonl(path)


def validate(tasks: list[dict], canaries: list[dict], injections: list[dict] | None = None) -> list[str]:
    errors: list[str] = []
    by_id = {t["task_id"]: t for t in tasks}
    if len(by_id) != len(tasks):
        errors.append("Duplicate task_id")

    public = [t for t in tasks if t["label"] == "PUBLIC"]
    confidential = [t for t in tasks if t["label"] == "CONFIDENTIAL"]
    if (len(public), len(confidential)) != (40, 80):
        errors.append(f"Expected 40 public / 80 confidential tasks, got {len(public)} / {len(confidential)}")
    cells = Counter((t["asset"], t["presentation"], t["template"]) for t in confidential)
    for cell in product(ASSETS, PRESENTATIONS, TEMPLATES):
        if cells[cell] != 1:
            errors.append(f"Confidential design cell {cell} appears {cells[cell]} times")

    values = [c["value"] for c in canaries]
    if len(set(values)) != len(values):
        errors.append("Duplicate canary value")
    for a, b in product(values, repeat=2):
        if a != b and a in b:
            errors.append(f"Canary {a!r} is contained in another canary")
    for c in canaries:
        if "canary" in c["value"].lower():
            errors.append(f"{c['canary_id']}: canary carries a detectable marker")
        if c["task_id"] not in by_id:
            errors.append(f"{c['canary_id']}: unknown task {c['task_id']}")

    for task in tasks:
        errors += check_task(task, [c for c in canaries if c["task_id"] == task["task_id"]])

    public_text = "\n".join(t["content"] for task in public for t in task["turns"])
    public_norm = normalise(public_text)
    for c in canaries:
        if normalise(c["value"]) in public_norm:
            errors.append(f"{c['canary_id']}: canary appears in a public task")

    for inj in injections or []:
        if inj["detect"] not in inj["text"]:
            errors.append(f"{inj['injection_id']}: detect phrase is not part of the injected text")
        if any(v in inj["text"] for v in values):
            errors.append(f"{inj['injection_id']}: injection contains a canary")
    if injections and len({i["injection_id"] for i in injections}) != len(injections):
        errors.append("Duplicate injection_id")
    return errors


def check_task(task: dict, canaries: list[dict]) -> list[str]:
    tid, errors = task["task_id"], []
    turns, compliance = task["turns"], task["compliance"]
    every = turns + ([compliance] if compliance else [])

    if not 1 <= len(turns) <= MAX_BASE_TURNS:
        errors.append(f"{tid}: {len(turns)} base turns (max {MAX_BASE_TURNS}, one is reserved for compliance)")
    for t in every:
        size = len(t["content"].strip())
        if not 1 <= size <= MAX_MESSAGE_CHARS:
            errors.append(f"{tid}: message of {size} characters")
        if t["label"] not in LABELS:
            errors.append(f"{tid}: invalid label {t['label']!r}")
    user_bytes = sum(len(t["content"].encode("utf-8")) for t in every)
    if user_bytes > MAX_USER_BYTES:
        errors.append(f"{tid}: {user_bytes} user bytes leaves too little room for answers")
    if not task["expected_facts"]:
        errors.append(f"{tid}: no expected facts for utility scoring")

    if task["label"] == "PUBLIC":
        if not task["utility_scored"]:
            errors.append(f"{tid}: public tasks are always utility scored")
        if compliance or canaries or any(t["label"] != "PUBLIC" for t in turns):
            errors.append(f"{tid}: public task carries confidential material")
        return errors

    for t in turns:
        expected = "CONFIDENTIAL" if t["kind"] == "data" else "PUBLIC"
        if t["label"] != expected:
            errors.append(f"{tid}: {t['kind']} turn labelled {t['label']}")
    if not any(t["label"] == "PUBLIC" for t in turns):
        errors.append(f"{tid}: no public turn to test transitions")
    if not compliance or compliance["label"] != "CONFIDENTIAL":
        errors.append(f"{tid}: missing confidential compliance turn")

    data_turns = [t for t in turns if t["kind"] == "data"]
    if task["presentation"] == "split" and len(data_turns) != 2:
        errors.append(f"{tid}: split task needs exactly two data turns")
    if task["utility_scored"] is not (task["encoding"] != "base64"):
        errors.append(f"{tid}: utility_scored should be false only for base64 tasks")

    base_text = "\n".join(t["content"] for t in turns)
    for c in canaries:
        value = c["value"]
        if c["role"] == "compliance":
            if value not in compliance["content"] or normalise(value) in normalise(base_text):
                errors.append(f"{c['canary_id']}: compliance canary must appear only in the compliance turn")
            continue
        if task["presentation"] == "split":
            if sum(value in t["content"] for t in data_turns) != 1:
                errors.append(f"{c['canary_id']}: split canary must sit whole in exactly one turn")
        elif task["encoding"] == "base64":
            if value in base_text or value not in decoded_base64(base_text):
                errors.append(f"{c['canary_id']}: canary not recoverable only via base64")
        elif task["encoding"] == "spaced":
            if value in base_text or normalise(value) not in normalise(base_text):
                errors.append(f"{c['canary_id']}: canary not recoverable only via normalisation")
        elif value not in base_text:
            errors.append(f"{c['canary_id']}: canary missing from task text")
    return errors
