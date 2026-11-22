"""Tests for the leak extractor's bookkeeping."""

from __future__ import annotations

import unittest

from relay7508.canary import Canary, CanarySet
from relay7508.scan import TaskResult, collect, summarise


def corpus() -> CanarySet:
    return CanarySet([
        Canary("c1", "AKIAIOSFODNN7EXAMPLE", "api_key", "t1"),
        Canary("c2", "Hunter2-Prod-2026", "password", "t1"),
    ])


class TestSummarise(unittest.TestCase):
    def build(self) -> dict[str, TaskResult]:
        known = TaskResult("t1", condition="C2", phrasing="verbatim",
                           assigned={"c1", "c2"})
        known.leaked["relay"] = {"c1": {"turn": 1, "forms": ["verbatim"],
                                        "direction": "request"}}
        known.calls["relay"] = 2
        stray = TaskResult("t9", condition="C1", phrasing="none", assigned=set(),
                           in_manifest=False)
        stray.leaked["relay"] = {"c2": {"turn": 3, "forms": ["base64"],
                                        "direction": "response"}}
        stray.calls["relay"] = 1
        return {"t1": known, "t9": stray}

    def test_totals_and_extra_leakage(self):
        summary = summarise(self.build(), corpus(), ["relay"])
        totals = summary["totals"]["relay"]
        self.assertEqual(totals["canaries_assigned"], 2)
        self.assertEqual(totals["canaries_leaked"], 1)
        self.assertEqual(totals["leak_rate"], 0.5)
        self.assertEqual(totals["requests_logged"], 3)
        self.assertEqual(summary["extra_leakage_after_turn_1"]["relay"], 0)

    def test_assigned_late_hit_in_c1_is_not_c2_extra_leakage(self):
        results = self.build()
        results["t9"].assigned = {"c2"}
        summary = summarise(results, corpus(), ["relay"])
        self.assertEqual(summary["totals"]["relay"]["canaries_leaked"], 2)
        self.assertEqual(summary["extra_leakage_after_turn_1"]["relay"], 0)

    def test_buckets_use_the_manifest(self):
        summary = summarise(self.build(), corpus(), ["relay"])
        self.assertEqual(summary["by_condition"]["C2"]["relay_rate"], 0.5)
        self.assertEqual(summary["by_secret_type"]["api_key"]["relay_rate"], 1.0)
        self.assertEqual(summary["by_secret_type"]["password"]["relay_rate"], 0.0)
        self.assertEqual(summary["tasks_missing_from_manifest"], ["t9"])

    def test_collect_without_logs_still_groups_the_corpus(self):
        results = collect(corpus(), {}, None)
        self.assertEqual(list(results), ["t1"])
        self.assertEqual(results["t1"].assigned, {"c1", "c2"})
        self.assertEqual(results["t1"].leaked, {})

    def test_collect_without_manifest_groups_by_canary_task(self):
        import json
        import os
        import tempfile

        record = {"recipient": "relay", "task_id": "t1", "condition": "C2", "turn": 1,
                  "request": {"body": {"prompt": "AKIAIOSFODNN7EXAMPLE Hunter2-Prod-2026"}},
                  "response": {"body": {"text": "ok"}}}
        handle, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
        try:
            results = collect(corpus(), {"relay": path}, None)
            self.assertIn("t1", results)
            self.assertEqual(results["t1"].leaked["relay"]["c1"]["forms"], ["verbatim"])
            summary = summarise(results, corpus(), ["relay"])
            self.assertEqual(summary["totals"]["relay"]["leak_rate"], 1.0)
            restricted = collect(corpus(), {"relay": path}, {"t1": {"assigned": []}})
            totals = summarise(restricted, corpus(), ["relay"])["totals"]["relay"]
            self.assertEqual(totals["canaries_leaked"], 0)
            self.assertEqual(totals["off_manifest_leaks"], ["c1", "c2"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
