"""Body-derived attribution: turn counting, conversation ids and manifest mapping."""

import json
import tempfile
import unittest
from pathlib import Path

from relay7508.canary import Canary, CanarySet
from relay7508.conversation import conversation_id, conversation_key
from relay7508.scan import collect, summarise

OPENER = "Our dev cluster throws 500s after the 11:20 deploy. Which log should I read first?"


def _history(*user_turns: str) -> dict:
    messages = [{"role": "system", "content": "You are BrandAI."}]
    for index, text in enumerate(user_turns, start=1):
        messages.append({"role": "user", "content": text})
        messages.append({"role": "assistant", "content": f"answer {index}"})
    return {"model": "qwen3:4b", "messages": messages, "stream": False}


class ConversationKeyTest(unittest.TestCase):
    def test_turn_counts_user_messages(self):
        self.assertEqual(conversation_key(_history("a"))[1], 1)
        self.assertEqual(conversation_key(_history("a", "b"))[1], 2)
        self.assertEqual(conversation_key(_history(OPENER, "more", "even more"))[1], 3)

    def test_conv_id_is_stable_across_turns(self):
        first = conversation_key(_history(OPENER))[0]
        later = conversation_key(_history(OPENER, "and the config?"))[0]
        self.assertTrue(first)
        self.assertEqual(first, later)

    def test_conv_id_ignores_whitespace_noise(self):
        self.assertEqual(conversation_id("a  b\n c"), conversation_id("a b c"))

    def test_different_openers_differ(self):
        self.assertNotEqual(conversation_id(OPENER), conversation_id("Something else entirely"))

    def test_non_chat_bodies_are_tolerated(self):
        for body in (None, [], {}, {"messages": []}, {"messages": "nope"}, {"prompt": "x"}):
            self.assertEqual(conversation_key(body), (None, None))


class ScanAttributionTest(unittest.TestCase):
    """A log without task ids is attributed through the manifest's opening prompt."""

    def _write(self, records) -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                             encoding="utf-8")
        with handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")
        return handle.name

    def test_log_without_task_id_maps_to_manifest_task(self):
        canaries = CanarySet([Canary("c-api", "AKIAIOSFODNN7EXAMPLE", "api_key", "t1")])
        log = self._write([
            {
                "recipient": "relay",
                "task_id": "unknown-task",
                "conv_id": conversation_id(OPENER),
                "turn": 1,
                "request": {"body": _history(OPENER)},
                "response": {"body": {"message": {"content": "ok"}}},
            },
            {
                "recipient": "relay",
                "task_id": "unknown-task",
                "conv_id": conversation_id(OPENER),
                "turn": 2,
                "request": {"body": _history(OPENER, "the key is AKIAIOSFODNN7EXAMPLE")},
                "response": {"body": {"message": {"content": "received"}}},
            },
        ])
        tasks = {"t1": {"condition": "C2", "opening": OPENER, "assigned": ["c-api"]}}
        results = collect(canaries, {"relay": log}, tasks)
        self.assertIn("t1", results)
        self.assertNotIn("unknown-task", results)
        self.assertEqual(results["t1"].leak_count("relay"), 1)
        summary = summarise(results, canaries, ["relay"])
        self.assertEqual(summary["tasks_missing_from_manifest"], [])
        self.assertEqual(summary["extra_leakage_after_turn_1"]["relay"], 1)
        Path(log).unlink()

    def test_unmapped_conversation_stays_unknown(self):
        canaries = CanarySet([Canary("c-api", "AKIAIOSFODNN7EXAMPLE", "api_key", "t1")])
        log = self._write([{"recipient": "relay", "task_id": "unknown-task",
                            "conv_id": "deadbeefcafe", "turn": 1,
                            "request": {"body": _history("unrelated chat")},
                            "response": {"body": {}}}])
        results = collect(canaries, {"relay": log},
                          {"t1": {"opening": OPENER, "assigned": ["c-api"]}})
        self.assertIn("unknown-task", results)
        Path(log).unlink()


if __name__ == "__main__":
    unittest.main()
