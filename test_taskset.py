"""Task set checks; no model or network needed."""

import copy
import unittest

from taskset.build import build
from taskset.validate import load_injections, validate


class TasksetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.built = build()

    def test_built_set_is_valid(self):
        self.assertEqual(validate(self.built["tasks"], self.built["canaries"], load_injections()), [])

    def test_build_is_deterministic(self):
        self.assertEqual(build(), self.built)
        self.assertNotEqual(build(seed=1)["canaries"], self.built["canaries"])

    def test_validator_catches_leaked_canary_in_public_task(self):
        tasks = copy.deepcopy(self.built["tasks"])
        public = next(t for t in tasks if t["label"] == "PUBLIC")
        public["turns"][0]["content"] += " " + self.built["canaries"][0]["value"]
        self.assertTrue(any("public task" in e for e in validate(tasks, self.built["canaries"])))

    def test_validator_catches_oversized_message(self):
        tasks = copy.deepcopy(self.built["tasks"])
        tasks[0]["turns"][0]["content"] += "x" * 2000
        self.assertTrue(any("characters" in e for e in validate(tasks, self.built["canaries"])))

    def test_validator_rejects_marker_canaries(self):
        canaries = copy.deepcopy(self.built["canaries"])
        canaries[0]["value"] = "CANARY-0001"
        self.assertTrue(any("marker" in e for e in validate(self.built["tasks"], canaries)))

    def test_labeller_inputs_exclude_canary_registry(self):
        record_keys = {k for r in self.built["records"] for k in r}
        self.assertNotIn("canaries", record_keys)
        self.assertNotIn("value", record_keys)


if __name__ == "__main__":
    unittest.main()
