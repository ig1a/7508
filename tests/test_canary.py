"""Representation-aware canary matching: what must be detected, and what must not."""

import unittest

from relay7508.canary import Canary, CanarySet, flatten_json_text

CANARY = "AKIAIOSFODNN7EXAMPLE"
PASSWORD = "Hunter2-Vault-9921"


def corpus() -> CanarySet:
    return CanarySet([
        Canary("c1", CANARY, "api_key"),
        Canary("c2", PASSWORD, "password"),
        Canary("c3", "192.0.2.77:5432/appdb", "connection_string"),
    ])


class TestMatching(unittest.TestCase):
    def test_verbatim(self):
        self.assertEqual(corpus().match(f"here it is: {CANARY} thanks"), {"c1": ["verbatim"]})

    def test_case_changed(self):
        hits = corpus().match(CANARY.lower())
        self.assertEqual(hits, {"c1": ["casefold"]})

    def test_whitespace_obfuscated(self):
        spaced = " ".join(CANARY.lower())
        self.assertIn("c1", corpus().match(f"key: {spaced}"))

    def test_base64_of_value(self):
        import base64

        encoded = base64.b64encode(CANARY.encode()).decode()
        self.assertIn("c1", corpus().match(f"blob {encoded}"))

    def test_value_inside_aligned_base64_blob(self):
        """A 3-byte-aligned prefix leaves the value's own base64 intact inside the blob."""
        import base64

        payload = base64.b64encode(f"config: api={CANARY}; db=ok".encode()).decode()
        hits = corpus().match(f"pasted: {payload}")
        self.assertIn("c1", hits)
        self.assertEqual(hits["c1"], ["base64"])

    def test_value_inside_misaligned_base64_blob(self):
        """When the encoding is shifted, only decoding the blob recovers the value."""
        import base64

        payload = base64.b64encode(f"k={CANARY}".encode()).decode()
        self.assertNotIn(CANARY, payload)
        hits = corpus().match(f"pasted: {payload}")
        self.assertIn("c1", hits)
        self.assertEqual(hits["c1"], ["value_inside_b64"])

    def test_value_inside_multiline_base64_record(self):
        """Encoded task records decode to several lines; the newlines must not hide the value."""
        import base64

        payload = base64.b64encode(f"Name: Test\nk={CANARY}\r\n\tNote: x\n".encode()).decode()
        self.assertNotIn(CANARY, payload)
        hits = corpus().match(f"decode this first:\n{payload}")
        self.assertEqual(hits.get("c1"), ["value_inside_b64"])

    def test_value_inside_base64_after_json_escaped_newline(self):
        """Log bodies are matched as JSON text, so the blob follows a literal backslash-n."""
        import base64

        payload = base64.b64encode(f"Name: Test\nk={CANARY}\n".encode()).decode()
        body = {"messages": [{"role": "user", "content": f"decode this first:\n{payload}"}]}
        hits = corpus().match(flatten_json_text(body))
        self.assertEqual(hits.get("c1"), ["value_inside_b64"])

    def test_url_encoded(self):
        import urllib.parse

        hits = corpus().match("q=" + urllib.parse.quote("192.0.2.77:5432/appdb", safe=""))
        self.assertIn("c3", hits)

    def test_no_false_positive_on_similar_text(self):
        self.assertEqual(corpus().match("AKIAIOSFODNN7EXAMPLZ and Hunter2-Vault"), {})

    def test_empty_and_none(self):
        self.assertEqual(corpus().match(""), {})
        self.assertEqual(corpus().match(None), {})

    def test_flatten_json_searches_nested_values(self):
        body = {"messages": [{"role": "user", "content": f"fix {CANARY}"}]}
        self.assertIn("c1", corpus().match(flatten_json_text(body)))

    def test_json_escaped_backslash_does_not_hide_value(self):
        body = {"messages": [{"content": "line1\n" + PASSWORD}]}
        self.assertIn("c2", corpus().match(flatten_json_text(body)))


class TestCorpusLoading(unittest.TestCase):
    def test_field_aliases(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.json"
            path.write_text(json.dumps([
                {"id": "x1", "secret": "hunter2-prod", "type": "password"},
                {"canary_id": "x2", "value": "s3cr3t-token", "secret_type": "api_key"},
            ]), encoding="utf-8")
            loaded = CanarySet.from_json(str(path))
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded.by_id("x1").secret_type, "password")
        self.assertEqual(loaded.by_id("x2").value, "s3cr3t-token")


if __name__ == "__main__":
    unittest.main()
