"""No-network M1 regression tests; detector mocks complement Windows real-plugin validation."""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

from gate import OutboundRequest
from security_gateway.audit import SecurityAuditLogger
from security_gateway.detection import (
    HybridPayloadScanner,
    _contains_nonplaceholder_db_password,
    _hk_id_valid,
    _is_high_entropy_secret,
    extract_payload_texts,
)
from security_gateway.engine import SecurityForwardingGate
from sessions import store


class SpyAnalyzer:
    def __init__(self):
        self.seen = []

    def analyze(self, *, text: str, language: str):
        self.seen.append(text)
        if "ordinary example" in text.lower():
            return [SimpleNamespace(entity_type="PERSON", score=.85),
                    SimpleNamespace(entity_type="IP_ADDRESS", score=.85),
                    SimpleNamespace(entity_type="US_BANK_NUMBER", score=.7)]
        if "contact@sample.net" in text:
            return [SimpleNamespace(entity_type="EMAIL_ADDRESS", score=1.0)]
        return []


def scanner_with_fake_plugins(secret_type_for=None):
    """Do not require Presidio/spaCy downloads for structural tests."""
    scanner = HybridPayloadScanner()
    scanner._initialised = True
    scanner._secret_default_settings = nullcontext
    scanner._presidio_analyzer = SpyAnalyzer()

    def scan_line(line):
        if secret_type_for is not None:
            return [SimpleNamespace(type=kind) for kind in secret_type_for(line)]
        return []

    scanner._secret_scan_line = scan_line
    return scanner


class M1PayloadScopeTests(unittest.TestCase):
    def test_model_and_generation_options_are_not_scanned(self):
        body = json.dumps({
            "model": "qwen3:4b-instruct-2507-q4_K_M",
            "options": {"provider_identifier": "LongRandomModelIdentifierQ1W2E3R4T5"},
            "stream": False,
            "messages": [
                {"role": "system", "content": "A system instruction"},
                {"role": "user", "content": "Explain this ordinary example."},
            ],
        }).encode()
        texts = extract_payload_texts(body)
        self.assertEqual(texts, ["A system instruction", "Explain this ordinary example."])

    def test_multiturn_assistant_and_user_content_are_inspected(self):
        body = json.dumps({"messages": [
            {"role": "user", "content": "a secret"},
            {"role": "assistant", "content": "a derived secret"},
            {"role": "user", "content": "a harmless followup"},
        ]}).encode()
        self.assertIn("a secret", extract_payload_texts(body))
        self.assertIn("a derived secret", extract_payload_texts(body))
        self.assertIn("a harmless followup", extract_payload_texts(body))

    def test_unknown_dynamic_fields_are_still_scanned(self):
        body = json.dumps({
            "messages": [{"role": "user", "content": "hello", "tool_args": {"credential": "secret1"}}],
            "tools": [{"params": {"credential": "secret2"}}],
        }).encode()
        texts = extract_payload_texts(body)
        self.assertIn("secret1", texts)
        self.assertIn("secret2", texts)

    def test_malformed_message_type_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "PAYLOAD_INVALID_MESSAGES"):
            extract_payload_texts(b'{"messages":"not a list"}')

    def test_static_transport_metadata_is_not_scanned(self):
        inspector = scanner_with_fake_plugins()
        with tempfile.TemporaryDirectory() as temp:
            gate = SecurityForwardingGate(scanner=inspector, audit=SecurityAuditLogger(Path(temp) / "audit.jsonl"))
            with store.lock:
                sid, _ = store.get_or_create(None)
                store.update_security_label(sid, "PUBLIC")
                try:
                    req = OutboundRequest(
                        url="http://127.0.0.1:11435/api/chat",
                        body=b'{"model":"model-long-example","messages":[{"role":"user","content":"hello"}]}',
                        headers=(("Content-Type", "application/json"),
                                 ("X-Trial-Id", "C1-M1:P-api-question:r1:b20261123T120000-0a1b2c"),
                                 ("X-Relay-Mode", "active")),
                        gate_mode="M1",
                        trial_id="C1-M1:P-api-question:r1:b20261123T120000-0a1b2c",
                    )
                    result = gate.inspect(req, session_id=sid)
                    self.assertTrue(result.allowed)
                    self.assertEqual(inspector._presidio_analyzer.seen, ["hello"])
                finally:
                    store.delete(sid)

    def test_custom_secret_header_is_inspected(self):
        inspector = scanner_with_fake_plugins(lambda line: ["AWS Access Key"] if "AKIAEXAMPLESECRET123456" in line else [])
        with tempfile.TemporaryDirectory() as temp:
            gate = SecurityForwardingGate(scanner=inspector, audit=SecurityAuditLogger(Path(temp) / "audit.jsonl"))
            with store.lock:
                sid, _ = store.get_or_create(None)
                store.update_security_label(sid, "PUBLIC")
                try:
                    req = OutboundRequest(url="http://127.0.0.1:11435/api/chat",
                        body=b'{"messages":[{"role":"user","content":"hello"}]}',
                        headers=(("Authorization", "Bearer AKIAEXAMPLESECRET123456"),),
                        gate_mode="M1")
                    self.assertFalse(gate.inspect(req, session_id=sid).allowed)
                finally:
                    store.delete(sid)


class M1PolicyQualityTests(unittest.TestCase):
    def _scan(self, text, secret_type_for=None):
        scanner = scanner_with_fake_plugins(secret_type_for)
        result = scanner.scan(json.dumps({"messages": [{"role": "user", "content": text}]}).encode())
        self.assertTrue(result.inspection_complete, result.error_code)
        return result

    def test_generic_named_entities_do_not_block_public(self):
        result = self._scan("Explain this ordinary example in a short sentence")
        self.assertFalse(result.has_sensitive_data)

    def test_email_is_sensitive(self):
        result = self._scan("Send mail to contact@sample.net")
        self.assertIn("EMAIL_ADDRESS", result.entity_types)

    def test_provider_key_is_sensitive(self):
        token = "AKIAEXAMPLESECRET123456"
        result = self._scan("My AWS access key is " + token,
                            lambda line: ["AWS Access Key"] if token in line else [])
        self.assertIn("AWS Access Key", result.entity_types)

    def test_secret_high_entropy_candidate_needs_context(self):
        token = "Z1k2Y3l4X5m6W7n8V9b0C1d2E3f4G5h6I7j8K9l0"
        find = lambda line: ["Base64 High Entropy String"] if token in line else []
        self.assertTrue(self._scan("API_KEY=" + token, find).has_sensitive_data)

    def test_checksum_avoids_high_entropy_false_positive(self):
        sha = "a4" * 32
        find = lambda line: ["Hex High Entropy String"] if sha in line else []
        result = self._scan("Public release. SHA-256 checksum: " + sha + ".", find)
        self.assertFalse(result.has_sensitive_data)

    def test_public_env_placeholders_not_assumed_secret(self):
        text = "# Example .env - replace values before use\nAPI_KEY=<your-api-key>\nSECRET_KEY=changeme\nDATABASE_URL=postgres://user:password@localhost:5432/app"
        result = self._scan(text, lambda line: ["Basic Auth Credentials", "Secret Keyword"] if "password@localhost" in line or "changeme" in line else [])
        self.assertFalse(result.has_sensitive_data)

    def test_example_claim_cannot_disguise_real_secret_keyword(self):
        result = self._scan(
            "# example file\nSECRET_KEY=password12345",
            lambda line: ["Secret Keyword"] if "password12345" in line else [],
        )
        self.assertIn("Secret Keyword", result.entity_types)

    def test_database_password_is_sensitive(self):
        password = "h7Kd9sjR5znP41dWq"
        result = self._scan("DATABASE_URL=postgresql://service:" + password + "@private-db.internal:5432/app")
        self.assertIn("DATABASE_PASSWORD", result.entity_types)

    def test_hkid_checksum_is_validated(self):
        letter, digits = "A", [1, 2, 3, 4, 5, 6]
        t = 36 * 9 + (ord(letter) - 55) * 8 + sum(d * (7 - i) for i, d in enumerate(digits))
        c = (11 - t % 11) % 11
        number = "A123456(" + ("A" if c == 10 else str(c)) + ")"
        self.assertTrue(_hk_id_valid(number))
        result = self._scan("HKID: " + number)
        self.assertIn("HKID", result.entity_types)

    def test_hkid_wrong_checksum_is_not_accepted(self):
        self.assertFalse(_hk_id_valid("A123456(Z)"))

    def test_database_placeholder_password_not_secret(self):
        self.assertFalse(_contains_nonplaceholder_db_password(
            "DATABASE_URL=postgres://user:password@localhost:5432/app"))

    def test_no_plugin_does_not_mean_no_scan(self):
        scanner = HybridPayloadScanner()
        scanner._initialised = True
        scanner._initialise_error = "DETECT_SECRETS_UNAVAILABLE:ImportError"
        result = scanner.scan(b'{"messages":[{"content":"clean"}]}')
        self.assertFalse(result.inspection_complete)


if __name__ == "__main__":
    unittest.main()
