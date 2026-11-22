"""Deterministic tests for the new security gateway logic (no model download required)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_gateway.audit import SecurityAuditLogger
from security_gateway.models import DecisionMode, DetectionFinding, DetectionReport, SecurityLabel
from security_gateway.policy import evaluate_policy
from security_gateway.provenance import merge_labels, parse_label
from sessions import SessionStore


class ProvenanceTests(unittest.TestCase):
    def test_first_turn_establishes_public(self):
        self.assertEqual(merge_labels(None, "PUBLIC"), SecurityLabel.PUBLIC)

    def test_missing_or_invalid_label_is_unknown(self):
        self.assertEqual(parse_label(None), SecurityLabel.UNKNOWN)
        self.assertEqual(parse_label("NOT_A_LABEL"), SecurityLabel.UNKNOWN)

    def test_confidential_is_sticky(self):
        state = merge_labels(None, "CONFIDENTIAL")
        self.assertEqual(merge_labels(state, "PUBLIC"), SecurityLabel.CONFIDENTIAL)
        self.assertEqual(merge_labels(state, "UNKNOWN"), SecurityLabel.CONFIDENTIAL)

    def test_unknown_cannot_be_upgraded_by_later_public_turn(self):
        state = merge_labels(None, None)
        self.assertEqual(merge_labels(state, "PUBLIC"), SecurityLabel.UNKNOWN)

    def test_public_becomes_unknown_when_later_label_missing(self):
        state = merge_labels(None, "PUBLIC")
        self.assertEqual(merge_labels(state, None), SecurityLabel.UNKNOWN)

    def test_session_store_deletes_label_with_history(self):
        store = SessionStore()
        sid, _ = store.get_or_create(None)
        self.assertEqual(store.update_security_label(sid, "PUBLIC"), SecurityLabel.PUBLIC)
        store.delete(sid)
        self.assertEqual(store.get_security_label(sid), SecurityLabel.UNKNOWN)
        self.assertNotIn(sid, store.security_labels)


class PolicyTests(unittest.TestCase):
    def test_m1_blocks_sensitive_payload(self):
        report = DetectionReport(findings=(DetectionFinding("presidio", "EMAIL"),))
        result = evaluate_policy(mode=DecisionMode.M1, session_label=SecurityLabel.PUBLIC, detection=report)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, "SENSITIVE_CONTENT")

    def test_m1_allows_clean_payload_without_using_session_label(self):
        result = evaluate_policy(mode=DecisionMode.M1, session_label=SecurityLabel.CONFIDENTIAL)
        self.assertTrue(result.allowed)

    def test_m2_blocks_confidential_and_unknown(self):
        for label in (SecurityLabel.CONFIDENTIAL, SecurityLabel.UNKNOWN):
            with self.subTest(label=label):
                result = evaluate_policy(mode=DecisionMode.M2, session_label=label)
                self.assertFalse(result.allowed)

    def test_m2_allows_public(self):
        result = evaluate_policy(mode=DecisionMode.M2, session_label=SecurityLabel.PUBLIC)
        self.assertTrue(result.allowed)

    def test_combined_gate_requires_both_checks(self):
        clean = DetectionReport()
        self.assertTrue(evaluate_policy(mode=DecisionMode.M1_M2, session_label=SecurityLabel.PUBLIC,
                                        detection=clean).allowed)
        self.assertFalse(evaluate_policy(mode=DecisionMode.M1_M2, session_label=SecurityLabel.CONFIDENTIAL,
                                         detection=clean).allowed)

    def test_incomplete_scan_fails_closed(self):
        report = DetectionReport(inspection_complete=False, error_code="MODEL_MISSING")
        result = evaluate_policy(mode=DecisionMode.M1, session_label=SecurityLabel.PUBLIC, detection=report)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason_code, "MODEL_MISSING")


class AuditTests(unittest.TestCase):
    def test_audit_never_writes_payload_or_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            logger = SecurityAuditLogger(path)
            logger.write(session_id="s1", trial_id="t1", mode="M1",
                         decision="DENY", reason_code="SENSITIVE_CONTENT",
                         session_label="PUBLIC", detector_names=("detect-secrets",),
                         entity_types=("API_KEY",), payload_bytes=99)
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("REAL_SECRET_VALUE", content)
            record = json.loads(content)
            self.assertEqual(record["decision"], "DENY")
            self.assertNotIn("payload", record)


class PayloadParsingTests(unittest.TestCase):
    def test_extracts_nested_json_string_values(self):
        from security_gateway.detection import extract_payload_texts
        payload = json.dumps({"messages": [{"role": "user", "content": "sample text"}]}).encode()
        texts = extract_payload_texts(payload)
        self.assertIn("sample text", texts)
        self.assertFalse(any('"messages"' in item for item in texts))

    def test_empty_payload_is_rejected(self):
        from security_gateway.detection import extract_payload_texts
        with self.assertRaises(ValueError) as ctx:
            extract_payload_texts(b"")
        self.assertEqual(str(ctx.exception), "PAYLOAD_EMPTY")

    def test_invalid_json_is_rejected(self):
        from security_gateway.detection import extract_payload_texts
        with self.assertRaises(ValueError) as ctx:
            extract_payload_texts(b'{"messages": [invalid json')
        self.assertEqual(str(ctx.exception), "PAYLOAD_INVALID_JSON")

    def test_base64_variant_is_decoded_for_scanning(self):
        import base64
        from security_gateway.detection import _derived_variants
        encoded = base64.b64encode(b"AKIAEXAMPLESECRET123456").decode()
        variants = _derived_variants("encoded=" + encoded)
        self.assertIn(("AKIAEXAMPLESECRET123456", "base64_decoded"), variants)

    def test_spaced_character_variant_is_compacted(self):
        from security_gateway.detection import _derived_variants
        variants = _derived_variants("s k - t e s t - 1 2 3 4")
        self.assertIn(("sk-test-1234", "spaced_compact"), variants)


class GateIntegrationTests(unittest.TestCase):
    def test_security_gate_uses_session_provenance(self):
        from gate import OutboundRequest
        from security_gateway.engine import SecurityForwardingGate
        from sessions import store

        class CleanScanner:
            def scan(self, payload, *, additional_texts=()):
                return DetectionReport()

        with tempfile.TemporaryDirectory() as tmp:
            gate = SecurityForwardingGate(scanner=CleanScanner(), audit=SecurityAuditLogger(Path(tmp) / "audit.jsonl"))
            store.histories.clear()
            store.security_labels.clear()
            public_id, _ = store.get_or_create(None)
            store.update_security_label(public_id, "PUBLIC")
            confidential_id, _ = store.get_or_create(None)
            store.update_security_label(confidential_id, "CONFIDENTIAL")
            unknown_id, _ = store.get_or_create(None)

            req = OutboundRequest(url="http://127.0.0.1:11435/api/chat", body=b'{"messages":[]} ', gate_mode="M2")
            self.assertTrue(gate.inspect(req, session_id=public_id).allowed)
            self.assertFalse(gate.inspect(req, session_id=confidential_id).allowed)
            self.assertFalse(gate.inspect(req, session_id=unknown_id).allowed)

    def test_api_passes_experiment_metadata_to_router(self):
        from main import ChatRequest, chat
        from routing import RoutingResult
        with patch.dict("os.environ", {"BRANDAI_RUNNER_TOKEN": "unit-test-only"}), patch(
            "main.run_assistant", return_value=RoutingResult("ok", "internal", "deny", "gate_denied", False, 0.0)
        ) as route:
            chat(ChatRequest(message="hello", source_label="CONFIDENTIAL", gate_mode="M2"),
                 x_trial_id="C1-M2:C-test:r1", x_experiment_token="unit-test-only")
            self.assertEqual(route.call_args.kwargs["gate_mode"], "M2")
            self.assertEqual(route.call_args.kwargs["trial_id"], "C1-M2:C-test:r1")

    def test_invalid_trial_id_is_rejected_before_routing(self):
        from fastapi import HTTPException
        from main import ChatRequest, chat
        with self.assertRaises(HTTPException) as ctx:
            chat(ChatRequest(message="hello"), x_trial_id="secret=REAL_SECRET_VALUE")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_gate_rejects_inconsistent_trial_header_without_logging_value(self):
        from gate import OutboundRequest
        from security_gateway.engine import SecurityForwardingGate
        from sessions import store

        class CleanScanner:
            def scan(self, payload, *, additional_texts=()):
                return DetectionReport()

        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "audit.jsonl"
            gate = SecurityForwardingGate(
                scanner=CleanScanner(), audit=SecurityAuditLogger(audit_path)
            )
            with store.lock:
                sid, _ = store.get_or_create(None)
                store.update_security_label(sid, "PUBLIC")
                try:
                    request = OutboundRequest(
                        url="http://127.0.0.1:11435/api/chat",
                        body=b'{"messages":[]}',
                        headers=(("X-Trial-Id", "secret=REAL_SECRET_VALUE"),),
                        gate_mode="M1",
                        trial_id="secret=REAL_SECRET_VALUE",
                    )
                    decision = gate.inspect(request, session_id=sid)
                finally:
                    store.delete(sid)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason_code, "INVALID_TRIAL_ID")
            self.assertNotIn("REAL_SECRET_VALUE", audit_path.read_text(encoding="utf-8"))

    def test_detector_timeout_fails_closed_and_disables_future_scans(self):
        from threading import Event
        from gate import OutboundRequest
        from security_gateway.engine import SecurityForwardingGate
        from sessions import store

        release = Event()

        class BlockingScanner:
            def scan(self, payload, *, additional_texts=()):
                release.wait(1)
                return DetectionReport()

        with tempfile.TemporaryDirectory() as tmp:
            gate = SecurityForwardingGate(
                scanner=BlockingScanner(),
                audit=SecurityAuditLogger(Path(tmp) / "audit.jsonl"),
                inspection_timeout_s=0.01,
            )
            with store.lock:
                sid, _ = store.get_or_create(None)
                store.update_security_label(sid, "PUBLIC")
                try:
                    request = OutboundRequest(
                        url="http://127.0.0.1:11435/api/chat",
                        body=b'{"messages":[]}',
                        gate_mode="M1",
                    )
                    first = gate.inspect(request, session_id=sid)
                    second = gate.inspect(request, session_id=sid)
                finally:
                    release.set()
                    store.delete(sid)
            self.assertFalse(first.allowed)
            self.assertEqual(first.reason_code, "DETECTOR_TIMEOUT")
            self.assertFalse(second.allowed)
            self.assertEqual(second.reason_code, "DETECTOR_DISABLED_AFTER_TIMEOUT")


class TrustedRunnerTests(unittest.TestCase):
    def test_missing_token_is_not_trusted(self):
        from security_gateway.trust import is_trusted_runner
        self.assertFalse(is_trusted_runner(None, "expected"))
        self.assertFalse(is_trusted_runner("wrong", "expected"))
        self.assertFalse(is_trusted_runner("expected", None))

    def test_correct_token_is_trusted(self):
        from security_gateway.trust import is_trusted_runner
        self.assertTrue(is_trusted_runner("local-test-token", "local-test-token"))

    def test_session_updates_are_atomic_and_audited_without_content(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "provenance.jsonl"
            store = SessionStore(audit_path)
            sid, _ = store.get_or_create(None)
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda label: store.update_security_label(sid, label),
                              ["PUBLIC", "CONFIDENTIAL", "PUBLIC", None] * 10))
            self.assertEqual(store.get_security_label(sid), SecurityLabel.CONFIDENTIAL)
            content = audit_path.read_text(encoding="utf-8")
            self.assertNotIn("SECRET", content)
            self.assertIn('"resulting_label": "CONFIDENTIAL"', content)
            records = [json.loads(line) for line in content.splitlines() if line.strip()]
            self.assertTrue(records)
            self.assertTrue(all("session_id" in record for record in records))
            store.delete(sid)
            self.assertEqual(store.get_security_label(sid), SecurityLabel.UNKNOWN)
            self.assertNotIn(sid, store.security_labels)

    def test_invalid_label_is_conservatively_unknown(self):
        store = SessionStore(provenance_audit_path=None)
        sid, _ = store.get_or_create(None)
        self.assertEqual(store.update_security_label(sid, "FORGED"), SecurityLabel.UNKNOWN)


class LabelIngressIntegrationTests(unittest.TestCase):
    def setUp(self):
        from sessions import store
        with store.lock:
            store.histories.clear()
            store.security_labels.clear()

    def test_unauthenticated_client_cannot_submit_public_label(self):
        from fastapi import HTTPException
        from main import ChatRequest, chat
        with self.assertRaises(HTTPException) as ctx:
            chat(ChatRequest(message="hello", source_label="PUBLIC"))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_authenticated_runner_can_submit_label(self):
        from main import ChatRequest, chat
        from types import SimpleNamespace
        from unittest.mock import patch
        from sessions import store
        request = ChatRequest(message="hello", source_label="PUBLIC", route_mode="internal_only")
        fake_result = SimpleNamespace(
            answer="hello", route="internal", gate_decision="not_checked",
            fallback_reason=None, external_attempted=False, gate_latency_ms=0.0
        )
        with patch.dict("os.environ", {"BRANDAI_RUNNER_TOKEN": "runner-secret"}), \
             patch("main.run_assistant", return_value=fake_result):
            response = chat(request, x_experiment_token="runner-secret")
        self.assertEqual(response.turn_count, 1)
        self.assertEqual(store.get_security_label(response.session_id), SecurityLabel.PUBLIC)
        store.delete(response.session_id)

    def test_unlabelled_request_is_conservatively_unknown(self):
        from main import ChatRequest, chat
        from types import SimpleNamespace
        from unittest.mock import patch
        from sessions import store
        fake_result = SimpleNamespace(
            answer="hello", route="internal", gate_decision="not_checked",
            fallback_reason=None, external_attempted=False, gate_latency_ms=0.0
        )
        with patch("main.run_assistant", return_value=fake_result):
            response = chat(ChatRequest(message="hello", route_mode="internal_only"))
        self.assertEqual(store.get_security_label(response.session_id), SecurityLabel.UNKNOWN)
        store.delete(response.session_id)





class ExperimentControlAuthTests(unittest.TestCase):
    def test_unauthenticated_client_cannot_disable_gate(self):
        from fastapi import HTTPException
        from main import ChatRequest, chat
        request = ChatRequest(
            message="ordinary text",
            route_mode="external_candidate",
            gate_mode="none",
            relay_mode="passive",
        )
        with self.assertRaises(HTTPException) as ctx:
            chat(request)
        self.assertEqual(ctx.exception.status_code, 401)

if __name__ == "__main__":
    unittest.main()
