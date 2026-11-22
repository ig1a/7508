"""Real HTTP integration; only model inference is replaced by a local stand-in."""
from contextlib import ExitStack, contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from integration_stack import local_stack
from model_backend import build_payload, send_payload
from provider import make_provider
from runner import leakscan
from runner.run import Client, run_trial
from scripts.integration_smoke import INJECTION, task, read_jsonl
from sessions import store
from taskset.build import build as build_taskset


@contextmanager
def model_server():
    received = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            received.append({"path": self.path, "body": raw, "headers": dict(self.headers)})
            response = b'{"message":{"content":"4 DEMO-482"}}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/api/chat", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class IntegratedHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store.histories.clear()
        store.security_labels.clear()
        cls.resources = ExitStack()
        cls.addClassCleanup(cls.resources.close)
        root = Path(cls.resources.enter_context(tempfile.TemporaryDirectory()))
        internal, cls.internal_requests = cls.resources.enter_context(model_server())
        external, cls.external_requests = cls.resources.enter_context(model_server())
        cls.stack = cls.resources.enter_context(local_stack(root / "stack", internal_url=internal,
                                                            external_url=external, append_text=INJECTION["text"]))
        cls.client = Client(cls.stack.url, 15, token=cls.stack.token)

    def rows(self, recipient, trial):
        return [r for r in read_jsonl(self.stack.output / f"{recipient}.jsonl") if r.get("trial_id") == trial]

    def test_m2_sticky_denial_never_reaches_relay_or_provider(self):
        record = run_trial(self.client, task("sticky", private=True), "C1-M2", 1, [INJECTION])
        self.assertEqual(record["status"], "ok")
        self.assertEqual([t["route"] for t in record["turns"]], ["internal", "internal"])
        self.assertEqual(self.rows("relay", record["trial_id"]), [])
        self.assertEqual(self.rows("provider", record["trial_id"]), [])
        self.assertEqual([r["session_label"] for r in self.rows("gate", record["trial_id"])], ["CONFIDENTIAL"] * 2)
        self.assertFalse(store.histories)
        self.assertFalse(store.security_labels)

    def test_active_compliance_rechecks_gate_and_logs_only_public_turn(self):
        record = run_trial(self.client, task("active", compliance=True), "C2-M2", 1, [INJECTION])
        self.assertEqual(record["status"], "ok")
        self.assertTrue(record["compliance_sent"])
        self.assertEqual([t["route"] for t in record["turns"]], ["external", "internal"])
        relay = self.rows("relay", record["trial_id"])
        provider = self.rows("provider", record["trial_id"])
        self.assertEqual(len(relay), 1)
        self.assertEqual(len(provider), 1)
        self.assertTrue(relay[0]["rewrite"]["applied"])
        self.assertEqual(relay[0]["request"]["body"], provider[0]["request"]["body"])

    def test_per_request_relay_mode_and_run_identity_do_not_bleed(self):
        for mode in ("C2-none", "C1-none", "C2-none"):
            for run in (1, 2, 3, 4):
                record = run_trial(self.client, task("same-opening"), mode, run, [INJECTION])
                self.assertEqual(record["status"], "ok")
                row = self.rows("relay", record["trial_id"])[-1]
                self.assertEqual(row["rewrite"]["applied"], mode == "C2-none")

    def test_task_set_trials_are_scored_by_part_c_extractor(self):
        built = build_taskset()
        task_spec = next(t for t in built["tasks"] if t["task_id"] == "C-cred-verbatim-debug")
        primary = next(c for c in built["canaries"] if c["task_id"] == task_spec["task_id"] and c["role"] == "primary")
        records = [run_trial(self.client, task_spec, config, 1, [INJECTION]) for config in ("C1-none", "C1-M1_M2")]
        self.assertEqual([r["status"] for r in records], ["ok", "ok"])
        with tempfile.TemporaryDirectory() as directory:
            canaries = Path(directory) / "canaries.jsonl"
            canaries.write_text("".join(json.dumps(c) + "\n" for c in built["canaries"]), encoding="utf-8")
            logs = {r: self.stack.output / f"{r}.jsonl" for r in ("relay", "provider")}
            with patch.object(leakscan, "CANARIES", canaries):
                summary = leakscan.scan_batch(records, Path(directory) / "batch.jsonl", logs)
        by_trial = {t["task_id"]: t for t in summary["tasks"]}
        for recipient in ("relay", "provider"):
            self.assertEqual(by_trial["C1-none:C-cred-verbatim-debug:r1"]["first_hits"][recipient], {primary["canary_id"]: 1})
            self.assertEqual(by_trial["C1-M1_M2:C-cred-verbatim-debug:r1"][f"{recipient}_leaked"], 0)
        self.assertEqual(summary["log_lines"], {"relay": 2, "provider": 2})
        self.assertEqual(summary["tasks_missing_from_manifest"], [])

    def test_checked_request_bytes_reach_independent_provider_without_auth_token(self):
        trial = "C1-none:bytes:r1"
        status, result = self.client.call("POST", "/chat", {
            "message": "Public payload", "source_label": "PUBLIC", "gate_mode": "none",
            "relay_mode": "passive", "route_mode": "external_candidate"}, trial)
        self.assertEqual(status, 200)
        try:
            raw = build_payload([{"role": "user", "content": "Public payload"}])
            provider = self.rows("provider", trial)[0]
            self.assertEqual(provider["request"]["body_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(self.external_requests[-1]["path"], "/api/chat")
            self.assertEqual(self.external_requests[-1]["body"], raw)
            self.assertNotIn(self.stack.token, json.dumps(self.rows("relay", trial)))
            self.assertNotIn(self.stack.token, json.dumps(provider))
        finally:
            self.client.call("DELETE", "/sessions/" + result["session_id"])

    def test_untrusted_control_request_does_not_create_session_or_send(self):
        before = len(self.external_requests)
        untrusted = Client(self.stack.url, 10, token="wrong")
        status, _ = untrusted.call("POST", "/chat", {"message": "hello", "gate_mode": "none"})
        self.assertEqual(status, 401)
        self.assertEqual(len(self.external_requests), before)
        self.assertFalse(store.histories)

    def test_runner_rejects_old_backend_without_configuration_acknowledgement(self):
        with patch.object(self.client, "call") as call:
            call.side_effect = [(200, {"session_id": "old", "answer": "4"}), (200, {"status": "reset"})]
            record = run_trial(self.client, task("old"), "C1-M2", 1, [INJECTION])
            self.assertEqual(record["status"], "error")
            self.assertIsNone(record["task_completed"])
            self.assertEqual(call.call_args.args[:2], ("DELETE", "/sessions/old"))


class ProviderBoundaryTests(unittest.TestCase):
    def test_refuses_internal_endpoint_even_with_loopback_alias(self):
        with patch.dict("os.environ", {"BRANDAI_INTERNAL_URL": "http://127.0.0.1:11434/api/chat"}):
            with self.assertRaises(ValueError):
                make_provider(upstream="http://localhost:11434/api/chat", port=0)

    def test_ingress_is_recorded_before_external_model_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            # Bind but do not listen: deterministic unreachable model endpoint.
            import socket
            with socket.socket() as closed:
                closed.bind(("127.0.0.1", 0))
                upstream = f"http://127.0.0.1:{closed.getsockname()[1]}/api/chat"
                server = make_provider(upstream=upstream, port=0, log_path=Path(directory) / "ingress.jsonl", timeout=1)
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    from model_backend import ModelBackendError
                    with self.assertRaises(ModelBackendError):
                        send_payload(f"http://127.0.0.1:{server.server_port}/api/chat", build_payload("synthetic"))
                    self.assertEqual(len(read_jsonl(Path(directory) / "ingress.jsonl")), 1)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
