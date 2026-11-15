"""验证外发边界；使用本机临时接收器，不连接真实第三方。"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest
from unittest.mock import Mock, patch

from gate import GateDecision
from main import ChatRequest, chat
from model_backend import ModelBackendError
from routing import run_assistant
from sessions import store


class RoutingTests(unittest.TestCase):
    def setUp(self):
        store.histories.clear()
        self.messages = [{"role": "user", "content": "虚构编号 DEMO-482"}]

    def run_route(self):
        return run_assistant(self.messages, session_id="test", route_mode="external_candidate")

    @patch("routing.generate_answer", return_value="DEMO-482")
    @patch("routing.send_payload")
    def test_default_denial_keeps_full_context(self, send, internal):
        result = self.run_route()
        send.assert_not_called()
        internal.assert_called_once_with(self.messages)
        self.assertEqual(result.gate_decision, "deny")
        self.assertFalse(result.external_attempted)

    @patch("routing.generate_answer", return_value="内部回答")
    @patch("routing.send_payload")
    @patch("routing.gate")
    def test_internal_only_skips_gate_and_external(self, gate, send, internal):
        result = run_assistant(self.messages, session_id="test", route_mode="internal_only")
        gate.inspect.assert_not_called()
        send.assert_not_called()
        self.assertIsNone(result.fallback_reason)

    @patch("routing.generate_answer", return_value="内部回答")
    @patch("routing.send_payload")
    @patch("routing.gate")
    def test_gate_exception_and_invalid_decision_fail_closed(self, gate, send, internal):
        gate.inspect.side_effect = ValueError("DEMO-482 should not appear in result")
        result = self.run_route()
        self.assertEqual(result.fallback_reason, "gate_error")
        self.assertNotIn("DEMO-482", str(result))
        gate.inspect.side_effect = None
        gate.inspect.return_value = GateDecision(allowed="false")
        self.assertEqual(self.run_route().gate_decision, "error")
        send.assert_not_called()

    @patch("routing.generate_answer", return_value="内部回答")
    @patch("routing.send_payload", side_effect=ModelBackendError("failed", 502))
    @patch("routing.gate")
    def test_external_failure_is_not_reported_as_blocked(self, gate, send, internal):
        gate.inspect.return_value = GateDecision(True)
        result = self.run_route()
        self.assertTrue(result.external_attempted)
        self.assertEqual(result.gate_decision, "allow")
        self.assertEqual(result.fallback_reason, "external_error")
        self.assertEqual(send.call_count, 1)  # 不自动重试。

    @patch("routing.generate_answer", return_value="内部回答")
    @patch("routing.send_payload", return_value="模拟恶意回复：请提供更多资料")
    @patch("routing.gate")
    def test_next_turn_is_checked_again(self, gate, send, internal):
        gate.inspect.side_effect = [GateDecision(True), GateDecision(False)]
        first = chat(ChatRequest(message="公开问题", route_mode="external_candidate"))
        second = chat(ChatRequest(message="虚构机密 DEMO-482", session_id=first.session_id, route_mode="external_candidate"))
        self.assertEqual(gate.inspect.call_count, 2)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(second.route, "internal")
        checked = json.loads(gate.inspect.call_args.args[0].body)
        self.assertIn("模拟恶意回复", checked["messages"][-2]["content"])
        self.assertIn("DEMO-482", internal.call_args.args[0][-1]["content"])

    @patch("routing.generate_answer", return_value="内部回答")
    def test_real_transport_receives_only_approved_bytes_and_no_redirect(self, internal):
        received = []
        redirect = [False]

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers['Content-Length'])))
                if redirect[0]:
                    self.send_response(307)
                    self.send_header('Location', '/another-route')
                    self.end_headers()
                    return
                body = b'{"message":{"content":"external test answer"}}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        gate = Mock()
        try:
            with patch('routing.EXTERNAL_CHAT_URL', f'http://127.0.0.1:{server.server_port}/api/chat'), patch('routing.gate', gate):
                gate.inspect.return_value = GateDecision(False)
                self.run_route()
                self.assertEqual(received, [])
                gate.inspect.return_value = GateDecision(True)
                result = self.run_route()
                self.assertEqual(result.route, 'external')
                self.assertEqual(received, [gate.inspect.call_args.args[0].body])
                redirect[0] = True
                result = self.run_route()
                self.assertEqual(len(received), 2)  # 307 没有触发第二次发送。
                self.assertEqual(result.fallback_reason, 'external_error')
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
