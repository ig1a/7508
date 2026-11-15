"""无须加载模型，检查输入校验和模型错误处理。"""

import io
import unittest
from unittest.mock import patch
from urllib.error import URLError

from fastapi import HTTPException
from pydantic import ValidationError

from main import ChatRequest, chat, reset_session
from model_backend import ModelBackendError, generate_answer
from sessions import store


class BackendTests(unittest.TestCase):
    def setUp(self):
        store.histories.clear()

    def test_blank_input_rejected(self):
        with self.assertRaises(ValidationError):
            ChatRequest(message="   ")

    @patch("model_backend.build_opener")
    def test_local_request_and_answer(self, build):
        build.return_value.open.return_value = io.BytesIO(
            b'{"message":{"content":"hello"}}'
        )
        self.assertEqual(generate_answer("hello"), "hello")
        request = build.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/chat")

    @patch("model_backend.build_opener")
    def test_connection_failure_is_503(self, build):
        build.return_value.open.side_effect = URLError("offline")
        with self.assertRaises(ModelBackendError) as caught:
            generate_answer("hello")
        self.assertEqual(caught.exception.status_code, 503)

    @patch("model_backend.build_opener")
    def test_invalid_response_is_502(self, build):
        build.return_value.open.return_value = io.BytesIO(b'{}')
        with self.assertRaises(ModelBackendError) as caught:
            generate_answer("hello")
        self.assertEqual(caught.exception.status_code, 502)

    @patch("routing.generate_answer", side_effect=ModelBackendError("timeout", 504))
    def test_api_preserves_error_status(self, generate):
        with self.assertRaises(HTTPException) as caught:
            chat(ChatRequest(message="hello"))
        self.assertEqual(caught.exception.status_code, 504)
        self.assertEqual(store.histories, {})

    @patch("routing.generate_answer", return_value="收到")
    def test_history_is_sent_only_to_same_session(self, generate):
        first = chat(ChatRequest(message="编号 DEMO-482"))
        chat(ChatRequest(message="编号是什么？", session_id=first.session_id))
        messages = generate.call_args.args[0]
        self.assertEqual([m["role"] for m in messages], ["user", "assistant", "user"])
        self.assertIn("DEMO-482", messages[0]["content"])
        other = chat(ChatRequest(message="编号是什么？"))
        self.assertNotEqual(other.session_id, first.session_id)
        self.assertEqual(len(generate.call_args.args[0]), 1)

    @patch("routing.generate_answer", return_value="收到")
    def test_reset_does_not_delete_other_session(self, generate):
        first = chat(ChatRequest(message="A"))
        second = chat(ChatRequest(message="B"))
        reset_session(first.session_id)
        self.assertNotIn(first.session_id, store.histories)
        self.assertIn(second.session_id, store.histories)
        with self.assertRaises(HTTPException) as caught:
            chat(ChatRequest(message="继续", session_id=first.session_id))
        self.assertEqual(caught.exception.status_code, 404)

    @patch("routing.generate_answer", return_value="收到")
    def test_failed_turn_does_not_modify_history(self, generate):
        first = chat(ChatRequest(message="A"))
        before = list(store.histories[first.session_id])
        generate.side_effect = ModelBackendError("offline", 503)
        with self.assertRaises(HTTPException):
            chat(ChatRequest(message="B", session_id=first.session_id))
        self.assertEqual(store.histories[first.session_id], before)

    @patch("routing.generate_answer", return_value="收到")
    def test_fifth_turn_rejected_without_model_call(self, generate):
        first = chat(ChatRequest(message="A"))
        for _ in range(3):
            chat(ChatRequest(message="B", session_id=first.session_id))
        with self.assertRaises(HTTPException) as caught:
            chat(ChatRequest(message="C", session_id=first.session_id))
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(generate.call_count, 4)

    @patch("routing.generate_answer", return_value="收到")
    def test_context_limit_preserves_history(self, generate):
        first = chat(ChatRequest(message="中" * 2000))
        with self.assertRaises(HTTPException) as caught:
            chat(ChatRequest(message="文" * 2000, session_id=first.session_id))
        self.assertEqual(caught.exception.status_code, 413)
        self.assertEqual(len(store.histories[first.session_id]), 2)
        self.assertEqual(generate.call_count, 1)


if __name__ == "__main__":
    unittest.main()
