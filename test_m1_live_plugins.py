"""Real Presidio + detect-secrets regression using only synthetic task data."""

import json
import unittest
from pathlib import Path

from model_backend import build_payload
from security_gateway.detection import HybridPayloadScanner, DetectionUnavailable

ROOT = Path(__file__).resolve().parent


class RealM1DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scanner = HybridPayloadScanner()
        try:
            cls.scanner._initialise()
        except DetectionUnavailable as exc:
            raise unittest.SkipTest(f"Real detector prerequisites unavailable: {exc}")
        task_path = ROOT / 'data/generated/tasks.jsonl'
        if not task_path.exists():
            raise unittest.SkipTest('Generate fixed benchmark first: python -m taskset.build')
        cls.tasks = {t['task_id']: t for t in
            (json.loads(line) for line in task_path.read_text(encoding='utf-8').splitlines() if line)}

    def scan_task(self, task_id):
        task = self.tasks[task_id]
        messages = [{'role': 'user', 'content': turn['content']} for turn in task['turns']]
        r = self.scanner.scan(build_payload(messages))
        self.assertTrue(r.inspection_complete, r.error_code)
        return r

    def test_public_docs_and_template_allow(self):
        for name in ('P-apidoc-question', 'P-placeholder-debug'):
            with self.subTest(name=name):
                self.assertFalse(self.scan_task(name).has_sensitive_data)

    def test_formatted_secret_detected(self):
        self.assertTrue(self.scan_task('C-cred-verbatim-question').has_sensitive_data)

    def test_base64_and_spaced_variants_detected(self):
        # Fixed task generator alternates base64 on even template indices,
        # spaced characters on odd indices.
        base64_findings = self.scan_task('C-cred-encoded-debug').findings
        spaced_findings = self.scan_task('C-cred-encoded-summarise').findings
        self.assertTrue(any(f.source_variant == 'base64_decoded' for f in base64_findings))
        self.assertTrue(any(f.source_variant == 'spaced_compact' for f in spaced_findings))


if __name__ == '__main__':
    unittest.main()
