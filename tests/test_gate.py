"""Real cloud rows, loopback mock transport, real CLI exit/summary checks."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import security_gate as gate

PASS = json.loads((ROOT / 'tests/fixtures/pass.json').read_text())
FAIL = json.loads((ROOT / 'tests/fixtures/fail.json').read_text())


class GateTests(unittest.TestCase):
    def invoke(self, rows, urls, minimum='B', required=None, http_status=200, config_override=None):
        received = []

        class Mock(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.path, self.headers.get('Authorization'), json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                self.send_response(http_status)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(rows).encode())

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Mock)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as folder:
                config = Path(folder) / 'config.yml'
                summary = Path(folder) / 'summary.md'
                config.write_text(yaml.safe_dump(config_override or {'urls': urls, 'minimum_grade': minimum, 'required_headers': required or []}))
                result = subprocess.run([sys.executable, str(ROOT / 'security_gate.py'), '--config', str(config), '--api-base', f'http://127.0.0.1:{server.server_port}/v2'],
                                        env={**os.environ, 'APIFY_TOKEN': 'offline-mock-only', 'GITHUB_STEP_SUMMARY': str(summary)}, capture_output=True, text=True, timeout=10)
                text = summary.read_text()
                self.assertEqual(result.stdout.strip(), text.strip())
                self.assertNotIn('offline-mock-only', text + result.stderr)
                if received:
                    path, auth, payload = received[0]
                    self.assertEqual(len(received), 1)
                    self.assertTrue(path.startswith('/v2/acts/hiver~website-security-headers-audit/run-sync-get-dataset-items?'))
                    self.assertIn('maxTotalChargeUsd=0.05', path)
                    self.assertNotIn('offline-mock-only', path)
                    self.assertEqual(auth, 'Bearer offline-mock-only')
                    self.assertEqual(payload['urls'], urls)
                return result.returncode, text
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_real_passing_fixture(self):
        code, text = self.invoke([PASS], [PASS['input']], required=['content-security-policy', 'Strict-Transport-Security'])
        self.assertEqual(code, 0)
        self.assertIn('| B | None | PASS |', text)
        print('REAL FIXTURE BBC/B minimum B + CSP/HSTS: exit 0 PASS')

    def test_real_failing_grade(self):
        code, text = self.invoke([FAIL], [FAIL['input']])
        self.assertEqual(code, 1)
        self.assertIn('| F | None | FAIL |', text)
        print('REAL FIXTURE Wikipedia/F minimum B: exit 1 FAIL')

    def test_missing_header_alone(self):
        code, text = self.invoke([FAIL], [FAIL['input']], minimum='F', required=['content-security-policy'])
        self.assertEqual(code, 1)
        self.assertIn('content-security-policy | FAIL', text)
        print('REAL FIXTURE Wikipedia/F minimum F + required CSP: exit 1 FAIL')

    def test_grade_equal_no_headers(self):
        self.assertEqual(self.invoke([FAIL], [FAIL['input']], minimum='F')[0], 0)

    def test_every_grade_floor(self):
        for row in [PASS, FAIL]:
            for minimum in gate.GRADES:
                for headers in [[], ['content-security-policy'], ['strict-transport-security']]:
                    with self.subTest(input=row['input'], minimum=minimum, required=headers):
                        code, _ = self.invoke([row], [row['input']], minimum, headers)
                        expected = gate.GRADES[row['grade']] < gate.GRADES[minimum] or any(not row['headers'][h]['present'] for h in headers)
                        self.assertEqual(code, int(expected))

    def test_multi_url_out_of_order(self):
        code, text = self.invoke([FAIL, PASS], [PASS['input'], FAIL['input']])
        self.assertEqual(code, 1)
        self.assertIn('PASS', text)
        self.assertIn('FAIL', text)
        self.assertLess(text.index(PASS['input']), text.index(FAIL['input']))

    def test_bad_datasets(self):
        failed = {**PASS, 'success': False, 'error': 'offline failure'}
        for rows in [[], [PASS, PASS], [FAIL], [failed], [{**PASS, 'grade': 'E'}], {'error': 'bad shape'}]:
            with self.subTest(rows=rows):
                self.assertEqual(self.invoke(rows, [PASS['input']])[0], 2)

    def test_api_failure(self):
        self.assertEqual(self.invoke({'error': 'unauthorized'}, [PASS['input']], http_status=401)[0], 2)

    def test_invalid_config_never_calls_api(self):
        for config in [{'urls': [], 'minimum_grade': 'B'}, {'urls': ['https://example.com/path']}, {'urls': ['https://example.com', 'https://example.com/']}, {'urls': ['https://example.com'], 'minimum_grade': 'E'}, {'urls': ['https://example.com'], 'required_headers': ['typo']}]:
            with self.subTest(config=config):
                self.assertEqual(self.invoke([], [], config_override=config)[0], 2)

    def test_csp_framing_not_actual_xfo(self):
        row = copy.deepcopy(PASS)
        row['headers']['x-frame-options']['value'] = None
        self.assertFalse(gate.evaluate([row['input']], 'F', ['x-frame-options'], [row])[0][3])

    def test_remote_api_override_rejected(self):
        with self.assertRaises(ValueError):
            gate.run_audit(['https://example.com'], 'offline-mock-only', 'https://example.com/v2')


if __name__ == '__main__':
    unittest.main()
