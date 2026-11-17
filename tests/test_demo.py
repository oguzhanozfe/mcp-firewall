import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class DemoTest(unittest.TestCase):
    def test_replay_demo_gets_every_expected_decision(self):
        r = subprocess.run([sys.executable, "-m", "mcp_firewall", "demo", "--replay"], cwd=ROOT,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("mode: replay (recorded gemini-3.1-flash-lite", r.stdout)
        self.assertNotIn("classifier_error", r.stdout)  # every result has a recorded verdict
        self.assertEqual(r.stdout.count("\nok "), 7)
