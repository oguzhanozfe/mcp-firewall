"""End-to-end: real proxy process wrapping the fake server over stdio."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE = ROOT / "tests" / "fake_server.py"
FAKE_TOKEN = "gh" + "p_" + "A" * 36
FAKE_KEY = "sk-" + "ant-" + "b" * 30

POLICY = {
    "tools": {"deny": ["delete_*"]},
    "per_tool": {
        "read_file": {"args": {"path": {"path_prefix": ["/work"]}}},
        "echo": {"rate_limit": {"calls": 3, "per_seconds": 60}},
    },
    "injection": {"action": "annotate"},
}


class Proxy:
    def __init__(self, policy):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        (d / "policy.json").write_text(json.dumps(policy))
        self.audit_path = d / "audit.jsonl"
        self.p = subprocess.Popen(
            [sys.executable, "-m", "mcp_firewall", "--policy", str(d / "policy.json"),
             "--audit", str(self.audit_path), "--", sys.executable, str(FAKE)],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.next_id = 0

    def send(self, msg):
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()

    def request(self, method, params=None):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        while True:  # skip notifications
            msg = json.loads(self.p.stdout.readline())
            if msg.get("id") == self.next_id:
                return msg

    def call(self, tool, **args):
        return self.request("tools/call", {"name": tool, "arguments": args})["result"]

    def close(self):
        self.p.stdin.close()
        code = self.p.wait(timeout=10)
        self.p.stdout.close()
        audit = [json.loads(l) for l in self.audit_path.read_text().splitlines()]
        self.dir.cleanup()
        return code, audit


class ProxyTest(unittest.TestCase):
    def setUp(self):
        self.px = Proxy(POLICY)

    def tearDown(self):
        if self.px.p.poll() is None:
            self.px.close()

    def test_handshakes_pass_through(self):
        self.assertEqual(self.px.request("initialize", {"protocolVersion": "2025-11-25"})["result"]["serverInfo"]["name"], "fake")
        self.assertIn("supportedVersions", self.px.request("server/discover")["result"])
        self.assertEqual(self.px.request("nope")["error"]["code"], -32601)

    def test_tools_list_hides_denied_tools(self):
        names = [t["name"] for t in self.px.request("tools/list")["result"]["tools"]]
        self.assertNotIn("delete_everything", names)
        self.assertIn("echo", names)

    def test_denied_tool_never_reaches_upstream(self):
        r = self.px.call("delete_everything")
        self.assertTrue(r["isError"])
        self.assertEqual(r["resultType"], "complete")
        self.assertIn("not allowed", r["content"][0]["text"])
        _, audit = self.px.close()
        self.assertEqual([e["decision"] for e in audit if e.get("tool") == "delete_everything"], ["deny"])

    def test_path_traversal_denied(self):
        self.assertIn("contents of /work/a.txt", self.px.call("read_file", path="/work/a.txt")["content"][0]["text"])
        self.assertTrue(self.px.call("read_file", path="/work/../etc/passwd")["isError"])
        self.assertTrue(self.px.call("read_file", path="/workshop/x")["isError"])

    def test_rate_limit(self):
        results = [self.px.call("echo", n=i) for i in range(4)]
        self.assertEqual([bool(r.get("isError")) for r in results], [False, False, False, True])

    def test_redaction_both_directions(self):
        # outbound: the fake server echoes what it received, so we see what upstream got
        r = self.px.call("echo", note=f"use key {FAKE_KEY}", password="hunter2hunter2")
        got = r["structuredContent"]
        self.assertNotIn(FAKE_KEY, json.dumps(r))
        self.assertIn("[REDACTED:openai_or_anthropic_key]", got["note"])
        self.assertEqual(got["password"], "hunter2hunter2")  # plain value; only key=value text shapes match
        # inbound
        text = self.px.call("leaky")["content"][0]["text"]
        self.assertNotIn(FAKE_TOKEN, text)
        self.assertIn("token=[REDACTED", text)
        _, audit = self.px.close()
        self.assertNotIn(FAKE_KEY, json.dumps(audit))
        self.assertNotIn(FAKE_TOKEN, json.dumps(audit))

    def test_injection_annotated(self):
        content = self.px.call("web_fetch")["content"]
        self.assertTrue(content[0]["text"].startswith("[mcp-firewall] Warning"))
        self.assertIn("ignore all previous", content[1]["text"])
        _, audit = self.px.close()
        ev = [e for e in audit if e.get("tool") == "web_fetch" and e["dir"] == "response"][0]
        self.assertEqual(ev["decision"], "annotate")
        self.assertIn("override", ev["injection"]["rules"])

    def test_garbage_line_dropped_and_upstream_exit_code_propagates(self):
        self.px.p.stdin.write("this is not json\n")
        self.px.send({"jsonrpc": "2.0", "id": 99, "method": "exit"})
        code, audit = self.px.close()
        self.assertEqual(code, 3)
        self.assertTrue(any(e["decision"] == "drop" for e in audit))


class ProxyStripBlockTest(unittest.TestCase):
    def run_action(self, action):
        px = Proxy({**POLICY, "injection": {"action": action}})
        try:
            return px.call("web_fetch")
        finally:
            px.close()

    def test_strip(self):
        r = self.run_action("strip")
        self.assertNotIn("ignore all previous", json.dumps(r))
        self.assertIn("removed by mcp-firewall", r["content"][1]["text"])

    def test_block(self):
        r = self.run_action("block")
        self.assertTrue(r["isError"])
        self.assertEqual(len(r["content"]), 1)

    def test_flag_leaves_result_alone(self):
        r = self.run_action("flag")
        self.assertEqual(len(r["content"]), 1)


if __name__ == "__main__":
    unittest.main()
