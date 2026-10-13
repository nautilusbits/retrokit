"""Tests of the MCP server on a synthetic workspace (no Ghidra, no game data).

    python -m unittest discover -s tests
"""
import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
sys.path.insert(0, KIT)

from retrokit import mcp_server, workspace  # noqa: E402

C = """// ==================================================================
// main @ 00010000  size=16  callers=0  callees=1
// ==================================================================

int main(void)
{
  FUN_00010010("hello");
  return 0;
}

// ==================================================================
// FUN_00010010 @ 00010010  size=8  callers=1  callees=0
// ==================================================================

void FUN_00010010(char *param_1)
{
  puts(param_1);
}
"""


def make_workspace(root):
    ws = {"dir": root, "exe": os.path.join(root, "missing.exe"), "format": "LE", "pipeline": "le",
          "cname": "x_decompiled.c", "loader": "LinearExecutableLoader", "cspec": "watcom"}
    workspace.save(ws)
    d = os.path.join(root, "decomp")
    os.makedirs(d)
    with open(os.path.join(d, "functions.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["addr", "name", "size", "callers", "callees", "cc", "signature"])
        w.writerow(["00010000", "main", 16, 0, 1, "__watcall", "int main(void)"])
        w.writerow(["00010010", "FUN_00010010", 8, 1, 0, "__watcall", "void FUN_00010010(char * param_1)"])
    with open(os.path.join(d, "calls.txt"), "w") as fh:
        fh.write("00010000 main -> 00010010 FUN_00010010\n")
    with open(os.path.join(d, "fixups.txt"), "w") as fh:
        fh.write("00010004\t00020000\t7\tDATA\tmain\t\"hello\"\n")
        for i, t in enumerate(["00010000", "00010010", "00010010"]):
            fh.write("%08x\t%s\t7\tFUNC\t-\tx\n" % (0x20100 + 4 * i, t))
    with open(os.path.join(d, "strings.txt"), "w") as fh:
        fh.write("00020000\tstring\thello\n")
    with open(os.path.join(d, "data_symbols.txt"), "w") as fh:
        fh.write("00020100\thandlers\tpointer[3]\t1 refs\n")
    with open(os.path.join(d, "x_decompiled.c"), "w") as fh:
        fh.write(C)


class TestServer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "game_analysis")
        os.makedirs(self.root)
        make_workspace(self.root)
        self.server = mcp_server.Server([self.root])

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, tool, **args):
        r = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": tool, "arguments": args}})
        res = r["result"]
        return res["isError"], res["content"][0]["text"]

    def test_protocol(self):
        r = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(r["result"]["serverInfo"]["name"], "retrokit")
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        self.assertIn("get_function", [t["name"] for t in tools])
        for t in tools:
            self.assertEqual(t["inputSchema"]["type"], "object")
        self.assertEqual(self.server.handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})["error"]["code"], -32601)

    def test_read_tools(self):
        err, text = self.call("get_function", functions=["FUN_00010010"])
        self.assertFalse(err)
        self.assertIn("puts(param_1)", text)
        self.assertNotIn("int main", text)
        self.assertIn("callers (1): main", text)
        err, text = self.call("list_functions", which="unnamed")
        self.assertIn("1 functions match", text)
        err, text = self.call("xrefs", address="0x20000")
        self.assertIn("in main", text)
        err, text = self.call("strings", pattern="hel")
        self.assertIn("main", text)
        err, text = self.call("pointer_tables")
        self.assertIn("table of function pointers: 3", text)
        err, text = self.call("call_graph", function="main", direction="callees")
        self.assertIn("FUN_00010010", text)
        err, text = self.call("search_code", regex=r"puts\(")
        self.assertIn("FUN_00010010:", text)
        err, text = self.call("get_function", functions=["nonsense name"])
        self.assertTrue(err)

    def test_proposals(self):
        err, text = self.call("propose_names", topic="text", names=[
            {"address": "10010", "name": "print_line", "confidence": "V", "comment": "puts wrapper"},
            {"address": "10000", "name": "bad name"},
            {"address": "FUN_00010010", "name": "FUN_00010010"}])
        self.assertIn("1 proposals written", text)
        self.assertIn("2 rejected", text)
        with open(os.path.join(self.root, "notes", "names_text.csv"), newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(rows, [{"addr": "00010010", "name": "print_line", "confidence": "V", "comment": "puts wrapper"}])
        self.call("propose_names", topic="text", names=[{"address": "10010", "name": "print_text"}])
        with open(os.path.join(self.root, "notes", "names_text.csv"), newline="") as fh:
            self.assertEqual([r["name"] for r in csv.DictReader(fh)], ["print_text"])     # replaced, not added
        err, text = self.call("propose_names", topic="sigs", names=[{"address": "10010", "name": "x"}])
        self.assertTrue(err)
        err, text = self.call("list_proposals")
        self.assertIn("print_text", text)

    def test_note_and_guarded_reexport(self):
        self.call("write_note", topic="formats", text="first")
        self.call("write_note", topic="formats", text="second")
        with open(os.path.join(self.root, "notes", "formats.md")) as fh:
            self.assertEqual(fh.read(), "first\n\nsecond\n")
        err, text = self.call("reexport", confirm=False)
        self.assertTrue(err)
        self.assertIn("confirm=true", text)

    def test_stdio(self):
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "workspace_info", "arguments": {}}}]
        r = subprocess.run([sys.executable, "-m", "retrokit", "mcp", self.root], cwd=KIT, capture_output=True,
                           input="".join(json.dumps(m) + "\n" for m in msgs), text=True, timeout=60)
        replies = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        self.assertEqual([x["id"] for x in replies], [1, 2])
        self.assertIn("functions: 2 (1 named, 1 unnamed)", replies[1]["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
