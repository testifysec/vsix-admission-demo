"""Print what a detonation bundle's trace saw: processes, files touched, connections.

usage: python3 -I show_trace.py detonate.bundle.json
"""
import base64
import json
import sys

env = json.load(open(sys.argv[1]))
payload = json.loads(base64.b64decode(env["payload"]))
for att in payload["predicate"]["attestations"]:
    if "command-run" not in att["type"]:
        continue
    a = att["attestation"]
    print("command-run keys:", sorted(a.keys()))
    for p in a.get("processes", []):
        print(f"\nprocess {p.get('processid')} {p.get('program') or p.get('comm')}")
        for path in sorted(p.get("openedfiles", {}) or {}):
            if "/.ssh" in path or "/home/victim" in path:
                print("  opened ", path)
        ops = p.get("fileOps") or {}
        for w in ops.get("writes", []) or []:
            print("  wrote  ", w.get("path"), w.get("bytes"))
        net = p.get("network") or {}
        for c in net.get("connections", []) or []:
            print("  connect", c.get("syscall"), c.get("address"), c.get("port"))
