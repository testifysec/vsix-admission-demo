"""Merge witness policies: steps and public keys from each, earliest expiry.

Each step binds to the VSIX digest on its own, so no cross-step edges are needed.
usage: python3 -I merge_policies.py out.json a.json b.json ...
"""
import json
import sys

out, *ins = sys.argv[1:]
merged = {"steps": {}, "publickeys": {}}
for path in ins:
    p = json.load(open(path))
    merged["steps"].update(p["steps"])
    merged["publickeys"].update(p.get("publickeys") or {})
    for k, v in p.items():
        if k not in ("steps", "publickeys", "expires"):
            merged.setdefault(k, v)
    if "expires" not in merged or p["expires"] < merged["expires"]:
        merged["expires"] = p["expires"]
json.dump(merged, open(out, "w"), indent=2)
