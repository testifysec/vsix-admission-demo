"""Attach a rego module to a step's command-run attestation in a witness policy.

usage: python3 -I add_rego.py policy.json step module.rego name
"""
import base64
import json
import sys

path, step, rego, name = sys.argv[1:5]
policy = json.load(open(path))
module = base64.b64encode(open(rego, "rb").read()).decode()
for att in policy["steps"][step]["attestations"]:
    if "command-run" in att["type"]:
        att["regopolicies"] = (att.get("regopolicies") or []) + [{"name": name, "module": module}]
json.dump(policy, open(path, "w"), indent=2)
