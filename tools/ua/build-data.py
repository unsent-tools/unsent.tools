#!/usr/bin/env python3
"""Generate data.js from uap-core's regexes.yaml.

Source: https://github.com/ua-parser/uap-core (Apache License 2.0,
Copyright 2009 Google Inc.) — this file pins the commit it was built from
in the generated header. Local copy expected at
~/workspace/devtools/uap-core/regexes.yaml (fetch with:
  curl -sfLO https://raw.githubusercontent.com/ua-parser/uap-core/<commit>/regexes.yaml
).

Output keys are shortened to keep the shipped file small:
  ua rules:     r (regex), f (family_replacement), v1..v4 (v*_replacement)
  os rules:     r, f (os_replacement), v1..v4 (os_v*_replacement)
  device rules: r, i (regex_flag 'i' present), f (device_replacement),
                b (brand_replacement), m (model_replacement)
Only keys present in the YAML rule are emitted.

Usage: python3 build-data.py [path/to/regexes.yaml] [commit-sha] > /dev/null
       (writes data.js next to itself)
"""
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
    "~/workspace/devtools/uap-core/regexes.yaml")
COMMIT = sys.argv[2] if len(sys.argv) > 2 else "unknown"

with open(SRC, encoding="utf-8") as f:
    data = yaml.safe_load(f)

MAPS = {
    "user_agent_parsers": [("family_replacement", "f"), ("v1_replacement", "v1"),
                           ("v2_replacement", "v2"), ("v3_replacement", "v3"),
                           ("v4_replacement", "v4")],
    "os_parsers": [("os_replacement", "f"), ("os_v1_replacement", "v1"),
                   ("os_v2_replacement", "v2"), ("os_v3_replacement", "v3"),
                   ("os_v4_replacement", "v4")],
    "device_parsers": [("device_replacement", "f"), ("brand_replacement", "b"),
                       ("model_replacement", "m")],
}

out = {}
for section, keymap in MAPS.items():
    rules = []
    for rule in data[section]:
        r = {"r": rule["regex"]}
        if rule.get("regex_flag") == "i":
            r["i"] = 1
        for src_key, dst_key in keymap:
            if src_key in rule:
                r[dst_key] = rule[src_key]
        rules.append(r)
    out[section] = rules

body = ",\n".join(
    f'  "{k}": [\n' + ",\n".join("    " + json.dumps(r, ensure_ascii=False)
                                 for r in v) + "\n  ]"
    for k, v in out.items())

with open(os.path.join(HERE, "data.js"), "w", encoding="utf-8") as f:
    f.write(f"""\
// GENERATED FILE — do not edit; regenerate with build-data.py.
// Detection data from uap-core regexes.yaml, commit {COMMIT}.
// https://github.com/ua-parser/uap-core
// Licensed under the Apache License, Version 2.0; Copyright 2009 Google Inc.
// See UAP-CORE-LICENSE in this directory. The rest of this project is MIT;
// this data file remains Apache-2.0.
export default {{
{body}
}};
""")

counts = {k: len(v) for k, v in out.items()}
print(f"data.js written: {counts}", file=sys.stderr)
