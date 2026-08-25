#!/usr/bin/env python3
"""Dump encoded keystroke programs as JSON. Used by test/keymap_test.js to
check that the Python and JavaScript encoders cannot drift apart."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaplib import encode_program

req = json.loads(sys.argv[1])
out = {}
for lay in req["layouts"]:
    out[lay] = {s: encode_program(s, lay)[0].hex() for s in req["samples"]}
print(json.dumps(out))
