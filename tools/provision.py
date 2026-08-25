#!/usr/bin/env python3
"""Debug helper for the type-out slot.

In normal use you do NOT need this: a web page writes the text straight to the
device through WebAuthn's user.id field (see test/index.html). This tool exists
for bench work without a browser.

    tools/provision.py --text "literal string" --layout dk
    tools/provision.py --show                    # capacity and stored length
    tools/provision.py --clear

--layout matters: the device stores keystrokes, not characters, so the text has
to be mapped against the keyboard layout of the machine that will receive the
typing. Layout data comes from test/layouts.js (see tools/gen_layouts.py).
"""
import argparse, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaplib import Device, TYPEOUT_MAX, CTAPHID_TEXTINFO, encode_program, layout_ids

import struct


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--text", help="store this literal string")
    ap.add_argument("--layout", default="us",
                    help="keyboard layout to map the text against (default: us)")
    ap.add_argument("--list-layouts", action="store_true",
                    help="print the available layout ids")
    ap.add_argument("--show", action="store_true", help="report capacity and length")
    ap.add_argument("--clear", action="store_true", help="erase the type-out slot")
    ap.add_argument("--device", help="path to the FIDO hidraw node")
    args = ap.parse_args()

    if args.list_layouts:
        ids = layout_ids()
        for i in range(0, len(ids), 12):
            print("  " + " ".join(ids[i:i+12]))
        return 0

    dev = Device(args.device)
    dev.init()
    print(f"device: {dev.path}")

    if args.show:
        dev.send(CTAPHID_TEXTINFO, b"")
        cmd, r = dev.recv(timeout=5.0)
        if cmd != CTAPHID_TEXTINFO:
            raise SystemExit("device has no type-out slot (ENABLE_TYPEOUT=0)")
        cap, n = struct.unpack(">HH", r)
        print(f"type-out slot: {n} / {cap} bytes used")
        return 0

    if args.clear:
        dev.set_text(b"")
        print("type-out slot cleared")
        return 0

    if args.text is None:
        raise SystemExit("nothing to do -- pass --text, --show or --clear")
    data, unsupported = encode_program(args.text, args.layout)
    if unsupported:
        raise SystemExit("cannot be typed on layout %r: %s"
                         % (args.layout, " ".join(unsupported)))

    if len(data) > TYPEOUT_MAX:
        raise SystemExit(f"text is {len(data)} bytes, device limit is {TYPEOUT_MAX}")

    dev.set_text(data)
    preview = args.text if len(args.text) <= 60 else args.text[:57] + "..."
    print(f"stored {len(data)} bytes ({len(args.text)} chars, layout "
          f"{args.layout}): {preview!r}")
    print("press the button on pin 7 to type it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
