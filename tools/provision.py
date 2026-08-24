#!/usr/bin/env python3
"""Debug helper for the type-out slot.

In normal use you do NOT need this: a web page writes the text straight to the
device through WebAuthn's user.id field (see test/index.html). This tool exists
for bench work without a browser.

    tools/provision.py --text "literal string"   # write directly
    tools/provision.py --show                    # capacity and stored length
    tools/provision.py --clear
"""
import argparse, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaplib import Device, TYPEOUT_MAX, CTAPHID_TEXTINFO

import struct


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--text", help="store this literal string")
    ap.add_argument("--show", action="store_true", help="report capacity and length")
    ap.add_argument("--clear", action="store_true", help="erase the type-out slot")
    ap.add_argument("--device", help="path to the FIDO hidraw node")
    args = ap.parse_args()

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
    data = args.text.encode()

    # The device only has a US-layout ASCII keymap; anything else would be
    # silently skipped while typing, so refuse it here instead.
    bad = sorted({b for b in data if not (0x20 <= b < 0x7F) and b not in (0x09, 0x0A)})
    if bad:
        raise SystemExit("text contains bytes the keyboard map cannot type: "
                         + " ".join(f"0x{b:02x}" for b in bad))
    if len(data) > TYPEOUT_MAX:
        raise SystemExit(f"text is {len(data)} bytes, device limit is {TYPEOUT_MAX}")

    dev.set_text(data)
    preview = data.decode("ascii", "replace")
    if len(preview) > 60:
        preview = preview[:57] + "..."
    print(f"stored {len(data)} bytes: {preview!r}")
    print("press the button on pin 7 to type it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
