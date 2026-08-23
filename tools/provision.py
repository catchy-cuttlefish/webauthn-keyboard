#!/usr/bin/env python3
"""Debug helper for the type-out slot.

In normal use you do NOT need this: a web page writes the text straight to the
device through WebAuthn's user.id field (see test/index.html). This tool exists
for bench work without a browser, and for the legacy largeBlob path.

    tools/provision.py --text "literal string"   # write directly
    tools/provision.py --show                    # capacity and stored length
    tools/provision.py --clear
    tools/provision.py --from-blob --rp localhost

--from-blob only applies to firmware built with ENABLE_LARGEBLOB=1. The device
cannot read its own largeBlob (the browser AES-GCM-encrypts it and the
ATmega32u4 has no room for AES plus inflate), so this decrypts it host-side and
pushes the plaintext down.
"""
import argparse, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ctaplib import (Device, blob_read, parse_blob_array, TYPEOUT_MAX,
                     CTAPHID_TEXTINFO)

import secrets, struct


def get_large_blob_key(dev, rp_id):
    """A discoverable-credential assertion returns the largeBlobKey directly."""
    st, ga = dev.cbor(0x02, {
        1: rp_id,
        2: secrets.token_bytes(32),
        4: {"largeBlobKey": True},
        5: {"up": True},
    }, timeout=30.0)
    if st == 0x2E:
        raise SystemExit(f"no credential on the device for rp '{rp_id}' -- "
                         "register one from the browser demo page first")
    if st != 0:
        raise SystemExit(f"getAssertion failed: 0x{st:02x}")
    key = ga.get(0x07)
    if not key:
        raise SystemExit("device did not return a largeBlobKey")
    return key


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rp", default="localhost",
                    help="relying party id used at registration (default: localhost)")
    ap.add_argument("--text", help="store this literal string")
    ap.add_argument("--show", action="store_true", help="report capacity and length")
    ap.add_argument("--from-blob", action="store_true",
                    help="decrypt the largeBlob host-side and store it")
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

    if args.text is not None:
        data = args.text.encode()
    elif not args.from_blob:
        raise SystemExit("nothing to do -- pass --text, --from-blob, --show or --clear")
    else:
        print(f"requesting assertion for rp '{args.rp}' (~5 s)...")
        key = get_large_blob_key(dev, args.rp)
        ser = blob_read(dev)
        print(f"largeBlob array: {len(ser)} bytes")
        data = parse_blob_array(key, ser)
        if data is None:
            raise SystemExit("no blob entry decrypts with this credential's key "
                             "-- write one from the browser page first")

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
