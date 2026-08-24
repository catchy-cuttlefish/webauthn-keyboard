#!/usr/bin/env python3
"""
End-to-end exercise of the authenticator over raw CTAPHID.

Drives the device the way a browser does -- registrations carrying the text in
user.id -- and checks the CTAP2 responses against the wire format.

Run:  ./v/bin/python test/ctaphid_test.py [/dev/hidraw0]
"""
import os, sys, struct, time, hashlib, secrets

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from ctaplib import (Device, PING, cbor_dec, find_fido_hidraw,
                     CTAPHID_SETTEXT, CTAPHID_TEXTINFO)

ok_count = 0
fail_count = 0
skip_count = 0


def check(name, cond, detail=""):
    global ok_count, fail_count
    if cond:
        ok_count += 1
        print(f"  ok   {name}")
    else:
        fail_count += 1
        print(f"  FAIL {name}  {detail}")


def skip(name, why):
    global skip_count
    skip_count += 1
    print(f"  skip {name} ({why})")


RP = "example.com"


def make_credential(dev, user_id, rp=RP, rk=True, alg=-7):
    return dev.cbor(0x01, {
        1: secrets.token_bytes(32),
        2: {"id": rp, "name": "demo"},
        3: {"id": user_id, "name": "u", "displayName": "u"},
        4: [{"alg": alg, "type": "public-key"}],
        7: {"rk": rk},
    }, timeout=30.0)


def text_info(dev):
    """(capacity, stored length) of the type-out slot."""
    dev.send(CTAPHID_TEXTINFO, b"")
    cmd, r = dev.recv(timeout=5.0)
    assert cmd == CTAPHID_TEXTINFO, f"TEXTINFO refused (0x{cmd:02x})"
    return struct.unpack(">HH", r)


def main(path):
    dev = Device(path)

    print("CTAPHID transport")
    r = dev.init()
    check("INIT allocates channel", dev.cid not in (0, 0xFFFFFFFF), f"cid={dev.cid:#x}")
    check("protocol version 2", r[12] == 2, f"got {r[12]}")
    payload = bytes(range(200))
    dev.send(PING, payload)
    c, echo = dev.recv()
    check("PING echoes multi-frame payload", c == PING and echo == payload)

    print("\nauthenticatorGetInfo")
    st, info = dev.cbor(0x04)
    check("status ok", st == 0, f"0x{st:02x}")
    check("versions include FIDO_2_1", "FIDO_2_1" in info[1], str(info.get(1)))
    check("options.rk true", info[4].get("rk") is True)
    check("no clientPin advertised", "clientPin" not in info[4])
    check("no extensions advertised", 2 not in info, str(info.get(2)))
    print(f"       maxMsgSize={info.get(5)}   aaguid={info[3].hex()}")

    print("\nauthenticatorMakeCredential")
    uid = b"\x00" + b"seed-user"
    st, mc = make_credential(dev, uid)
    check("status ok", st == 0, f"0x{st:02x}")
    check("fmt is none", mc[1] == "none", str(mc.get(1)))
    ad = mc[2]
    check("authData length 180", len(ad) == 180, str(len(ad)))
    check("rpIdHash correct", ad[:32] == hashlib.sha256(RP.encode()).digest())
    check("UP+AT flags set", ad[32] & 0x41 == 0x41, f"flags={ad[32]:#04x}")
    cred_len = struct.unpack(">H", ad[53:55])[0]
    cred_id = ad[55:55+cred_len]
    check("credential id is 48 bytes", cred_len == 48, str(cred_len))
    cose = cbor_dec(ad[55+cred_len:])[0]
    check("COSE key is EC2/ES256/P-256",
          cose[1] == 2 and cose[3] == -7 and cose[-1] == 1, str(cose.get(3)))
    pub_x, pub_y = cose[-2], cose[-3]

    print("\ntype-out slot written through user.id")
    cap = text_info(dev)[0]
    check("capacity reported", cap == 512, f"{cap}")
    a = b"Correct-Horse_Battery+Staple"
    b = b" :: appended-chunk-42!"
    st, _ = make_credential(dev, b"\x00" + a)
    check("control byte 0 replaces", st == 0 and text_info(dev)[1] == len(a),
            f"stored={text_info(dev)[1]} want={len(a)}")
    st, _ = make_credential(dev, b"\x01" + b)
    check("control byte 1 appends", st == 0 and text_info(dev)[1] == len(a) + len(b),
            f"stored={text_info(dev)[1]} want={len(a)+len(b)}")
    st, _ = make_credential(dev, b"\x00" + b"reset")
    check("re-replacing truncates", text_info(dev)[1] == 5, f"{text_info(dev)[1]}")

    # A non-resident registration must not touch the slot: user.id is only
    # meaningful for discoverable credentials.
    st, _ = make_credential(dev, b"\x00" + b"should-not-appear", rk=False)
    check("non-resident create leaves slot alone",
            st == 0 and text_info(dev)[1] == 5, f"{text_info(dev)[1]}")

    # Oversized writes must clamp, not overrun.
    dev.send(CTAPHID_SETTEXT, b"Z" * (cap + 50))
    cmd, _ = dev.recv(timeout=10.0)
    check("oversize SETTEXT rejected or clamped",
            cmd == 0x3F or text_info(dev)[1] <= cap, f"stored={text_info(dev)[1]}")

    print("\nauthenticatorGetAssertion (discoverable, no allowList)")
    final_text = b"the-typed-secret-42"
    make_credential(dev, b"\x00" + final_text)
    cdh2 = secrets.token_bytes(32)
    t0 = time.time()
    st, ga = dev.cbor(0x02, {1: RP, 2: cdh2, 5: {"up": True}}, timeout=30.0)
    print(f"       assertion took {time.time()-t0:.1f}s")
    check("status ok", st == 0, f"0x{st:02x}")
    check("user handle echoes the written user.id",
          4 in ga and ga[4]["id"] == b"\x00" + final_text, str(ga.get(4)))
    check("assertion text matches what was written",
          text_info(dev)[1] == len(final_text), f"{text_info(dev)[1]}")
    ad2 = ga[2]
    check("assertion authData is 37 bytes", len(ad2) == 37, str(len(ad2)))
    check("UP set, AT clear", ad2[32] & 0x41 == 0x01, f"flags={ad2[32]:#04x}")

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    # The public key above belongs to an earlier credential; re-register and
    # verify that assertion instead so the key and signature match.
    st, mc2 = make_credential(dev, b"\x00" + final_text)
    ad3 = mc2[2]
    cl = struct.unpack(">H", ad3[53:55])[0]
    cid2 = ad3[55:55+cl]
    cose2 = cbor_dec(ad3[55+cl:])[0]
    pk = ec.EllipticCurvePublicNumbers(
        int.from_bytes(cose2[-2], "big"), int.from_bytes(cose2[-3], "big"),
        ec.SECP256R1()).public_key()
    cdh3 = secrets.token_bytes(32)
    st, ga3 = dev.cbor(0x02, {1: RP, 2: cdh3,
                              3: [{"id": cid2, "type": "public-key"}]}, timeout=30.0)
    check("no user handle with allowList", 4 not in ga3, f"keys={sorted(ga3)}")

    # The device performs no cryptography: one fixed public key for every
    # credential and a canned signature. Assert that is exactly what we get,
    # so the fixture can never be mistaken for working crypto.
    check("every credential reports the same fixed public key",
          (pub_x, pub_y) == (cose2[-2], cose2[-3]))
    check("canned signature is well-formed DER",
          ga3[3][0] == 0x30 and len(ga3[3]) == ga3[3][1] + 2, ga3[3][:4].hex())
    # An off-curve point would make Chrome reject the attestation object.
    try:
        ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose2[-2], "big"), int.from_bytes(cose2[-3], "big"),
            ec.SECP256R1()).public_key()
        on_curve = True
    except Exception:
        on_curve = False
    check("fixed public key really is on P-256 (Chrome parses it)", on_curve)
    try:
        pk.verify(ga3[3], ga3[2] + cdh3, ec.ECDSA(hashes.SHA256()))
        sig_ok = True
    except Exception:
        sig_ok = False
    check("canned signature does NOT verify (it is not a signature)", not sig_ok)

    print("\nerror handling")
    st, _ = dev.cbor(0x02, {1: "other.example", 2: secrets.token_bytes(32)})
    check("unknown rp -> NO_CREDENTIALS (0x2E)", st == 0x2E, f"0x{st:02x}")
    st, _ = dev.cbor(0x99)
    check("bad command -> INVALID_COMMAND (0x01)", st == 0x01, f"0x{st:02x}")
    st, _ = dev.cbor(0x06)
    check("clientPin -> UNSUPPORTED_OPTION (0x2B)", st == 0x2B, f"0x{st:02x}")
    st, _ = dev.cbor(0x0C, {1: 100, 3: 0})
    check("largeBlobs -> INVALID_COMMAND (0x01)", st == 0x01, f"0x{st:02x}")
    st, _ = make_credential(dev, b"\x00x", alg=-257)
    check("RS256-only -> UNSUPPORTED_ALGORITHM (0x26)", st == 0x26, f"0x{st:02x}")

    # Leave something sensible on the device for a manual button press.
    make_credential(dev, b"\x00" + b"hello-from-webauthn")

    print(f"\n{ok_count} passed, {fail_count} failed, {skip_count} skipped")
    return 1 if fail_count else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else find_fido_hidraw()))
