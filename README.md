# WebAuthn-writable USB keyboard on an ATmega32u4

This is a purely vibe coded proof of concept on how you can extract data
through Webauthn. This would make it possible to get data out from a remote
or virtual desktop where clipboard sharing disabled but Webauthn enabled.

---

A CTAP2 authenticator for the Pro Micro / Leonardo that a web page can write
ASCII into, and that types that ASCII on a button press.

A browser calls `navigator.credentials.create()`; the text rides along in
`user.id` and lands in RAM. Press the button and the board types it into
whatever has focus. No host-side tool in the loop.

**The text is volatile.** Unplug the board and it is gone, along with the
credential — you write it again from a browser on every plug-in. That is the
deliberate trade: nothing is left on the chip for a programmer to read.

## Keyboard layouts

USB keyboards transmit HID *usage ids* — "the key in position X" — never
characters. The computer decides what character each position produces, using
its own active layout. A device that stores characters therefore has to guess
the layout, and gets it wrong for everyone outside the US.

The mapping is done by the page instead, and the device just replays the
result. That works here because storage is volatile: the text is rewritten on
every plug-in, so the machine that writes it is always the machine that will
receive the typing, and its layout is the right one by construction.

The page detects the layout with `navigator.keyboard.getLayoutMap()` where that
exists (Chromium), and otherwise offers a dropdown of 54 Latin layouts —
the 17 most common first. Data is generated from the system's
`xkeyboard-config` by `tools/gen_layouts.py`.

Danish, for comparison with US:

| char | US | Danish |
|---|---|---|
| `@` | Shift+2 | AltGr+2 |
| `\` | key `0x31` | AltGr+`<` (key `0x64`, absent from US boards) |
| `[` `]` | dedicated keys | AltGr+8 / AltGr+9 |
| `~` | Shift+`` ` `` | dead key, then space |

Note the last row: some characters need *two* keystrokes, and several need
AltGr, which the old firmware could not emit at all.

Verified on hardware against a real Danish layout: the string

```
abcz ABCZ 0189 @#$&*()!? -_=+;:,./ []{}\|<> '"`^~
```

(9 AltGr keystrokes, 20 shifted, 23 plain, plus three dead-key sequences)
was typed back byte for byte. The other 53 layouts are checked against the xkb
data and round-trip tests, but only Danish and US have been through a physical
keyboard.

### Stored format

One byte per keystroke, so a password costs about as many bytes as it has
characters:

```
b == 0x00   escape: the next two bytes are a modifier byte and a usage id
b != 0x00   usage = b & 0x7F, and bit 7 means "hold Left Shift"
```

Usage ids used for typing are all <= 0x64, so bit 7 is free and a zero byte is
never a valid usage. Capacity is 512 bytes; the full printable ASCII set costs
116 bytes on a Danish layout.

## How the text gets in

`user.id` is the only `create()` field a page can fill with arbitrary bytes that
reaches the authenticator untouched. The client neither hashes it (unlike
`challenge`) nor encrypts it (unlike `largeBlob`), and the spec fixes it at
1–64 bytes. Byte 0 is a control byte:

| `user.id[0]` | meaning |
|---|---|
| `0` | replace the stored text with the remaining bytes |
| `1` | append the remaining bytes |

So one registration carries 63 bytes of keystroke program — typically 63
characters — and longer strings take several, at ~20 ms each.

```js
const userId = new Uint8Array([0, ...new TextEncoder().encode("my secret")]);
await navigator.credentials.create({ publicKey: {
  challenge, rp: { id: location.hostname, name: "demo" },
  user: { id: userId, name: "text", displayName: "text" },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  authenticatorSelection: { residentKey: "required",
                            userVerification: "discouraged" },
}});
```

Only **resident** registrations write the slot — a non-discoverable `create()`
leaves it alone.

An assertion returns the user handle, so a page can confirm the last chunk it
wrote. The firmware never hands the full text back over USB.

### Why not largeBlob or credBlob?

`largeBlob` is *processed by the user agent*: the browser deflates the data and
seals it with AES-256-GCM before the authenticator ever sees it, so the bytes
arrive as ciphertext. No firmware change alters that — the device would need AES
plus an inflate implementation, roughly 3.5 KB more flash than exists here.

`credBlob`, the CTAP extension designed for unencrypted per-credential data, is
not exposed by browsers.

## There is no cryptography here

Every credential reports the same hardcoded public key, and assertions carry a
canned byte string that is not a signature over anything. Browsers do not verify
assertions — relying parties do — so nothing in this setup ever checks them.

Skipping the two P-256 scalar multiplies takes registration from ~4.7 s to
~0.2 s and lets the linker drop micro-ecc entirely, about 9 KB of flash. That is
what leaves room for the keyboard *and* the CDC serial port.

The constants are reproducible rather than magic:

```py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib
k = ec.derive_private_key(
    int.from_bytes(hashlib.sha256(b"webauthn-typeout fixed demo key v1").digest(), "big"),
    ec.SECP256R1())
n = k.public_key().public_numbers()
print(n.x.to_bytes(32, "big").hex(), n.y.to_bytes(32, "big").hex())
print(k.sign(b"fixed", ec.ECDSA(hashes.SHA256())).hex())
```

The public key must be a genuine curve point or Chrome rejects the attestation
object while parsing the COSE key; the signature only has to be well-formed DER.

## Wiring

| Signal | Pin | Notes |
|---|---|---|
| Type-out button | **7** to GND | PE6; avoids I2C (2/3), SPI (14-16), UART (0/1) |
| Status LED | built in | Pro Micro RX LED (PB0, active low) |
| Entropy | A0, A1 | Leave unconnected — their ADC noise seeds the master secret |

Button gestures: **short press** types the stored text; **hold 3 s** reboots
into the bootloader (fast LED blink confirms), which is how you reprogram a
Pro Micro that has no reset button.

## Build

```sh
arduino-cli core install arduino:avr
arduino-cli compile -b arduino:avr:leonardo webauthn_keyboard
arduino-cli upload  -b arduino:avr:leonardo -p /dev/ttyACM0 webauthn_keyboard
```

No third-party libraries. If the board is wedged, `tools/reboot_bootloader.py
--upload <dir>` gets it into Caterina over CTAPHID.

```
Flash   17826 / 28672 bytes   (62%)
SRAM     1304 / 2560  static, 977 peak stack, 279 free
EEPROM     40 / 1024  used
```

## Demo page

<https://catchy-cuttlefish.github.io/webauthn-keyboard/> — published from
`test/index.html` by `.github/workflows/pages.yml`.

WebAuthn needs a secure context, so the page has to be served over HTTPS or
from `localhost`; opening the file directly will not work.

Note that the relying-party id is taken from `location.hostname`, so a
credential registered on `catchy-cuttlefish.github.io` is a different
credential from one registered on `localhost`. The device has a single
resident-credential slot, so switching between the two overwrites it.

Pick the keyboard layout of the machine that will receive the typing. Getting
it wrong produces mangled output rather than an error, because the device only
sends key positions.

## Test

```sh
python3 -m venv /tmp/v && /tmp/v/bin/pip install cryptography
/tmp/v/bin/python test/ctaphid_test.py          # 40 checks against the hardware
node test/keymap_test.js                        # 22 checks on the layout mapping
python3 -m http.server -d test 8000             # or serve the page locally
g++ -O2 -o /tmp/t test/selftest.c webauthn_keyboard/sha256.cpp \
    webauthn_keyboard/cbor.cpp && /tmp/t       # SHA-256/HMAC/CBOR vectors
```

`tools/provision.py --text "..." --layout dk` writes the slot without a
browser; `--show` reports usage; `--clear` erases it; `--list-layouts` prints
the available ids. It shares the layout data and encoder with the page, and
`keymap_test.js` checks the two encoders cannot drift apart.

## Measured performance

| Operation | Time |
|---|---|
| `getInfo` | 8 ms |
| `makeCredential` (one 63-byte chunk) | ~20 ms |
| `getAssertion` | ~15 ms |
| `authenticatorReset` (regenerates the master secret) | 0.62 s |
| typing, per character | 24 ms |

What little remains in `makeCredential` is the 4-byte EEPROM counter write.

### RAM budget

Measured on the running board by painting the stack with a canary and counting
untouched bytes after exercising every path — max-size PING, the largest
`makeCredential`, a 4-entry `allowList`, a full 512-byte write and
`authenticatorReset`:

| | bytes |
|---|---|
| static (`.data` + `.bss`) | 1304 |
| peak stack | 977 |
| **free** | **279** |

Of the static figure, 514 is the text buffer and 113 the credential slot.
Raising `TYPEOUT_MAX` eats directly into the 279-byte margin.

## Layout

| File | Role |
|---|---|
| `webauthn_keyboard.ino` | setup/loop |
| `FidoHID.{h,cpp}` | one PluggableUSB module exposing FIDO HID + boot keyboard |
| `ctaphid.{h,cpp}` | CTAPHID framing, channels, keepalive, vendor commands |
| `ctap.{h,cpp}` | CTAP2 commands, key derivation, user.id write path |
| `cbor.{h,cpp}` | minimal CBOR reader/writer |
| `sha256.{h,cpp}` | SHA-256 / HMAC-SHA-256 |
| `storage.{h,cpp}` | EEPROM map |
| `config.h` | pins, timings, LED |
| `typeout.{h,cpp}` | ASCII→HID keymap, button handling, long-press-to-bootloader |
| `tools/`, `test/` | CTAPHID client, bench tools, hardware and host test suites |

Credentials are **stateless**: the private key would be
`HMAC-SHA256(masterSecret, 'k' ‖ rpIdHash ‖ nonce)` and the credential ID is
`nonce ‖ HMAC(masterSecret, 'c' ‖ rpIdHash ‖ nonce)`, so unlimited
non-discoverable credentials cost zero storage. Only *discoverable* credentials
need a slot, and there is exactly one.

The text and the credential live in **RAM**, so a power cycle erases both.
Only two things persist:

```
EEPROM (1024 bytes, 916 unused)
  0x000  4    magic "FLB3"
  0x004  32   master secret
  0x024  4    signature counter
```

The credential slot is volatile for consistency as much as for secrecy: it
holds a copy of the text in its user handle, so a persistent credential would
report stale text after a replug while the button typed nothing.

USB endpoints are exactly full: CDC 3, FIDO 2, keyboard 1, of 6 available.

## Deliberate deviations from CTAP2.1

- **`user.id` is repurposed as a data channel.** It is meant to be an opaque
  user handle, not storage.
- **No signatures, one shared public key.** See above.
- **No clientPin, no user verification, no `pinUvAuthToken`.**
- **One discoverable-credential slot.** A second `rk` registration evicts the
  first.
- **`none` attestation only**, and `excludeList` is ignored.
- **ES256 only** (nominally — nothing is actually computed).
- `maxMsgSize` is 384, under the 1024 minimum, so a request carrying a large
  `excludeList` may be rejected with `CTAP1_ERR_INVALID_LENGTH`.

## Security

This is a bench tool, and it is **not an authenticator**. Concretely:

- Assertions are not signed and every credential shares one public key. Anyone
  can impersonate the device; any relying party that verifies will reject it.
  **Do not register it with a real relying party.**
- **There is no user-presence gate on CTAP operations** — any process that can
  open the HID device can drive registrations and assertions. Only the type-out
  button requires a physical press.
- **The type-out text is held in plaintext in RAM.** Unavoidable: a device that
  types a secret on demand must be able to recover it. It is at least not
  written to non-volatile storage, so an unpowered chip yields nothing — but
  anything that can read the running device's memory, or simply press the
  button, gets it.
- The master secret sits in EEPROM in the clear, seeded from ADC noise on
  floating pins — a weak source.
- Anything that can reach the HID device can also reboot the board into the
  bootloader and reflash it.
