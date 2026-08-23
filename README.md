# WebAuthn-writable USB keyboard on an ATmega32u4

A CTAP2 authenticator for the Leonardo / Pro Micro that a web page can write
ASCII into, and that types that ASCII on a button press.

A browser calls `navigator.credentials.create()`; the text rides along in
`user.id` and lands in EEPROM. Press the button and the board types it into
whatever has focus. No host-side tool in the loop.

The Leonardo enumerates as a real FIDO security key (HID usage page `0xF1D0`),
so no drivers, no host agent, and no browser flags are needed.

## How the text gets in

`user.id` is the only `create()` field a page can fill with arbitrary bytes that
reaches the authenticator untouched. The client neither hashes it (unlike
`challenge`) nor encrypts it (unlike `largeBlob`), and the spec fixes it at
1–64 bytes. Byte 0 is a control byte:

| `user.id[0]` | meaning |
|---|---|
| `0` | replace the stored text with the remaining bytes |
| `1` | append the remaining bytes |

So one registration carries 63 bytes; longer strings take several, at ~0.2 s
each. Capacity is 512 bytes.

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

### Why not largeBlob?

`largeBlob` is *processed by the user agent*: the browser deflates the data and
seals it with AES-256-GCM before the authenticator ever sees it, so the bytes
arrive as ciphertext. No firmware change alters that — the device would need AES
plus an inflate implementation, about 3.5 KB more flash than exists here.

`credBlob`, the CTAP extension designed for unencrypted per-credential data,
is not exposed by browsers.

The largeBlob code is still in the tree behind `ENABLE_LARGEBLOB` (default off).
Turning it on costs ~2.1 KB of flash and 512 bytes of EEPROM, and does not fit
alongside the keyboard; it is only useful with `tools/provision.py --from-blob`,
which decrypts host-side.

## Wiring

| Signal | Pin | Notes |
|---|---|---|
| Type-out button | **7** to GND | Plain digital pin (PE6); avoids I2C (2/3), SPI (14-16), UART (0/1) |
| Status LED | built in | Pro Micro RX LED (PB0); set `BOARD_PRO_MICRO 0` for a Leonardo's pin-13 LED |
| Reset (optional) | **RST** to GND | Not a GPIO. Double-tap enters the bootloader |
| Entropy | A0, A1 | Leave unconnected -- their ADC noise seeds the master secret |

Button gestures: **short press** types the stored text; **hold 3 s** reboots
into the bootloader (fast LED blink confirms).

## Test it

```sh
python3 -m venv /tmp/v && /tmp/v/bin/pip install cryptography
/tmp/v/bin/python test/ctaphid_test.py          # against the hardware
python3 -m http.server -d test 8000             # then open localhost:8000
g++ -O2 -o /tmp/t test/selftest.c webauthn_largeblob/sha256.cpp \
    webauthn_largeblob/cbor.cpp && /tmp/t       # host-side crypto vectors
```

The hardware suite skips whichever of the two write paths is not compiled in.

## Reprogramming without a reset button

CDC serial is disabled to free flash, so there is no 1200-baud touch. Two ways
in, and neither needs a reset button:

```sh
tools/reboot_bootloader.py --upload <build-dir>   # over CTAPHID
```

or hold the button for 3 s, then flash. Caterina only stays resident for ~7 s.

Note the tool drives `avrdude` directly rather than `arduino-cli upload`: for
Leonardo-class boards the latter does a 1200-baud touch first, which Caterina
reads as "reset and run the sketch", so the upload races the bootloader exiting.

## Build

```sh
arduino-cli core install arduino:avr
arduino-cli lib install "micro-ecc"          # only needed for FAKE_CRYPTO=0
arduino-cli compile -b arduino:avr:leonardo webauthn_largeblob
arduino-cli upload  -b arduino:avr:leonardo -p /dev/ttyACM0 webauthn_largeblob
```

Ordinary uploads work because CDC serial fits again. `-DCDC_DISABLED` is only
required with `-DFAKE_CRYPTO=0`, where flash is tight; in that case flash with
`tools/reboot_bootloader.py --upload <dir>`.

Current footprint — note how little room is left:

```
Flash   18262 / 28672 bytes   (63%)
SRAM      682 / 2560  static
EEPROM    676 / 1024  used
```

Skipping the P-256 work lets the linker drop micro-ecc entirely: **9.3 KB of
flash**, which is what buys back the CDC serial port (so ordinary
`arduino-cli upload` works again) and leaves room for `ENABLE_LARGEBLOB=1`.

| Build | Flash |
|---|---|
| default (fake crypto, keyboard, CDC) | 18262 |
| `-DENABLE_LARGEBLOB=1` | 20324 |
| `-DFAKE_CRYPTO=0 -DCDC_DISABLED` | 26790 |
| `-DFAKE_CRYPTO=0 -DENABLE_LARGEBLOB=1` | does not fit |

`-DCDC_DISABLED` is still required with the keyboard enabled. Feature knobs live
in `config.h`: `ENABLE_TYPEOUT`, `ENABLE_LARGEBLOB`, `ENABLE_LONG_PRESS`,
`ALLOW_REMOTE_TYPE`, `BOARD_PRO_MICRO`.


**Against the hardware**, over raw CTAPHID — this reimplements the browser side
of largeBlob (deflate → AES-256-GCM → CBOR array → checksum), so the firmware is
checked against the real CTAP2.1 wire format:

```sh
python3 -m venv /tmp/v && /tmp/v/bin/pip install cryptography
/tmp/v/bin/python test/ctaphid_test.py /dev/hidraw0
```

51 checks, including ECDSA signature verification against the registered public
key, single- and multi-fragment blob writes, and recovery from an abandoned
write. All currently pass on an Arduino Leonardo.

**In a browser:**

```sh
python3 -m http.server -d test 8000   # WebAuthn requires a secure context
```

Open <http://localhost:8000/largeblob.html>, then **Register → Write → Read**.

**Host-side known-answer tests** for the portable code (SHA-256/HMAC/CBOR
against NIST and RFC 4231 vectors):

```sh
g++ -O2 -o /tmp/selftest test/selftest.c webauthn_largeblob/sha256.cpp webauthn_largeblob/cbor.cpp && /tmp/selftest
```

No udev rule is needed on a systemd system: the report descriptor declares the
FIDO usage page (`0xF1D0`), so systemd's built-in `60-fido-id.rules` tags the
device `uaccess` and grants the logged-in user an ACL on `/dev/hidraw*`
automatically. Verify with `getfacl /dev/hidraw0`.

## Measured performance

| Operation | `FAKE_CRYPTO=1` (default) | `FAKE_CRYPTO=0` |
|---|---|---|
| `getInfo` | 8 ms | 20 ms |
| `makeCredential` (one 63-byte chunk) | **228 ms** | 4.7 s |
| `getAssertion` | **148 ms** | 5.0 s |
| typing, per character | 24 ms | 24 ms |

With real crypto both operations are one P-256 scalar multiply; the ATmega32u4
has no hardware multiplier for this and micro-ecc's faster optimization levels
cost ~10 KB of flash the part does not have. What is left at 228 ms is EEPROM
writing, not computation.

## Layout

| File | Role |
|---|---|
| `webauthn_largeblob.ino` | setup/loop |
| `FidoHID.{h,cpp}` | custom `PluggableUSB` FIDO HID interface (2 × 64-byte endpoints) |
| `ctaphid.{h,cpp}` | CTAPHID framing, channels, keepalive |
| `ctap.{h,cpp}` | CTAP2 commands, key derivation, `authenticatorLargeBlobs` |
| `cbor.{h,cpp}` | minimal CBOR reader/writer |
| `sha256.{h,cpp}` | SHA-256 / HMAC-SHA-256 |
| `storage.{h,cpp}` | EEPROM map |
| `config.h` | button, LED, board and feature switches |
| `FidoHID.{h,cpp}` also carries the boot-keyboard interface | |
| `typeout.{h,cpp}` | ASCII->HID keymap, button handling, long-press-to-bootloader |
| `tools/ctaplib.py` | shared CTAPHID client + largeBlob codec |
| `tools/provision.py` | bench helper: write/inspect the slot without a browser |
| `tools/reboot_bootloader.py` | reboot into Caterina and flash |
| `test/ctaphid_test.py` | end-to-end CTAPHID exercise against real hardware |
| `test/selftest.c` | host-side SHA-256/HMAC/CBOR known-answer tests |
| `test/index.html` | browser demo page |

Credentials are **stateless**: the private key is
`HMAC-SHA256(masterSecret, 'k' ‖ rpIdHash ‖ nonce)` and the credential ID is
`nonce ‖ HMAC(masterSecret, 'c' ‖ rpIdHash ‖ nonce)`. Unlimited non-discoverable
credentials therefore cost zero storage. Only *discoverable* credentials need a
slot, and there is exactly one.

EEPROM map (1024 bytes):

```
0x000  4    magic
0x004  32   master secret
0x024  4    signature counter
0x028  113  the single discoverable-credential slot
0x0A0  2    committed largeBlob length
0x0A0  2    type-out text length
0x0A4  512  type-out text (plaintext ASCII)
```

## Deliberate deviations from CTAP2.1

- **`user.id` is repurposed as a data channel.** It is meant to be an opaque
  user handle, not storage. Nothing in WebAuthn forbids it, but this device is
  not a general-purpose authenticator and should not be registered with real
  relying parties.
- **No clientPin, no user verification, no `pinUvAuthToken`.** `getInfo`
  advertises no `uv`/`clientPin` options.
- With `ENABLE_LARGEBLOB=1`, the blob array is 512 bytes rather than the
  mandated ≥ 1024, because the whole EEPROM is 1 KB.
- **One discoverable-credential slot.** A second `rk` registration evicts the
  first.
- **`none` attestation only**, and `excludeList` is ignored, so re-registering
  the same account silently creates a new credential.
- **ES256 only.**
- `maxMsgSize` is 384, well under the 1024 minimum, so requests carrying a large
  `excludeList` may be rejected with `CTAP1_ERR_INVALID_LENGTH`.

## Security

This is a bench tool, and with the default settings it is **not an
authenticator at all**. Concretely:

- **`FAKE_CRYPTO=1` (default) removes the cryptography.** Every credential
  reports the same hardcoded public key, and assertions carry a canned byte
  string that is not a signature over anything. Any relying party that actually
  verifies will reject it, and anyone can trivially impersonate the device.
  This is deliberate — the board is a WebAuthn-addressable keyboard, not a
  security key. Build with `-DFAKE_CRYPTO=0` for real ES256.

- With `REQUIRE_BUTTON 0` (the default) **there is no user consent at all** —
  any process that can open the HID device can read or overwrite the blob and
  request assertions. Set it to `1` in `config.h` for physical confirmation.
- **The type-out text is stored in plaintext.** This is inherent: a device that
  types a secret on demand must be able to recover that secret. An EEPROM dump
  hands it over directly.
- `ALLOW_REMOTE_TYPE` (default 0) would let any local process trigger typing.
  Leave it off; it exists only to test the keyboard without a button wired.
- Anything that can reach the HID device can also reboot the board into the
  bootloader and reflash it.
- The master secret sits in EEPROM in the clear and is readable by anyone with
  an ISP programmer or the ability to run `avrdude` on an attached board.
- Its initial entropy comes from ADC noise on floating pins plus timer jitter.
  That is a weak seed, and it is the one value the whole device depends on.
- No side-channel hardening: micro-ecc's scalar multiply is not constant-time
  against a local attacker with power/EM access.

ECDSA nonces are derived deterministically as
`HMAC(masterSecret, 's' ‖ privateKey ‖ messageHash ‖ counter)` rather than drawn
from the board's poor entropy sources — reusing a nonce across two signatures
would disclose the private key, and binding it to the key and message removes
any dependence on the entropy pool or on the counter never rolling back.

Don't protect anything you care about with it.
