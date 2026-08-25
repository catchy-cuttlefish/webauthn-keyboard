"""Minimal CTAPHID client.

Shared by test/ctaphid_test.py, tools/provision.py and
tools/reboot_bootloader.py. Implements only what this project needs; it is not
a general-purpose FIDO library (see python-fido2 for that).
"""
import os, glob, json, re, base64, struct, secrets, select

BROADCAST = 0xFFFFFFFF
PING, MSG, INIT, CBOR, CANCEL, KEEPALIVE, ERROR = 0x01, 0x03, 0x06, 0x10, 0x11, 0x3B, 0x3F

# Vendor range (0x40-0x7F), specific to this firmware.
CTAPHID_SETTEXT    = 0x40
CTAPHID_TEXTINFO   = 0x41
CTAPHID_BOOTLOADER = 0x42

TYPEOUT_MAX = 512


# ----------------------------------------------------------------- CBOR ----
def cbor_enc(v):
    def head(mt, n):
        if n < 24:    return bytes([mt << 5 | n])
        if n < 256:   return bytes([mt << 5 | 24, n])
        if n < 65536: return bytes([mt << 5 | 25]) + struct.pack(">H", n)
        return bytes([mt << 5 | 26]) + struct.pack(">I", n)
    if isinstance(v, bool):  return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor_enc(x) for x in v)
    if isinstance(v, dict):
        # CTAP2 canonical ordering: ints before strings, then by value/length.
        def key(k):
            return (0, k) if isinstance(k, int) else (1, len(k), k)
        items = sorted(v.items(), key=lambda kv: key(kv[0]))
        return head(5, len(v)) + b"".join(cbor_enc(k) + cbor_enc(x) for k, x in items)
    raise TypeError(type(v))


def cbor_dec(b, i=0):
    ib = b[i]; mt, ai = ib >> 5, ib & 0x1F; i += 1
    if ai < 24:    n = ai
    elif ai == 24: n = b[i]; i += 1
    elif ai == 25: n = struct.unpack(">H", b[i:i+2])[0]; i += 2
    elif ai == 26: n = struct.unpack(">I", b[i:i+4])[0]; i += 4
    elif ai == 27: n = struct.unpack(">Q", b[i:i+8])[0]; i += 8
    else: raise ValueError("indefinite/reserved")
    if mt == 0: return n, i
    if mt == 1: return -1 - n, i
    if mt == 2: return b[i:i+n], i + n
    if mt == 3: return b[i:i+n].decode(), i + n
    if mt == 4:
        out = []
        for _ in range(n):
            v, i = cbor_dec(b, i); out.append(v)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(n):
            k, i = cbor_dec(b, i); v, i = cbor_dec(b, i); out[k] = v
        return out, i
    if mt == 7:
        if n == 20: return False, i
        if n == 21: return True, i
        if n == 22: return None, i
    raise ValueError(f"mt={mt}")


# -------------------------------------------------------------- device -----
def find_fido_hidraw():
    """The FIDO interface is the hidraw node whose report descriptor starts
    with usage page 0xF1D0. Node numbering is not stable across replugs."""
    for path in sorted(glob.glob("/dev/hidraw*")):
        desc = f"/sys/class/hidraw/{os.path.basename(path)}/device/report_descriptor"
        try:
            with open(desc, "rb") as f:
                if f.read(3) == b"\x06\xd0\xf1":
                    return path
        except OSError:
            continue
    return None


class Device:
    def __init__(self, path=None):
        path = path or find_fido_hidraw()
        if not path:
            raise SystemExit("no FIDO hidraw device found (is the board plugged in?)")
        self.path = path
        self.fd = os.open(path, os.O_RDWR)
        self.cid = BROADCAST

    def _write(self, pkt):
        assert len(pkt) == 64
        os.write(self.fd, b"\x00" + pkt)            # hidraw: leading report id

    def _read(self, timeout=5.0):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            raise TimeoutError("no HID report within %.1fs" % timeout)
        return os.read(self.fd, 64)

    def send(self, cmd, data=b""):
        cid = struct.pack(">I", self.cid)
        pkt = cid + bytes([0x80 | cmd]) + struct.pack(">H", len(data)) + data[:57]
        self._write(pkt.ljust(64, b"\x00"))
        off, seq = 57, 0
        while off < len(data):
            chunk = data[off:off+59]
            self._write((cid + bytes([seq]) + chunk).ljust(64, b"\x00"))
            off += 59; seq += 1

    def recv(self, timeout=5.0):
        while True:
            pkt = self._read(timeout)
            cid, cmd = struct.unpack(">I", pkt[:4])[0], pkt[4]
            if not (cmd & 0x80):
                raise ValueError("unexpected continuation frame")
            cmd &= 0x7F
            blen = struct.unpack(">H", pkt[5:7])[0]
            buf = pkt[7:7+min(blen, 57)]
            while len(buf) < blen:
                p = self._read(timeout)
                buf += p[5:5+min(blen - len(buf), 59)]
            if cmd == KEEPALIVE:
                continue                             # device busy; keep waiting
            return cmd, buf

    def init(self):
        nonce = secrets.token_bytes(8)
        self.cid = BROADCAST
        self.send(INIT, nonce)
        cmd, r = self.recv()
        assert cmd == INIT and r[:8] == nonce, "INIT nonce mismatch"
        self.cid = struct.unpack(">I", r[8:12])[0]
        return r

    def cbor(self, cmd, params=None, timeout=15.0):
        payload = bytes([cmd]) + (cbor_enc(params) if params else b"")
        self.send(CBOR, payload)
        c, r = self.recv(timeout)
        assert c == CBOR, f"expected CBOR frame, got 0x{c:02x} {r.hex()}"
        status = r[0]
        body = cbor_dec(r[1:])[0] if len(r) > 1 else None
        return status, body

    def set_text(self, data: bytes):
        if len(data) > TYPEOUT_MAX:
            raise ValueError(f"text is {len(data)} bytes, limit is {TYPEOUT_MAX}")
        self.send(CTAPHID_SETTEXT, data)
        cmd, _ = self.recv(timeout=10.0)
        if cmd != CTAPHID_SETTEXT:
            raise RuntimeError(f"device rejected SETTEXT (0x{cmd:02x})")




# ------------------------------------------------------- keystroke encoding --
# The device stores keystrokes, not characters: USB keyboards transmit HID
# usage ids and the host applies its own layout. This mirrors test/keymap.js;
# the layout data is shared with the browser page.

_LAYOUTS = None


def _load_layouts():
    global _LAYOUTS
    if _LAYOUTS is None:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "test", "layouts.js")
        with open(p) as f:
            txt = f.read()
        _LAYOUTS = json.loads(re.search(r"const LAYOUTS = (\{.*\});", txt, re.S).group(1))
    return _LAYOUTS


def layout_ids():
    return _load_layouts()["order"]


def encode_program(text, layout="us"):
    """(program bytes, list of characters with no key on this layout)."""
    data = _load_layouts()
    if layout not in data["layouts"]:
        raise SystemExit("unknown layout %r (try --list-layouts)" % layout)
    t = base64.b64decode(data["layouts"][layout]["d"])

    out, bad = bytearray(), []
    for ch in text:
        if ch == "\n":   seq = [(0x28, 0)]
        elif ch == "\t": seq = [(0x2B, 0)]
        else:
            c = ord(ch)
            if not (0x20 <= c <= 0x7E) or not t[(c - 0x20) * 4]:
                if ch not in bad:
                    bad.append(ch)
                continue
            i = (c - 0x20) * 4
            seq = [(t[i], t[i + 1])]
            if t[i + 2]:
                seq.append((t[i + 2], t[i + 3]))
        for usage, mod in seq:
            if mod == 0:
                out.append(usage)
            elif mod == 0x02:
                out.append(usage | 0x80)
            else:
                out += bytes([0x00, mod, usage])
    return bytes(out), bad
