"""Minimal CTAPHID client + largeBlob codec.

Shared by test/ctaphid_test.py, tools/provision.py and
tools/reboot_bootloader.py. Implements only what this project needs; it is not
a general-purpose FIDO library (see python-fido2 for that).
"""
import os, glob, struct, zlib, hashlib, secrets, select

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BROADCAST = 0xFFFFFFFF
PING, MSG, INIT, CBOR, CANCEL, KEEPALIVE, ERROR = 0x01, 0x03, 0x06, 0x10, 0x11, 0x3B, 0x3F

# Vendor range (0x40-0x7F), specific to this firmware.
CTAPHID_SETTEXT    = 0x40
CTAPHID_TEXTINFO   = 0x41
CTAPHID_BOOTLOADER = 0x42
CTAPHID_TYPENOW    = 0x43

# Fallback only; ask the device with CTAPHID_TEXTINFO for the real capacity,
# which depends on whether largeBlob was compiled in.
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


# ------------------------------------------------------------ largeBlob ----
def build_blob_array(key, data):
    """Client-side largeBlob encoding, per WebAuthn / CTAP2.1 6.10.4."""
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)   # raw deflate
    pt = comp.compress(data) + comp.flush()
    nonce = secrets.token_bytes(12)
    aad = b"blob" + struct.pack("<Q", len(data))
    ct = AESGCM(key).encrypt(nonce, pt, aad)
    arr = cbor_enc([{1: ct, 2: nonce, 3: len(data)}])
    return arr + hashlib.sha256(arr).digest()[:16]


def parse_blob_array(key, ser):
    body, digest = ser[:-16], ser[-16:]
    assert hashlib.sha256(body).digest()[:16] == digest, "array checksum mismatch"
    for entry in cbor_dec(body)[0]:
        aad = b"blob" + struct.pack("<Q", entry[3])
        try:
            pt = AESGCM(key).decrypt(entry[2], entry[1], aad)
        except Exception:
            continue                                 # entry for another credential
        return zlib.decompressobj(-15).decompress(pt)
    return None


def blob_read(dev):
    out = b""
    while True:
        st, r = dev.cbor(0x0C, {1: 1024, 3: len(out)})
        assert st == 0, f"largeBlobs get failed: 0x{st:02x}"
        frag = r[1]
        if not frag:
            break
        out += frag
    return out


def blob_write(dev, ser, frag=256):
    off = 0
    while off < len(ser):
        chunk = ser[off:off+frag]
        p = {2: chunk, 3: off}
        if off == 0:
            p[4] = len(ser)
        st, _ = dev.cbor(0x0C, p, timeout=20.0)
        assert st == 0, f"largeBlobs set failed at offset {off}: 0x{st:02x}"
        off += len(chunk)
