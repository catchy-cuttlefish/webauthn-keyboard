// Turning text into keystrokes.
//
// USB keyboards transmit HID usage ids -- "the key in position X" -- not
// characters. The host decides what character each position produces, using
// its active keyboard layout. So a device that stores characters has to guess
// the layout and gets it wrong for everyone outside the US.
//
// This module does the mapping instead, against an explicit layout, and the
// device just replays the result. Loaded by index.html and exercised by
// keymap_test.js; depends on LAYOUTS from layouts.js.

const MOD_SHIFT = 0x02, MOD_ALTGR = 0x40;
const KEY_ENTER = 0x28, KEY_TAB = 0x2b, KEY_SPACE = 0x2c;

function tableFor(id) {
  const raw = atob(LAYOUTS.layouts[id].d);
  const t = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) t[i] = raw.charCodeAt(i);
  return t;                       // 95 chars * [usage1, mod1, usage2, mod2]
}

// Character -> the keystrokes needed to produce it on this layout. Two
// keystrokes means a dead key followed by space, which is how ^ ` ~ are
// reached on most Nordic and German layouts.
function keystrokesFor(ch, t) {
  if (ch === "\n") return [[KEY_ENTER, 0]];
  if (ch === "\t") return [[KEY_TAB, 0]];
  const c = ch.codePointAt(0);
  if (c < 0x20 || c > 0x7e) return null;
  const i = (c - 0x20) * 4;
  if (!t[i]) return null;
  const seq = [[t[i], t[i + 1]]];
  if (t[i + 2]) seq.push([t[i + 2], t[i + 3]]);
  return seq;
}

// One byte per keystroke when the only modifier is Shift; otherwise a 0x00
// escape followed by an explicit modifier and usage. Must match typeout.cpp.
function encodeProgram(text, t) {
  const out = [];
  const bad = new Set();
  for (const ch of text) {
    const seq = keystrokesFor(ch, t);
    if (!seq) { bad.add(ch); continue; }
    for (const [usage, mod] of seq) {
      if (mod === 0) out.push(usage);
      else if (mod === MOD_SHIFT) out.push(usage | 0x80);
      else out.push(0x00, mod, usage);
    }
  }
  return { bytes: Uint8Array.from(out), unsupported: [...bad] };
}

function decodeKeystrokes(bytes) {
  const ks = [];
  for (let i = 0; i < bytes.length; ) {
    const b = bytes[i++];
    if (b === 0x00) {
      if (i + 1 > bytes.length - 1) break;      // truncated escape
      ks.push([bytes[i + 1], bytes[i]]);
      i += 2;
    } else {
      ks.push([b & 0x7f, (b & 0x80) ? MOD_SHIFT : 0]);
    }
  }
  return ks;
}

// Reverse a keystroke program back to text, for the read-back button.
function decodeProgram(bytes, t) {
  const ks = decodeKeystrokes(bytes);
  const one = new Map(), two = new Map();
  const k = (u, m) => u + ":" + m;
  for (let c = 0x20; c <= 0x7e; c++) {
    const seq = keystrokesFor(String.fromCharCode(c), t);
    if (!seq) continue;
    const key = seq.map(([u, m]) => k(u, m)).join("|");
    (seq.length === 2 ? two : one).set(key, String.fromCharCode(c));
  }
  one.set(k(KEY_ENTER, 0), "\n");
  one.set(k(KEY_TAB, 0), "\t");

  let s = "";
  for (let i = 0; i < ks.length; ) {
    if (i + 1 < ks.length) {
      const pair = two.get(k(...ks[i]) + "|" + k(...ks[i + 1]));
      if (pair !== undefined) { s += pair; i += 2; continue; }
    }
    const single = one.get(k(...ks[i]));
    s += single !== undefined ? single : "\uFFFD";
    i++;
  }
  return s;
}

// navigator.keyboard.getLayoutMap() reports what each physical key produces
// unmodified. That is not enough to build a full map -- it says nothing about
// Shift or AltGr -- but it is plenty to identify which known layout is in use.
const PROBE = {
  KeyQ: 0x14, KeyW: 0x1a, KeyY: 0x1c, KeyZ: 0x1d, KeyA: 0x04, KeyM: 0x10,
  Semicolon: 0x33, Quote: 0x34, BracketLeft: 0x2f, BracketRight: 0x30,
  Comma: 0x36, Period: 0x37, Slash: 0x38, Minus: 0x2d, Equal: 0x2e,
  Backquote: 0x35, Backslash: 0x31,
};

// `actual` maps probe code -> the character that key produces unmodified.
// Returns the best-matching layout id, or null if the match is ambiguous.
function identifyLayout(actual) {
  const probed = Object.keys(actual).length;
  if (probed < 6) return null;
  let best = null, bestScore = -1, tie = false;
  for (const id of LAYOUTS.order) {
    const t = tableFor(id);
    const base = new Map();       // usage -> unshifted character
    for (let c = 0x20; c <= 0x7e; c++) {
      const i = (c - 0x20) * 4;
      if (t[i] && t[i + 1] === 0 && !t[i + 2] && !base.has(t[i])) {
        base.set(t[i], String.fromCharCode(c).toLowerCase());
      }
    }
    let score = 0;
    for (const [code, usage] of Object.entries(PROBE)) {
      if (actual[code] !== undefined && base.get(usage) === actual[code]) score++;
    }
    if (score > bestScore) { bestScore = score; best = id; tie = false; }
    else if (score === bestScore) tie = true;
  }
  if (bestScore < probed - 1) return null;      // nothing matched well
  if (tie && bestScore < probed) return null;   // several equally plausible
  return best;
}

if (typeof module !== "undefined") {
  module.exports = { tableFor, keystrokesFor, encodeProgram, decodeProgram,
                     decodeKeystrokes, identifyLayout, PROBE,
                     MOD_SHIFT, MOD_ALTGR, KEY_ENTER, KEY_TAB, KEY_SPACE };
}
