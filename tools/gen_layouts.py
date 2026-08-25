#!/usr/bin/env python3
"""Generate test/layouts.js from the system's X11 xkb keyboard definitions.

USB keyboards send HID usage ids -- "the key in position X" -- not characters.
The host maps those to characters using its active keyboard layout, so the
mapping has to be done by whoever writes the text, against the right layout.
This script extracts that mapping for every Latin xkb layout.

Requires /usr/share/X11/xkb (xkeyboard-config). Re-run only when you want to
refresh the data; the generated file is committed.

    tools/gen_layouts.py
"""
import re, os, json, base64, sys
import xml.etree.ElementTree as ET

import re, os, sys
SYM = "/usr/share/X11/xkb/symbols"

# xkb key name -> USB HID usage id (physical position; identical on every layout)
HID = {}
for i, n in enumerate(["AE01","AE02","AE03","AE04","AE05","AE06","AE07","AE08","AE09","AE10"]):
    HID[n] = 0x1E + i
HID.update({"AE11":0x2D,"AE12":0x2E,"TLDE":0x35,"BKSL":0x31,"LSGT":0x64,"SPCE":0x2C})
for n,v in zip(["AD01","AD02","AD03","AD04","AD05","AD06","AD07","AD08","AD09","AD10","AD11","AD12"],
               [0x14,0x1A,0x08,0x15,0x17,0x1C,0x18,0x0C,0x12,0x13,0x2F,0x30]): HID[n]=v
for n,v in zip(["AC01","AC02","AC03","AC04","AC05","AC06","AC07","AC08","AC09","AC10","AC11"],
               [0x04,0x16,0x07,0x09,0x0A,0x0B,0x0D,0x0E,0x0F,0x33,0x34]): HID[n]=v
for n,v in zip(["AB01","AB02","AB03","AB04","AB05","AB06","AB07","AB08","AB09","AB10"],
               [0x1D,0x1B,0x06,0x19,0x05,0x11,0x10,0x36,0x37,0x38]): HID[n]=v

KEYSYM = {"space":" ","exclam":"!","quotedbl":'"',"numbersign":"#","dollar":"$","percent":"%",
 "ampersand":"&","apostrophe":"'","parenleft":"(","parenright":")","asterisk":"*","plus":"+",
 "comma":",","minus":"-","period":".","slash":"/","colon":":","semicolon":";","less":"<",
 "equal":"=","greater":">","question":"?","at":"@","bracketleft":"[","backslash":"\\",
 "bracketright":"]","asciicircum":"^","underscore":"_","grave":"`","braceleft":"{","bar":"|",
 "braceright":"}","asciitilde":"~"}
for c in "0123456789": KEYSYM[c] = c
for c in "abcdefghijklmnopqrstuvwxyz": KEYSYM[c] = c; KEYSYM[c.upper()] = c.upper()

def sym_to_char(s):
    if s in KEYSYM: return KEYSYM[s]
    return None

def parse(name, variant="basic", seen=None):
    """Returns {keyname: [lvl1, lvl2, lvl3, lvl4]} resolving xkb includes."""
    seen = seen or set()
    key = (name, variant)
    if key in seen: return {}
    seen.add(key)
    path = os.path.join(SYM, name)
    if not os.path.exists(path): return {}
    txt = open(path, encoding="utf-8", errors="replace").read()
    # isolate the requested xkb_symbols block
    m = re.search(r'xkb_symbols\s+"%s"\s*\{(.*?)\n\};' % re.escape(variant), txt, re.S)
    if not m and variant == "basic":
        # Many files name their default variant something else ("abnt2",
        # "cedilla", ...) and mark it with the `default` keyword instead.
        m = re.search(r'default[^\n]*\n?[^\n]*xkb_symbols\s+"[^"]+"\s*\{(.*?)\n\};',
                      txt, re.S)
    if not m: return {}
    body = m.group(1)
    out = {}
    for inc in re.findall(r'include\s+"([^"]+)"', body):
        if "(" in inc:
            f, v = inc.split("(", 1); v = v.rstrip(")")
        else:
            f, v = inc, "basic"
        out.update(parse(f, v, seen))
    for km in re.finditer(r'key\s+<(\w+)>\s*\{([^}]*)\}', body):
        kn, spec = km.group(1), km.group(2)
        lv = re.search(r'\[([^\]]*)\]', spec)
        if not lv: continue
        levels = [x.strip() for x in lv.group(1).split(",")]
        out[kn] = levels
    return out

# On many layouts ^ ` ~ ' " exist only as dead keys: press the dead key, then
# space, to get the bare character.
DEAD = {"dead_circumflex":"^", "dead_grave":"`", "dead_tilde":"~",
        "dead_acute":"'", "dead_diaeresis":'"'}

def table(layout, variant="basic"):
    """ASCII char -> [(usage, mod), ...]. A one-element list is a plain
    keystroke; two elements means a dead key followed by space.
    mod bits: 0x02 = LeftShift, 0x40 = RightAlt (AltGr)."""
    keys = parse(layout, variant)
    t, dead = {}, {}
    for kn, levels in keys.items():
        if kn not in HID: continue
        for lvl, sym in enumerate(levels[:4]):
            mod = (0x02 if lvl in (1,3) else 0) | (0x40 if lvl in (2,3) else 0)
            ch = sym_to_char(sym)
            if ch is not None:
                # Prefer the combination needing the fewest modifiers.
                if ch not in t or bin(mod).count("1") < bin(t[ch][0][1]).count("1"):
                    t[ch] = [(HID[kn], mod)]
            elif sym in DEAD:
                d = DEAD[sym]
                if d not in dead or bin(mod).count("1") < bin(dead[d][1]).count("1"):
                    dead[d] = (HID[kn], mod)

    # The space bar lives in a shared include that layout files do not repeat.
    t.setdefault(" ", [(0x2C, 0)])
    for ch, k in dead.items():
        if ch not in t:
            t[ch] = [k, (0x2C, 0)]        # dead key, then space
    return t

# Shown at the top of the dropdown, in this order.
COMMON = ["us", "gb", "de", "fr", "dk", "se", "no", "fi", "es", "it",
          "nl", "be", "ch", "pt", "pl", "cz", "br"]

PRINTABLE = [chr(c) for c in range(0x20, 0x7F)]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test", "layouts.js")


def main():
    if not os.path.isdir(SYM):
        sys.exit(f"{SYM} not found -- install xkeyboard-config")

    names = {}
    rules = "/usr/share/X11/xkb/rules/evdev.xml"
    if os.path.exists(rules):
        for li in ET.parse(rules).getroot().find("layoutList"):
            ci = li.find("configItem")
            names[ci.find("name").text] = ci.find("description").text

    out, skipped = {}, []
    for fn in sorted(os.listdir(SYM)):
        if not re.fullmatch(r"[a-z0-9_]+", fn):
            continue
        try:
            t = table(fn)
        except Exception:
            skipped.append(fn); continue
        # A layout that cannot reach every letter and digit is not Latin and
        # cannot type ASCII at all (Cyrillic, Greek, Arabic, ...).
        if not set("abcdefghijklmnopqrstuvwxyz0123456789").issubset(t.keys()):
            skipped.append(fn); continue

        # 4 bytes per printable ASCII char: usage1, mod1, usage2, mod2.
        # usage2 == 0 means a single keystroke, otherwise a dead-key sequence.
        blob = bytearray()
        for ch in PRINTABLE:
            seq = t.get(ch, [])
            a = seq[0] if len(seq) > 0 else (0, 0)
            b = seq[1] if len(seq) > 1 else (0, 0)
            blob += bytes([a[0], a[1], b[0], b[1]])
        out[fn] = {"n": names.get(fn, fn), "d": base64.b64encode(bytes(blob)).decode()}

    order = ([c for c in COMMON if c in out] +
             sorted([k for k in out if k not in COMMON], key=lambda k: out[k]["n"].lower()))

    data = {"common": len([c for c in COMMON if c in out]),
            "order": order, "layouts": out}
    with open(OUT, "w") as f:
        f.write("// Generated by tools/gen_layouts.py from /usr/share/X11/xkb -- do not edit.\n")
        f.write("// 4 bytes per printable ASCII char: usage1, mod1, usage2, mod2.\n")
        f.write("// mod bits: 0x02 = LeftShift, 0x40 = RightAlt (AltGr).\n")
        f.write("const LAYOUTS = " + json.dumps(data, sort_keys=True) + ";\n")

    missing = [c for c in COMMON if c not in out]
    print(f"wrote {OUT}: {len(out)} Latin layouts, {len(skipped)} skipped as non-Latin")
    if missing:
        print("WARNING: common layouts missing:", missing)
    incomplete = [k for k in out
                  if any(c not in table(k) for c in PRINTABLE)]
    if incomplete:
        print("WARNING: layouts missing some printable ASCII:", incomplete[:10])


if __name__ == "__main__":
    main()
