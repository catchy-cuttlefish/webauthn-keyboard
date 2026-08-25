// Tests for the text -> keystroke mapping.
//
//   node test/keymap_test.js
//
// The firmware just replays whatever keystrokes it is given, so correctness of
// the typed output lives entirely in here and in the generated layout data.

const fs = require("fs");
const vm = require("vm");
const path = require("path");

const dir = __dirname;
const ctx = { atob: s => Buffer.from(s, "base64").toString("binary"),
              module: { exports: {} }, console };
ctx.globalThis = ctx;
vm.createContext(ctx);
// Both files declare top-level `const`s, which are lexical bindings rather
// than properties of the context, so they have to share one compilation unit.
vm.runInContext(
  fs.readFileSync(path.join(dir, "layouts.js"), "utf8") + "\n" +
  fs.readFileSync(path.join(dir, "keymap.js"), "utf8") + "\n" +
  "globalThis.__layouts = LAYOUTS;", ctx);
const K = ctx.module.exports;
const LAYOUTS = ctx.__layouts;

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log(`  FAIL ${name}  ${detail}`); }
}
const hex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join(" ");

const PRINTABLE = [];
for (let c = 0x20; c <= 0x7e; c++) PRINTABLE.push(String.fromCharCode(c));

console.log("layout data");
check("54 Latin layouts present", Object.keys(LAYOUTS.layouts).length === 54,
      String(Object.keys(LAYOUTS.layouts).length));
check("common layouts lead the order",
      LAYOUTS.order.slice(0, 5).join(",") === "us,gb,de,fr,dk");
check("every layout blob is 95*4 bytes",
      LAYOUTS.order.every(id => K.tableFor(id).length === 380));

console.log("\nknown-good mappings");
{
  const us = K.tableFor("us"), dk = K.tableFor("dk"), de = K.tableFor("de");
  const one = (ch, t) => K.keystrokesFor(ch, t);
  check("US '@' is Shift+2", JSON.stringify(one("@", us)) === "[[31,2]]",
        JSON.stringify(one("@", us)));
  check("Danish '@' is AltGr+2", JSON.stringify(one("@", dk)) === "[[31,64]]",
        JSON.stringify(one("@", dk)));
  check("Danish '\\\\' is AltGr on the ISO key 0x64",
        JSON.stringify(one("\\", dk)) === "[[100,64]]", JSON.stringify(one("\\", dk)));
  check("Danish '~' is a dead key then space",
        one("~", dk).length === 2 && one("~", dk)[1][0] === 0x2c,
        JSON.stringify(one("~", dk)));
  check("German QWERTZ: z and y are swapped vs US",
        one("z", de)[0][0] === K.keystrokesFor("y", us)[0][0] &&
        one("y", de)[0][0] === K.keystrokesFor("z", us)[0][0]);
  check("French AZERTY: 'a' sits on the US 'q' key",
        K.keystrokesFor("a", K.tableFor("fr"))[0][0] === 0x14);
}

console.log("\nencoding");
{
  const us = K.tableFor("us"), dk = K.tableFor("dk");
  check("plain char is one byte", hex(K.encodeProgram("a", us).bytes) === "04");
  check("shifted char sets bit 7", hex(K.encodeProgram("A", us).bytes) === "84");
  check("AltGr char uses the 0x00 escape",
        hex(K.encodeProgram("@", dk).bytes) === "00 40 1f",
        hex(K.encodeProgram("@", dk).bytes));
  check("newline maps to Enter", hex(K.encodeProgram("\n", us).bytes) === "28");
  check("non-ASCII is reported, not silently dropped",
        K.encodeProgram("ok\u00e9", us).unsupported.join("") === "\u00e9");
  // A zero byte must never appear except as an escape prefix, or the firmware
  // would mis-parse the program.
  let stray = 0;
  for (const id of LAYOUTS.order) {
    const t = K.tableFor(id);
    const b = K.encodeProgram(PRINTABLE.join(""), t).bytes;
    for (let i = 0; i < b.length; i++) {
      if (b[i] === 0) { i += 2; continue; }        // legitimate escape
      if (b[i] === 0x80) stray++;                  // shift + usage 0 = bogus
    }
  }
  check("no bogus zero-usage keystrokes in any layout", stray === 0, String(stray));
}

console.log("\nround-trip over every layout and every printable character");
{
  const text = PRINTABLE.join("");
  const broken = [];
  for (const id of LAYOUTS.order) {
    const t = K.tableFor(id);
    const { bytes, unsupported } = K.encodeProgram(text, t);
    const back = K.decodeProgram(bytes, t);
    const expected = [...text].filter(c => !unsupported.includes(c)).join("");
    if (back !== expected) broken.push(id);
  }
  check("all 54 layouts round-trip", broken.length === 0, broken.join(","));

  const common = LAYOUTS.order.slice(0, LAYOUTS.common);
  const gaps = common.filter(id =>
    K.encodeProgram(text, K.tableFor(id)).unsupported.length > 0);
  check("the 17 common layouts can type every printable ASCII char",
        gaps.length === 0, gaps.join(","));
}

console.log("\ncapacity");
{
  const pw = "Correct-Horse_Battery+Staple";
  for (const id of ["us", "dk", "de", "fr"]) {
    const n = K.encodeProgram(pw, K.tableFor(id)).bytes.length;
    console.log(`       ${id}: ${pw.length} chars -> ${n} bytes`);
  }
  check("a 28-char password fits in one 63-byte registration",
        K.encodeProgram(pw, K.tableFor("dk")).bytes.length <= 63);
}

console.log("\ntruncated input");
{
  const us = K.tableFor("us");
  // A write interrupted mid-escape must not throw or run off the end.
  const b = K.encodeProgram("a@b", K.tableFor("dk")).bytes;
  for (let cut = 0; cut <= b.length; cut++) {
    try { K.decodeProgram(b.slice(0, cut), us); }
    catch (e) { check("decode survives truncation at " + cut, false, e.message); }
  }
  check("decode survives every truncation point", true);
}

console.log("\nlayout detection");
{
  // Simulate getLayoutMap() output by reading each layout's own base chars.
  const wrong = [];
  for (const id of LAYOUTS.order) {
    const t = K.tableFor(id);
    const base = new Map();
    for (let c = 0x20; c <= 0x7e; c++) {
      const i = (c - 0x20) * 4;
      if (t[i] && t[i + 1] === 0 && !t[i + 2] && !base.has(t[i]))
        base.set(t[i], String.fromCharCode(c).toLowerCase());
    }
    const actual = {};
    for (const [code, usage] of Object.entries(K.PROBE))
      if (base.has(usage)) actual[code] = base.get(usage);
    const got = K.identifyLayout(actual);
    // Several layouts are genuinely identical in their unshifted Latin block
    // (e.g. us vs several variants); accepting any layout whose probe answers
    // match exactly is correct behaviour, so compare the probe results.
    if (got === null) { wrong.push(id + "=null"); continue; }
    const gt = K.tableFor(got);
    const gbase = new Map();
    for (let c = 0x20; c <= 0x7e; c++) {
      const i = (c - 0x20) * 4;
      if (gt[i] && gt[i + 1] === 0 && !gt[i + 2] && !gbase.has(gt[i]))
        gbase.set(gt[i], String.fromCharCode(c).toLowerCase());
    }
    for (const [code, usage] of Object.entries(K.PROBE)) {
      if (actual[code] !== undefined && gbase.get(usage) !== actual[code]) {
        wrong.push(`${id}->${got}`); break;
      }
    }
  }
  check("detection identifies a compatible layout for all 54",
        wrong.length === 0, wrong.slice(0, 6).join(" "));
  check("detection declines when given too little to go on",
        K.identifyLayout({ KeyQ: "q" }) === null);
}

console.log("\nparity with the Python encoder in tools/ctaplib.py");
{
  // The browser and the bench tool must produce byte-identical programs, or
  // text written by one and inspected by the other silently disagrees.
  const { execFileSync } = require("child_process");
  const samples = ["Correct-Horse_Battery+Staple", "a@A~", "user@example.com",
                   "p@ssw0rd!#$%^&*()", "back\\slash|pipe{brace}"];
  const layouts = ["us", "dk", "de", "fr", "gb", "se"];
  let py;
  try {
    py = execFileSync(process.env.PYTHON || "python3",
      [path.join(dir, "..", "tools", "_encode_dump.py"),
       JSON.stringify({ samples, layouts })], { encoding: "utf8" });
  } catch (e) {
    console.log("  skip parity check (" + (e.message || "").split("\n")[0] + ")");
    py = null;
  }
  if (py) {
    const want = JSON.parse(py);
    let bad = [];
    for (const lay of layouts) {
      const t = K.tableFor(lay);
      for (const s of samples) {
        const js = hex(K.encodeProgram(s, t).bytes).replace(/ /g, "");
        if (js !== want[lay][s]) bad.push(`${lay}:${JSON.stringify(s)}`);
      }
    }
    check("JS and Python encoders agree byte-for-byte", bad.length === 0,
          bad.slice(0, 3).join(" "));
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
