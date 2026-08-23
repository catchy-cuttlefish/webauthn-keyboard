#include "cbor.h"
#include <string.h>
#ifdef __AVR__
#include <avr/pgmspace.h>
#endif

// ---------------------------------------------------------------- reader ---

void cbor_in_init(CborIn *in, const uint8_t *buf, size_t len)
{
  in->p = buf;
  in->end = buf + len;
  in->err = false;
}

uint8_t cbor_peek_type(CborIn *in)
{
  if (in->err || in->p >= in->end) return 0xFF;
  return in->p[0] >> 5;
}

bool cbor_head(CborIn *in, uint8_t *mt, uint32_t *val)
{
  if (in->err || in->p >= in->end) { in->err = true; return false; }

  uint8_t ib = *in->p++;
  uint8_t ai = ib & 0x1F;
  uint32_t v = 0;

  if (ai < 24) {
    v = ai;
  } else if (ai == 24) {
    if (in->end - in->p < 1) { in->err = true; return false; }
    v = *in->p++;
  } else if (ai == 25) {
    if (in->end - in->p < 2) { in->err = true; return false; }
    v = ((uint32_t)in->p[0] << 8) | in->p[1];
    in->p += 2;
  } else if (ai == 26) {
    if (in->end - in->p < 4) { in->err = true; return false; }
    v = ((uint32_t)in->p[0] << 24) | ((uint32_t)in->p[1] << 16) |
        ((uint32_t)in->p[2] << 8)  | in->p[3];
    in->p += 4;
  } else {
    // 27 (64-bit), 28..30 (reserved) and 31 (indefinite) are all unsupported.
    in->err = true;
    return false;
  }

  *mt = ib >> 5;
  *val = v;
  return true;
}

bool cbor_get_uint(CborIn *in, uint32_t *out)
{
  uint8_t mt; uint32_t v;
  if (!cbor_head(in, &mt, &v) || mt != CBOR_UINT) { in->err = true; return false; }
  *out = v;
  return true;
}

bool cbor_get_int(CborIn *in, int32_t *out)
{
  uint8_t mt; uint32_t v;
  if (!cbor_head(in, &mt, &v)) return false;
  if (mt == CBOR_UINT)      *out = (int32_t)v;
  else if (mt == CBOR_NINT) *out = -1 - (int32_t)v;
  else { in->err = true; return false; }
  return true;
}

bool cbor_get_bool(CborIn *in, bool *out)
{
  uint8_t mt; uint32_t v;
  if (!cbor_head(in, &mt, &v) || mt != CBOR_SIMPLE || (v != 20 && v != 21)) {
    in->err = true;
    return false;
  }
  *out = (v == 21);
  return true;
}

static bool cbor_get_str(CborIn *in, uint8_t want, const uint8_t **d, uint32_t *n)
{
  uint8_t mt; uint32_t v;
  if (!cbor_head(in, &mt, &v) || mt != want) { in->err = true; return false; }
  if ((uint32_t)(in->end - in->p) < v) { in->err = true; return false; }
  *d = in->p;
  *n = v;
  in->p += v;
  return true;
}

bool cbor_get_bytes(CborIn *in, const uint8_t **data, uint32_t *len)
{
  return cbor_get_str(in, CBOR_BSTR, data, len);
}

bool cbor_get_text(CborIn *in, const char **data, uint32_t *len)
{
  return cbor_get_str(in, CBOR_TSTR, (const uint8_t **)data, len);
}

bool cbor_enter_map(CborIn *in, uint32_t *n)
{
  uint8_t mt;
  if (!cbor_head(in, &mt, n) || mt != CBOR_MAP) { in->err = true; return false; }
  return true;
}

bool cbor_enter_array(CborIn *in, uint32_t *n)
{
  uint8_t mt;
  if (!cbor_head(in, &mt, n) || mt != CBOR_ARRAY) { in->err = true; return false; }
  return true;
}

bool cbor_skip(CborIn *in)
{
  // Iterative with an explicit pending counter: no recursion, so deeply nested
  // (or hostile) input cannot blow the 2.5 KB stack.
  uint32_t pending = 1;
  while (pending) {
    uint8_t mt; uint32_t v;
    if (!cbor_head(in, &mt, &v)) return false;
    pending--;
    switch (mt) {
      case CBOR_BSTR:
      case CBOR_TSTR:
        if ((uint32_t)(in->end - in->p) < v) { in->err = true; return false; }
        in->p += v;
        break;
      case CBOR_ARRAY:
        if (v > 0xFFFF) { in->err = true; return false; }
        pending += v;
        break;
      case CBOR_MAP:
        if (v > 0x7FFF) { in->err = true; return false; }
        pending += v * 2;
        break;
      default:
        break;
    }
    if (pending > 0xFFFF) { in->err = true; return false; }
  }
  return true;
}

bool cbor_text_is(CborIn *in, const char *s)
{
  CborIn save = *in;
  const char *d; uint32_t n;
  if (!cbor_get_text(in, &d, &n)) { *in = save; return false; }
  size_t sl = strlen(s);
  if (n != sl || memcmp(d, s, sl) != 0) { *in = save; return false; }
  return true;
}

// ---------------------------------------------------------------- writer ---

void cbor_out_init(CborOut *o, uint8_t *buf, size_t cap)
{
  o->buf = buf;
  o->cap = cap;
  o->len = 0;
  o->err = false;
}

void cbor_raw(CborOut *o, const uint8_t *d, size_t n)
{
  if (o->err || o->len + n > o->cap) { o->err = true; return; }
  memcpy(o->buf + o->len, d, n);
  o->len += n;
}

void cbor_byte(CborOut *o, uint8_t b)
{
  if (o->err || o->len + 1 > o->cap) { o->err = true; return; }
  o->buf[o->len++] = b;
}

void cbor_head_out(CborOut *o, uint8_t mt, uint32_t val)
{
  uint8_t t = (uint8_t)(mt << 5);
  if (val < 24) {
    cbor_byte(o, (uint8_t)(t | val));
  } else if (val < 0x100) {
    cbor_byte(o, (uint8_t)(t | 24));
    cbor_byte(o, (uint8_t)val);
  } else if (val < 0x10000) {
    cbor_byte(o, (uint8_t)(t | 25));
    cbor_byte(o, (uint8_t)(val >> 8));
    cbor_byte(o, (uint8_t)val);
  } else {
    cbor_byte(o, (uint8_t)(t | 26));
    cbor_byte(o, (uint8_t)(val >> 24));
    cbor_byte(o, (uint8_t)(val >> 16));
    cbor_byte(o, (uint8_t)(val >> 8));
    cbor_byte(o, (uint8_t)val);
  }
}

void cbor_uint(CborOut *o, uint32_t v)          { cbor_head_out(o, CBOR_UINT, v); }
void cbor_bool(CborOut *o, bool v)              { cbor_byte(o, v ? 0xF5 : 0xF4); }
void cbor_map(CborOut *o, uint32_t n)           { cbor_head_out(o, CBOR_MAP, n); }
void cbor_array(CborOut *o, uint32_t n)         { cbor_head_out(o, CBOR_ARRAY, n); }

void cbor_int(CborOut *o, int32_t v)
{
  if (v < 0) cbor_head_out(o, CBOR_NINT, (uint32_t)(-1 - v));
  else       cbor_head_out(o, CBOR_UINT, (uint32_t)v);
}

void cbor_bstr(CborOut *o, const uint8_t *d, uint32_t n)
{
  cbor_head_out(o, CBOR_BSTR, n);
  cbor_raw(o, d, n);
}

void cbor_tstr_n(CborOut *o, const char *s, uint32_t n)
{
  cbor_head_out(o, CBOR_TSTR, n);
  cbor_raw(o, (const uint8_t *)s, n);
}

void cbor_tstr(CborOut *o, const char *s)
{
  cbor_tstr_n(o, s, (uint32_t)strlen(s));
}

#ifdef __AVR__
void cbor_tstr_P(CborOut *o, const char *progmem_s)
{
  uint32_t n = (uint32_t)strlen_P(progmem_s);
  cbor_head_out(o, CBOR_TSTR, n);
  if (o->err || o->len + n > o->cap) { o->err = true; return; }
  memcpy_P(o->buf + o->len, progmem_s, n);
  o->len += n;
}
#endif
