// Just enough CBOR (RFC 8949, canonical/CTAP subset) for CTAP2.
// Deliberately limited: no floats, no tags, no indefinite lengths, no 64-bit
// integers. CTAP2 requests never need them.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CBOR_UINT   0
#define CBOR_NINT   1
#define CBOR_BSTR   2
#define CBOR_TSTR   3
#define CBOR_ARRAY  4
#define CBOR_MAP    5
#define CBOR_SIMPLE 7

// ---------------------------------------------------------------- reader ---
typedef struct {
  const uint8_t *p;
  const uint8_t *end;
  bool           err;
} CborIn;

void cbor_in_init(CborIn *in, const uint8_t *buf, size_t len);
// Peeks the major type of the next item (returns 0xFF at end / on error).
uint8_t cbor_peek_type(CborIn *in);
// Reads a head; `val` gets the argument. Returns false on error.
bool cbor_head(CborIn *in, uint8_t *mt, uint32_t *val);
bool cbor_get_uint(CborIn *in, uint32_t *out);
bool cbor_get_int(CborIn *in, int32_t *out);
bool cbor_get_bool(CborIn *in, bool *out);
// Byte/text strings are returned as pointers *into* the request buffer; no copy.
bool cbor_get_bytes(CborIn *in, const uint8_t **data, uint32_t *len);
bool cbor_get_text(CborIn *in, const char **data, uint32_t *len);
bool cbor_enter_map(CborIn *in, uint32_t *n);
bool cbor_enter_array(CborIn *in, uint32_t *n);
// Skips one complete data item (recursing into containers).
bool cbor_skip(CborIn *in);
// Compares the next text string against `s` without consuming on mismatch.
bool cbor_text_is(CborIn *in, const char *s);

// ---------------------------------------------------------------- writer ---
typedef struct {
  uint8_t *buf;
  size_t   cap;
  size_t   len;
  bool     err;
} CborOut;

void cbor_out_init(CborOut *o, uint8_t *buf, size_t cap);
void cbor_raw(CborOut *o, const uint8_t *d, size_t n);
void cbor_byte(CborOut *o, uint8_t b);
void cbor_head_out(CborOut *o, uint8_t mt, uint32_t val);
void cbor_uint(CborOut *o, uint32_t v);
void cbor_int(CborOut *o, int32_t v);
void cbor_bool(CborOut *o, bool v);
void cbor_bstr(CborOut *o, const uint8_t *d, uint32_t n);
void cbor_tstr(CborOut *o, const char *s);
void cbor_tstr_n(CborOut *o, const char *s, uint32_t n);
void cbor_map(CborOut *o, uint32_t n);
void cbor_array(CborOut *o, uint32_t n);
#ifdef __AVR__
void cbor_tstr_P(CborOut *o, const char *progmem_s);
#else
#define cbor_tstr_P(o, s) cbor_tstr((o), (s))
#endif
