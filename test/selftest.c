// Host-side known-answer tests for the portable parts of the firmware.
//   cc -O2 -o t test/selftest.c webauthn_largeblob/sha256.cpp webauthn_largeblob/cbor.cpp && ./t
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../webauthn_largeblob/sha256.h"
#include "../webauthn_largeblob/cbor.h"

static int fails = 0;

static void hex(const uint8_t *d, size_t n, char *out)
{
  for (size_t i = 0; i < n; i++) sprintf(out + i * 2, "%02x", d[i]);
}

static void check(const char *name, const uint8_t *got, size_t n, const char *want)
{
  char buf[256];
  hex(got, n, buf);
  if (strcmp(buf, want) == 0) {
    printf("  ok   %s\n", name);
  } else {
    printf("  FAIL %s\n       got  %s\n       want %s\n", name, buf, want);
    fails++;
  }
}

static void test_sha256(void)
{
  uint8_t d[32];
  puts("SHA-256 (NIST/RFC vectors)");

  sha256((const uint8_t *)"", 0, d);
  check("empty", d, 32,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  sha256((const uint8_t *)"abc", 3, d);
  check("abc", d, 32,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  // 56 bytes: exercises the padding path that needs a second block.
  sha256((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
  check("448-bit", d, 32,
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

  // 1,000,000 x 'a': many blocks, checks the 64-bit length counter.
  {
    sha256_ctx c;
    uint8_t a[1000];
    memset(a, 'a', sizeof(a));
    sha256_init(&c);
    for (int i = 0; i < 1000; i++) sha256_update(&c, a, sizeof(a));
    sha256_final(&c, d);
    check("1e6 x 'a'", d, 32,
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  }

  // Odd-sized incremental updates must match a one-shot hash.
  {
    uint8_t one[32], inc[32];
    uint8_t msg[300];
    for (int i = 0; i < 300; i++) msg[i] = (uint8_t)(i * 7 + 3);
    sha256(msg, 300, one);
    sha256_ctx c;
    sha256_init(&c);
    size_t off = 0;
    for (size_t step = 1; off < 300; step = step * 2 + 1) {
      size_t n = (off + step > 300) ? 300 - off : step;
      sha256_update(&c, msg + off, n);
      off += n;
    }
    sha256_final(&c, inc);
    if (memcmp(one, inc, 32) == 0) puts("  ok   incremental == one-shot");
    else { puts("  FAIL incremental != one-shot"); fails++; }
  }
}

static void test_hmac(void)
{
  uint8_t d[32];
  puts("HMAC-SHA-256 (RFC 4231)");

  {
    uint8_t key[20];
    memset(key, 0x0b, sizeof(key));
    hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, d);
    check("case 1", d, 32,
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  }
  {
    hmac_sha256((const uint8_t *)"Jefe", 4,
                (const uint8_t *)"what do ya want for nothing?", 28, d);
    check("case 2", d, 32,
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  }
  {
    // Key longer than the 64-byte block, forcing the hash-the-key path.
    uint8_t key[131];
    const char *msg = "Test Using Larger Than Block-Size Key - Hash Key First";
    memset(key, 0xaa, sizeof(key));
    hmac_sha256(key, 131, (const uint8_t *)msg, strlen(msg), d);
    check("case 6 (long key)", d, 32,
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
  }
}

// The exact bytes the authenticator must ship on a factory-fresh device:
// CBOR [] followed by the first 16 bytes of SHA-256(0x80).
static void test_empty_large_blob(void)
{
  uint8_t empty = 0x80, d[32];
  puts("largeBlob empty-array checksum (CTAP2.1 6.10)");
  sha256(&empty, 1, d);
  check("trunc16(SHA256(0x80))", d, 16, "76be8b528d0075f7aae98d6fa57a6d3c");
}

static void test_cbor_roundtrip(void)
{
  uint8_t buf[256];
  CborOut o;
  CborIn in;
  puts("CBOR");

  // Canonical head encodings.
  cbor_out_init(&o, buf, sizeof(buf));
  cbor_uint(&o, 23); cbor_uint(&o, 24); cbor_uint(&o, 255);
  cbor_uint(&o, 256); cbor_uint(&o, 65536);
  check("uint heads", buf, o.len, "17" "1818" "18ff" "190100" "1a00010000");

  cbor_out_init(&o, buf, sizeof(buf));
  cbor_int(&o, -7);
  check("int -7 (ES256 alg)", buf, o.len, "26");

  // A getAssertion-shaped map, then read it back.
  cbor_out_init(&o, buf, sizeof(buf));
  cbor_map(&o, 2);
  cbor_uint(&o, 1); cbor_tstr(&o, "example.com");
  cbor_uint(&o, 2); { uint8_t h[4] = {1,2,3,4}; cbor_bstr(&o, h, 4); }
  assert(!o.err);

  cbor_in_init(&in, buf, o.len);
  uint32_t n;
  assert(cbor_enter_map(&in, &n) && n == 2);
  uint32_t k;
  assert(cbor_get_uint(&in, &k) && k == 1);
  const char *s; uint32_t sl;
  assert(cbor_get_text(&in, &s, &sl) && sl == 11 && memcmp(s, "example.com", 11) == 0);
  assert(cbor_get_uint(&in, &k) && k == 2);
  const uint8_t *b; uint32_t bl;
  assert(cbor_get_bytes(&in, &b, &bl) && bl == 4 && b[0] == 1 && b[3] == 4);
  puts("  ok   map round-trip");

  // cbor_skip must step over nested containers exactly.
  cbor_out_init(&o, buf, sizeof(buf));
  cbor_map(&o, 2);
  cbor_uint(&o, 1);
  cbor_array(&o, 2);
    cbor_map(&o, 1); cbor_tstr(&o, "alg"); cbor_int(&o, -7);
    cbor_map(&o, 1); cbor_tstr(&o, "alg"); cbor_int(&o, -257);
  cbor_uint(&o, 2); cbor_bool(&o, true);
  assert(!o.err);

  cbor_in_init(&in, buf, o.len);
  assert(cbor_enter_map(&in, &n) && n == 2);
  assert(cbor_get_uint(&in, &k) && k == 1);
  assert(cbor_skip(&in));                       // skip the whole array
  assert(cbor_get_uint(&in, &k) && k == 2);
  bool v = false;
  assert(cbor_get_bool(&in, &v) && v);
  assert(in.p == in.end && !in.err);
  puts("  ok   skip nested array-of-maps");

  // Truncated input must set the error flag, never read past the end.
  cbor_in_init(&in, buf, 3);
  cbor_skip(&in);
  assert(in.err);
  puts("  ok   truncated input rejected");

  // Indefinite-length and 64-bit heads are unsupported -> must error, not crash.
  {
    uint8_t bad[] = { 0x9f, 0x01, 0xff };        // indefinite array
    cbor_in_init(&in, bad, sizeof(bad));
    assert(!cbor_skip(&in) && in.err);
    uint8_t big[] = { 0x1b, 0,0,0,0,0,0,0,1 };   // 64-bit uint
    cbor_in_init(&in, big, sizeof(big));
    assert(!cbor_skip(&in) && in.err);
    puts("  ok   unsupported heads rejected");
  }

  // Writer must refuse to overflow its buffer.
  {
    uint8_t small[4];
    cbor_out_init(&o, small, sizeof(small));
    uint8_t junk[64] = {0};
    cbor_bstr(&o, junk, 64);
    assert(o.err && o.len <= sizeof(small));
    puts("  ok   writer bounds-checked");
  }
}

int main(void)
{
  test_sha256();
  test_hmac();
  test_empty_large_blob();
  test_cbor_roundtrip();
  printf("\n%s\n", fails ? "FAILURES" : "all tests passed");
  return fails != 0;
}
