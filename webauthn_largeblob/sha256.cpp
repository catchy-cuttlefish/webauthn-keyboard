#include "sha256.h"
#include <string.h>

#ifdef __AVR__
#include <avr/pgmspace.h>
#define K_READ(i) ((uint32_t)pgm_read_dword(&K[i]))
#else
#define PROGMEM
#define K_READ(i) (K[i])
#endif

static const uint32_t K[64] PROGMEM = {
  0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,
  0x923f82a4UL,0xab1c5ed5UL,0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
  0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,0xe49b69c1UL,0xefbe4786UL,
  0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
  0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,
  0x06ca6351UL,0x14292967UL,0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
  0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,0xa2bfe8a1UL,0xa81a664bUL,
  0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
  0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,
  0x5b9cca4fUL,0x682e6ff3UL,0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
  0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

#define ROR(x,n) (((x) >> (n)) | ((x) << (32-(n))))

// ~2.3 KB of flash. That is not a mistake or a missing optimisation: the AVR
// has no barrel shifter, so every 32-bit rotate in the round function expands
// into a byte shuffle plus shifts. It is the single largest function in the
// firmware after the CTAP command handlers.
static void sha256_compress(uint32_t *st, const uint8_t *blk)
{
  uint32_t w[16];
  uint32_t a,b,c,d,e,f,g,h;
  uint8_t i;

  for (i = 0; i < 16; i++) {
    w[i] = ((uint32_t)blk[i*4] << 24) | ((uint32_t)blk[i*4+1] << 16) |
           ((uint32_t)blk[i*4+2] << 8) | (uint32_t)blk[i*4+3];
  }

  a=st[0]; b=st[1]; c=st[2]; d=st[3]; e=st[4]; f=st[5]; g=st[6]; h=st[7];

  for (i = 0; i < 64; i++) {
    uint32_t s0, s1, t1, t2, wi;
    if (i < 16) {
      wi = w[i];
    } else {
      /* Rolling 16-word schedule keeps RAM at 64 bytes instead of 256. */
      uint32_t w15 = w[(i+1) & 15];
      uint32_t w2  = w[(i+14) & 15];
      s0 = ROR(w15,7) ^ ROR(w15,18) ^ (w15 >> 3);
      s1 = ROR(w2,17) ^ ROR(w2,19) ^ (w2 >> 10);
      wi = w[i & 15] = w[i & 15] + s0 + w[(i+9) & 15] + s1;
    }
    s1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
    t1 = h + s1 + ((e & f) ^ ((~e) & g)) + K_READ(i) + wi;
    s0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
    t2 = s0 + ((a & b) ^ (a & c) ^ (b & c));
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }

  st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
  st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

void sha256_init(sha256_ctx *c)
{
  c->state[0]=0x6a09e667UL; c->state[1]=0xbb67ae85UL;
  c->state[2]=0x3c6ef372UL; c->state[3]=0xa54ff53aUL;
  c->state[4]=0x510e527fUL; c->state[5]=0x9b05688cUL;
  c->state[6]=0x1f83d9abUL; c->state[7]=0x5be0cd19UL;
  c->bitlen = 0;
  c->buflen = 0;
}

void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len)
{
  while (len) {
    size_t n = SHA256_BLOCK_SIZE - c->buflen;
    if (n > len) n = len;
    memcpy(c->buf + c->buflen, data, n);
    c->buflen += (uint8_t)n;
    data += n;
    len  -= n;
    if (c->buflen == SHA256_BLOCK_SIZE) {
      sha256_compress(c->state, c->buf);
      c->bitlen += 512;
      c->buflen = 0;
    }
  }
}

void sha256_final(sha256_ctx *c, uint8_t out[32])
{
  uint64_t total = c->bitlen + (uint64_t)c->buflen * 8;
  uint8_t i;

  c->buf[c->buflen++] = 0x80;
  if (c->buflen > 56) {
    while (c->buflen < SHA256_BLOCK_SIZE) c->buf[c->buflen++] = 0;
    sha256_compress(c->state, c->buf);
    c->buflen = 0;
  }
  while (c->buflen < 56) c->buf[c->buflen++] = 0;
  for (i = 0; i < 8; i++) c->buf[56+i] = (uint8_t)(total >> (56 - 8*i));
  sha256_compress(c->state, c->buf);

  for (i = 0; i < 8; i++) {
    out[i*4]   = (uint8_t)(c->state[i] >> 24);
    out[i*4+1] = (uint8_t)(c->state[i] >> 16);
    out[i*4+2] = (uint8_t)(c->state[i] >> 8);
    out[i*4+3] = (uint8_t)(c->state[i]);
  }
}

void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
  sha256_ctx c;
  sha256_init(&c);
  sha256_update(&c, data, len);
  sha256_final(&c, out);
}

void hmac_sha256_init(hmac_sha256_ctx *c, const uint8_t *key, size_t keylen)
{
  uint8_t k[SHA256_BLOCK_SIZE];
  uint8_t i;

  memset(k, 0, sizeof(k));
  if (keylen > SHA256_BLOCK_SIZE) sha256(key, keylen, k);
  else memcpy(k, key, keylen);

  for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
    c->okey[i] = k[i] ^ 0x5c;
    k[i]      ^= 0x36;
  }
  sha256_init(&c->inner);
  sha256_update(&c->inner, k, SHA256_BLOCK_SIZE);
  memset(k, 0, sizeof(k));
}

void hmac_sha256_update(hmac_sha256_ctx *c, const uint8_t *data, size_t len)
{
  sha256_update(&c->inner, data, len);
}

void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[32])
{
  uint8_t ihash[32];
  sha256_ctx outer;

  sha256_final(&c->inner, ihash);
  sha256_init(&outer);
  sha256_update(&outer, c->okey, SHA256_BLOCK_SIZE);
  sha256_update(&outer, ihash, 32);
  sha256_final(&outer, out);
  memset(c->okey, 0, sizeof(c->okey));
}

void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t len, uint8_t out[32])
{
  hmac_sha256_ctx c;
  hmac_sha256_init(&c, key, keylen);
  hmac_sha256_update(&c, data, len);
  hmac_sha256_final(&c, out);
}
