// Minimal SHA-256 + HMAC-SHA-256 for AVR.
#pragma once
#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t  buf[SHA256_BLOCK_SIZE];
  uint8_t  buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const uint8_t *data, size_t len, uint8_t out[32]);

typedef struct {
  sha256_ctx inner;
  uint8_t    okey[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx;

void hmac_sha256_init(hmac_sha256_ctx *c, const uint8_t *key, size_t keylen);
void hmac_sha256_update(hmac_sha256_ctx *c, const uint8_t *data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *data, size_t len, uint8_t out[32]);
