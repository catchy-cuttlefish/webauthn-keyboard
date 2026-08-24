#include "storage.h"
#include "sha256.h"
#include <Arduino.h>
#include <EEPROM.h>
#include <string.h>

// Bump this whenever the EEPROM map changes, so an old layout is reformatted
// instead of being reinterpreted as garbage. '2' = user.id type-out layout.
static const uint8_t EE_MAGIC[4] = { 'F', 'L', 'B', '2' };

void (*store_keepalive_hook)(void) = NULL;

// ---------------------------------------------------------------------------
// Entropy. The ATmega32u4 has no TRNG. We whisk together ADC noise from a
// floating pin, timer jitter and the existing EEPROM contents. This is enough
// for a hobby/test device; it is NOT a substitute for a real entropy source and
// the resulting master secret is stored in EEPROM in the clear, readable by
// anyone who can attach an ISP programmer.
// ---------------------------------------------------------------------------
static void gather_entropy(uint8_t out[32])
{
  sha256_ctx c;
  sha256_init(&c);

  for (uint16_t i = 0; i < 256; i++) {
    uint8_t s[4];
    uint16_t a = (uint16_t)analogRead(A0) ^ (uint16_t)analogRead(A1);
    uint32_t t = micros();
    s[0] = (uint8_t)a;
    s[1] = (uint8_t)(a >> 8);
    s[2] = (uint8_t)t;
    s[3] = (uint8_t)(t >> 8) ^ (uint8_t)(t >> 16);
    sha256_update(&c, s, 4);
    delayMicroseconds(37 + (a & 0x3F));
  }
  for (uint16_t i = 0; i < 1024; i++) {
    uint8_t b = EEPROM.read(i);
    sha256_update(&c, &b, 1);
  }
  sha256_final(&c, out);
}

static void ee_read(uint16_t addr, uint8_t *dst, uint16_t len)
{
  while (len--) *dst++ = EEPROM.read(addr++);
}

static void ee_write(uint16_t addr, const uint8_t *src, uint16_t len)
{
  while (len--) EEPROM.update(addr++, *src++);
}

// ---------------------------------------------------------------------------

void store_init(void)
{
  uint8_t magic[4];
  ee_read(EE_MAGIC_ADDR, magic, 4);
  if (memcmp(magic, EE_MAGIC, 4) == 0) return;
  store_reset();
}

void store_reset(void)
{
  uint8_t master[32];
  gather_entropy(master);

  ee_write(EE_MASTER_ADDR, master, 32);
  memset(master, 0, sizeof(master));

  for (uint8_t i = 0; i < 4; i++) EEPROM.update(EE_COUNTER_ADDR + i, 0);
  EEPROM.update(EE_RK_VALID, 0);
  EEPROM.update(EE_TEXT_LEN, 0);
  EEPROM.update(EE_TEXT_LEN + 1, 0);
  ee_write(EE_MAGIC_ADDR, EE_MAGIC, 4);
}

void store_master(uint8_t out[32])
{
  ee_read(EE_MASTER_ADDR, out, 32);
}

uint32_t store_next_counter(void)
{
  uint32_t v = 0;
  for (int8_t i = 3; i >= 0; i--) v = (v << 8) | EEPROM.read(EE_COUNTER_ADDR + i);
  v++;
  for (uint8_t i = 0; i < 4; i++) EEPROM.update(EE_COUNTER_ADDR + i, (uint8_t)(v >> (8 * i)));
  return v;
}

bool store_rk_match(const uint8_t rpIdHash[32])
{
  if (EEPROM.read(EE_RK_VALID) != 1) return false;
  for (uint8_t i = 0; i < 32; i++)
    if (EEPROM.read(EE_RK_RPIDHASH + i) != rpIdHash[i]) return false;
  return true;
}

bool store_rk_nonce(uint8_t nonce[CRED_NONCE_LEN])
{
  if (EEPROM.read(EE_RK_VALID) != 1) return false;
  ee_read(EE_RK_NONCE, nonce, CRED_NONCE_LEN);
  return true;
}

uint8_t store_rk_userid(uint8_t userId[MAX_USER_ID_LEN])
{
  if (EEPROM.read(EE_RK_VALID) != 1) return 0;
  uint8_t n = EEPROM.read(EE_RK_UIDLEN);
  if (n > MAX_USER_ID_LEN) n = MAX_USER_ID_LEN;
  ee_read(EE_RK_UID, userId, n);
  return n;
}

void store_rk_put(const uint8_t rpIdHash[32], const uint8_t nonce[CRED_NONCE_LEN],
                  const uint8_t *userId, uint8_t userIdLen)
{
  if (userIdLen > MAX_USER_ID_LEN) userIdLen = MAX_USER_ID_LEN;
  ee_write(EE_RK_RPIDHASH, rpIdHash, 32);
  ee_write(EE_RK_NONCE, nonce, CRED_NONCE_LEN);
  EEPROM.update(EE_RK_UIDLEN, userIdLen);
  ee_write(EE_RK_UID, userId, userIdLen);
  EEPROM.update(EE_RK_VALID, 1);
}

// --- type-out text -----------------------------------------------------------

uint16_t store_text_len(void)
{
  uint16_t n = (uint16_t)EEPROM.read(EE_TEXT_LEN) |
               ((uint16_t)EEPROM.read(EE_TEXT_LEN + 1) << 8);
  return n > TYPEOUT_MAX ? 0 : n;
}

uint8_t store_text_byte(uint16_t i)
{
  if (i >= TYPEOUT_MAX) return 0;
  return EEPROM.read(EE_TEXT_DATA + i);
}

static void text_store(const uint8_t *src, uint16_t len, uint16_t off)
{
  if (off > TYPEOUT_MAX) off = TYPEOUT_MAX;
  if ((uint32_t)off + len > TYPEOUT_MAX) len = TYPEOUT_MAX - off;
  for (uint16_t i = 0; i < len; i++) {
    EEPROM.update(EE_TEXT_DATA + off + i, src[i]);
    if ((i & 0x1F) == 0x1F && store_keepalive_hook) store_keepalive_hook();
  }
  uint16_t total = off + len;
  EEPROM.update(EE_TEXT_LEN,     (uint8_t)total);
  EEPROM.update(EE_TEXT_LEN + 1, (uint8_t)(total >> 8));
}

void store_text_set(const uint8_t *src, uint16_t len)
{
  text_store(src, len, 0);
}

void store_text_chunk(const uint8_t *src, uint16_t len)
{
  if (len < 1) return;
  text_store(src + 1, len - 1, src[0] ? store_text_len() : 0);
}
