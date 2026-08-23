// Persistent state in the ATmega32u4's 1 KB internal EEPROM.
//
// Layout (1024 bytes total, ~348 spare):
//   0x000  4    magic "FLB2"
//   0x004  32   master secret (all credential keys are derived from this)
//   0x024  4    signature counter, uint32 LE
//   0x028  1    resident-credential slot valid flag
//   0x029  32   resident slot: rpIdHash
//   0x049  16   resident slot: credential nonce
//   0x059  1    resident slot: userId length
//   0x05A  64   resident slot: userId
//   0x0A0  2    committed largeBlob array length, uint16 LE
//   0x0A4  512  serialized largeBlob array
#pragma once
#include <stdint.h>
#include "config.h"
#include <stdbool.h>

#define EE_MAGIC_ADDR    0x000
#define EE_MASTER_ADDR   0x004
#define EE_COUNTER_ADDR  0x024
#define EE_RK_VALID      0x028
#define EE_RK_RPIDHASH   0x029
#define EE_RK_NONCE      0x049
#define EE_RK_UIDLEN     0x059
#define EE_RK_UID        0x05A
#if ENABLE_LARGEBLOB
#define EE_BLOB_LEN      0x0A0
#define EE_BLOB_DATA     0x0A4
#define EE_TEXT_LEN      0x2A4
#define EE_TEXT_DATA     0x2A6
#define TYPEOUT_MAX      256
#else
// No blob array: the type-out text takes over that whole region.
#define EE_TEXT_LEN      0x0A0
#define EE_TEXT_DATA     0x0A4
#define TYPEOUT_MAX      512
#endif

#define CRED_NONCE_LEN   16
#define MAX_USER_ID_LEN  64

// Deliberately below the CTAP2.1 minimum of 1024: the whole EEPROM is only
// 1 KB, and 512 bytes is ample for the ASCII payloads this device targets.
#define LARGE_BLOB_MAX   512

void     store_init(void);                       // formats on first boot
void     store_reset(void);                      // authenticatorReset
void     store_master(uint8_t out[32]);
uint32_t store_next_counter(void);               // increments and persists
bool     store_rk_match(const uint8_t rpIdHash[32]);
// Split accessors so a caller that only wants the nonce need not put a
// 64-byte user-handle buffer on the stack.
bool     store_rk_nonce(uint8_t nonce[CRED_NONCE_LEN]);
uint8_t  store_rk_userid(uint8_t userId[MAX_USER_ID_LEN]);
void     store_rk_put(const uint8_t rpIdHash[32], const uint8_t nonce[CRED_NONCE_LEN],
                      const uint8_t *userId, uint8_t userIdLen);

#if ENABLE_LARGEBLOB
uint16_t store_blob_len(void);
void     store_blob_read(uint16_t offset, uint8_t *dst, uint16_t len);
// Writes with EEPROM.update() semantics; calls the keepalive hook periodically
// because a full 512-byte page rewrite takes ~1.7 s.
void     store_blob_write(uint16_t offset, const uint8_t *src, uint16_t len);
void     store_blob_commit_len(uint16_t len);
void     store_blob_reset(void);                 // restore empty-array + checksum
#endif

// --- type-out text -----------------------------------------------------------
// Held in the clear. Any device that types a secret on a button press must be
// able to read that secret back, so there is no version of this feature where
// the plaintext is not recoverable from the chip.
#if ENABLE_TYPEOUT
uint16_t store_text_len(void);
uint8_t  store_text_byte(uint16_t i);
void     store_text_set(const uint8_t *src, uint16_t len);
// Stores a chunk delivered through WebAuthn's user.id field. src[0] is a
// control byte: 0 = replace the stored text, non-zero = append to it. The rest
// is payload. Appending is what makes strings longer than one 64-byte user.id
// possible, at the cost of one create() call (~5 s) per chunk.
void     store_text_chunk(const uint8_t *src, uint16_t len);
#endif

// Installed by the CTAPHID layer so long EEPROM writes don't trip host timeouts.
extern void (*store_keepalive_hook)(void);
