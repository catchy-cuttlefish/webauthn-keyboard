// Device state.
//
// The type-out text and the discoverable credential live in RAM and are lost
// when the board loses power. That is deliberate: the text is a secret the
// device will type on demand, so keeping it out of non-volatile storage means a
// chip that is unplugged (or desoldered, or read with a programmer) yields
// nothing. The cost is that a browser must write the text again on every
// plug-in.
//
// The credential slot is volatile for the same reason and for consistency: it
// holds a copy of the text in its user handle, so a persistent credential would
// report stale text after a replug while the button typed nothing.
//
// Only the master secret and the signature counter persist:
//
//   EEPROM (1024 bytes, 916 unused)
//     0x000  4    magic "FLB3"
//     0x004  32   master secret (credential IDs are derived from this)
//     0x024  4    signature counter, uint32 LE
#pragma once
#include <stdint.h>
#include <stdbool.h>

#define EE_MAGIC_ADDR    0x000
#define EE_MASTER_ADDR   0x004
#define EE_COUNTER_ADDR  0x024

#define CRED_NONCE_LEN   16
#define MAX_USER_ID_LEN  64
#define TYPEOUT_MAX      512

void     store_init(void);                       // formats EEPROM on first boot
void     store_reset(void);                      // authenticatorReset
void     store_master(uint8_t out[32]);
uint32_t store_next_counter(void);               // increments and persists

// --- discoverable credential (volatile) --------------------------------------
bool     store_rk_match(const uint8_t rpIdHash[32]);
bool     store_rk_nonce(uint8_t nonce[CRED_NONCE_LEN]);
uint8_t  store_rk_userid(uint8_t userId[MAX_USER_ID_LEN]);
void     store_rk_put(const uint8_t rpIdHash[32], const uint8_t nonce[CRED_NONCE_LEN],
                      const uint8_t *userId, uint8_t userIdLen);

// --- type-out keystroke program (volatile) -----------------------------------
// Bytes are HID keystrokes, not characters -- see typeout.cpp for the encoding.
// The layout mapping is done by whoever writes the data, because USB keyboards
// have no notion of characters at all.
uint16_t store_text_len(void);
uint8_t  store_text_byte(uint16_t i);
void     store_text_set(const uint8_t *src, uint16_t len);
// Stores a chunk delivered through WebAuthn's user.id field. src[0] is a
// control byte: 0 = replace the stored text, non-zero = append to it. The rest
// is payload. Appending is what makes strings longer than one 64-byte user.id
// possible, at the cost of one create() call per chunk.
void     store_text_chunk(const uint8_t *src, uint16_t len);
