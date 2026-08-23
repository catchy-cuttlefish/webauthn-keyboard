#pragma once
#include <stdint.h>

// TYPEOUT_MAX lives in storage.h: it depends on whether the largeBlob array is
// compiled in and therefore how much EEPROM is left.
#include "storage.h"

void typeout_init(void);
// Types the stored string immediately, bypassing the button.
void typeout_trigger(void);
// Diagnostics from the last type-out: characters attempted, and reports the
// host failed to collect. Used by the ALLOW_REMOTE_TYPE test hook.
extern uint16_t typeout_last_chars;
extern uint16_t typeout_last_fails;
// Polls the trigger button; types the stored string on a debounced press.
// Call from loop().
void typeout_poll(void);
// True while a string is being typed (used to refuse concurrent CTAP work).
bool typeout_busy(void);
