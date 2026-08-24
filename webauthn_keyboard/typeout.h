#pragma once
#include <stdint.h>

#include "storage.h"    // TYPEOUT_MAX

void typeout_init(void);
// Polls the trigger button. A short press types the stored string; holding it
// for TYPE_BOOTLOADER_HOLD_MS reboots into the bootloader. Call from loop().
void typeout_poll(void);
