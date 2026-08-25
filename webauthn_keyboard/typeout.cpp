#include "typeout.h"
#include "config.h"

#include "storage.h"
#include "FidoHID.h"

#include <Arduino.h>
#include <avr/wdt.h>

// The device stores a keystroke program, not text.
//
// USB keyboards transmit HID usage IDs -- "the key in position X" -- and the
// host turns those into characters using whatever layout it has active. There
// is no character encoding on the wire, so a device holding ASCII has to guess
// the host's layout, and gets it wrong for everyone outside the US: on a Danish
// layout usage 0x33 is 'ae', not ';', and '@' is AltGr+2 rather than Shift+2.
//
// So the layout mapping lives in the page that writes the text, which knows
// (or can ask) what layout the machine uses. Because the text is volatile and
// rewritten on every plug-in, the machine that writes it is always the machine
// that will type it, so its layout is the right one by construction.
//
// Encoding, one or three bytes per keystroke:
//
//   b == 0x00   escape: the next two bytes are a modifier byte and a usage id.
//               Used for AltGr and anything else that is not a plain Shift.
//   b != 0x00   usage = b & 0x7F, and bit 7 means "hold Left Shift".
//
// Usage ids used for typing are all <= 0x64, so bit 7 is free and a zero byte
// is never a valid usage.
#define ESC_PREFIX  0x00
#define SHIFT_FLAG  0x80
#define MOD_LSHIFT  0x02

static bool     wasDown   = false;
static uint32_t lastEdge  = 0;
static uint32_t pressedAt = 0;
static bool     armed     = false;   // long-press already consumed?

void typeout_init(void)
{
  BTN_INIT();
  wasDown = BTN_PRESSED();
}

static void type_program(void)
{
  uint16_t n = store_text_len();
  if (n == 0 || !FidoHID.keyboardReady()) return;

  LED_ON();

  uint16_t i = 0;
  while (i < n) {
    uint8_t mod, usage;
    uint8_t b = store_text_byte(i++);

    if (b == ESC_PREFIX) {
      if (i + 1 > n - 1) break;            // truncated escape; ignore the tail
      mod   = store_text_byte(i++);
      usage = store_text_byte(i++);
    } else {
      usage = b & 0x7F;
      mod   = (b & SHIFT_FLAG) ? MOD_LSHIFT : 0;
    }
    if (usage == 0) continue;

    FidoHID.keyReport(mod, usage);
    delay(TYPE_KEY_DELAY_MS);
    FidoHID.keyReport(0, 0);        // release, so repeated keys register
    delay(TYPE_KEY_DELAY_MS);
  }

  LED_OFF();
}

static void enter_bootloader(void)
{
  // Blink fast so it is obvious the long press registered.
  for (uint8_t i = 0; i < 6; i++) {
    LED_ON();  delay(60);
    LED_OFF(); delay(60);
  }
  *(volatile uint16_t *)0x0800 = 0x7777;
  wdt_enable(WDTO_120MS);
  for (;;) { }
}

void typeout_poll(void)
{
  bool down = BTN_PRESSED();
  uint32_t now = millis();

  if (down != wasDown) {
    if (now - lastEdge < TYPE_DEBOUNCE_MS) return;  // contact bounce
    lastEdge = now;
    wasDown = down;
    if (down) {
      pressedAt = now;
      armed = true;
    } else if (armed) {
      // Short press: type on release, so a long press never types first.
      armed = false;
      type_program();
    }
    return;
  }

  if (down && armed && (now - pressedAt) >= TYPE_BOOTLOADER_HOLD_MS) {
    armed = false;
    enter_bootloader();
  }
}
