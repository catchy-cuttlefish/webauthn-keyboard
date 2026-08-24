#include "typeout.h"
#include "config.h"

#include "storage.h"
#include "FidoHID.h"

#include <Arduino.h>
#include <avr/wdt.h>

// ASCII -> USB HID usage code (US layout). Bit 7 set means "hold Left Shift".
// Index is the ASCII value; 0x00 means "no key for this character", which is
// how every control character and every non-ASCII byte gets skipped.
static const uint8_t asciiToKey[128] PROGMEM = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x2B, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00,   // \t \n
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x2C, 0x9E, 0xB4, 0xA0, 0xA1, 0xA2, 0xA4, 0x34,   // space ! " # $ % & '
  0xA6, 0xA7, 0xA5, 0xAE, 0x36, 0x2D, 0x37, 0x38,   // ( ) * + , - . /
  0x27, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,   // 0-7
  0x25, 0x26, 0xB3, 0x33, 0xB6, 0x2E, 0xB7, 0xB8,   // 8 9 : ; < = > ?
  0x9F, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,   // @ A-G
  0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92,   // H-O
  0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,   // P-W
  0x9B, 0x9C, 0x9D, 0x2F, 0x31, 0x30, 0xA3, 0xAD,   // X Y Z [ \ ] ^ _
  0x35, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,   // ` a-g
  0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,   // h-o
  0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,   // p-w
  0x1B, 0x1C, 0x1D, 0xAF, 0xB1, 0xB0, 0xB5, 0x00,   // x y z { | } ~ DEL
};

#define KEY_SHIFT_FLAG 0x80
#define MOD_LSHIFT     0x02

static bool     wasDown   = false;
static uint32_t lastEdge  = 0;
static uint32_t pressedAt = 0;
static bool     armed     = false;   // long-press already consumed?

void typeout_init(void)
{
  BTN_INIT();
  wasDown = BTN_PRESSED();
}

static void type_string(void)
{
  uint16_t n = store_text_len();
  if (n == 0 || !FidoHID.keyboardReady()) return;

  LED_ON();

  for (uint16_t i = 0; i < n; i++) {
    uint8_t c = store_text_byte(i);
    if (c >= 128) continue;
    uint8_t k = pgm_read_byte(&asciiToKey[c]);
    if (k == 0) continue;

    uint8_t mod = (k & KEY_SHIFT_FLAG) ? MOD_LSHIFT : 0;
    FidoHID.keyReport(mod, k & 0x7F);
    delay(TYPE_KEY_DELAY_MS);
    FidoHID.keyReport(0, 0);        // release, so repeated letters register
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
      type_string();
    }
    return;
  }

  if (down && armed && (now - pressedAt) >= TYPE_BOOTLOADER_HOLD_MS) {
    armed = false;
    enter_bootloader();
  }
}

