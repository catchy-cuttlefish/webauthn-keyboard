// Build-time knobs.
#pragma once

// --- type-out button ---------------------------------------------------------
// Momentary button from this pin to GND. Pressing it while idle types the
// stored text as USB keystrokes.
//
// Pin 7 is a plain digital pin on a Pro Micro: no I2C (2/3), SPI (14-16) or
// UART (0/1) alternate function to clash with.
#define TYPE_BUTTON_PIN  7

// Arduino's pinMode()/digitalRead() drag in the pin-mapping tables, ~200 bytes
// of flash we do not have. Pin 7 is PE6 on every ATmega32u4 board, so the
// button is driven through the registers directly. Change these three macros
// (or fall back to the Arduino API) if you move the button.
#if defined(__AVR_ATmega32U4__) && TYPE_BUTTON_PIN == 7
  #define BTN_INIT()    do { DDRE &= ~_BV(6); PORTE |= _BV(6); } while (0)
  #define BTN_PRESSED() (!(PINE & _BV(6)))
#else
  #define BTN_INIT()    pinMode(TYPE_BUTTON_PIN, INPUT_PULLUP)
  #define BTN_PRESSED() (digitalRead(TYPE_BUTTON_PIN) == LOW)
#endif

#define TYPE_DEBOUNCE_MS 40
// Per-keystroke gap. The keyboard endpoint is polled every 10 ms, so anything
// below that risks reports being coalesced and characters being dropped.
#define TYPE_KEY_DELAY_MS 12
// Press Enter after the text.
#define TYPE_PRESS_ENTER 0

// Hold the button this long to reboot into the bootloader instead of typing.
// Set ENABLE_LONG_PRESS to 0 to drop the gesture; the CTAPHID_BOOTLOADER
// vendor command still works, so the board stays recoverable either way.
#ifndef ENABLE_LONG_PRESS
#define ENABLE_LONG_PRESS 1
#endif
#define TYPE_BOOTLOADER_HOLD_MS 3000UL

// Compiles in a CTAPHID vendor command that makes the device type on demand.
// Useful for testing without a button wired, but it hands any local process the
// ability to inject your stored secret as keystrokes. Keep this at 0.
#ifndef ALLOW_REMOTE_TYPE
#define ALLOW_REMOTE_TYPE 0
#endif

// --- crypto ------------------------------------------------------------------
// 1: skip both P-256 scalar multiplies. makeCredential returns a fixed, real
//    curve point instead of deriving one, and getAssertion returns a fixed
//    DER blob instead of signing. Registration/assertion drop from ~4.7 s to
//    milliseconds, and micro-ecc is dead-stripped (~6 KB of flash).
//
//    This makes the device WORTHLESS as an authenticator: every credential
//    shares one public key, and assertions are not signatures at all. Any
//    relying party that verifies (i.e. any real one) will reject it. It is
//    fine only because this board is a WebAuthn-addressable keyboard, not a
//    security key.
//
// 0: real ES256. Needed if you ever want a genuine authenticator.
#ifndef FAKE_CRYPTO
#define FAKE_CRYPTO 1
#endif

// The largeBlob extension. Useful only if a host-side tool decrypts the blob
// (tools/provision.py): the browser encrypts it, so the device can never read
// its own blob. With the user.id write path there is no longer any reason to
// carry it, and it does not fit alongside the keyboard anyway -- ~900 bytes of
// flash and 512 bytes of EEPROM.
#ifndef ENABLE_LARGEBLOB
#define ENABLE_LARGEBLOB 0
#endif

// Set to 0 to build without the keyboard (fits alongside CDC serial).
#ifndef ENABLE_TYPEOUT
#define ENABLE_TYPEOUT 1
#endif

// --- user presence -----------------------------------------------------------
// 0: every CTAP operation is auto-approved. Convenient for bench testing, but
//    it means any software on the host can read/write the blob without consent.
// 1: TYPE_BUTTON_PIN must be pressed to approve each operation.
#ifndef REQUIRE_BUTTON
#define REQUIRE_BUTTON 0
#endif
#define BUTTON_PIN      TYPE_BUTTON_PIN
#define UP_TIMEOUT_MS   10000UL

// Prints CTAPHID/CTAP2 traffic on the CDC serial port. Costs ~2 KB of flash and
// slows transactions down enough to occasionally trip host timeouts.
#define CTAP_DEBUG      0

// --- LED ---------------------------------------------------------------------
// Arduino's digitalWrite()/pinMode() cost ~300 bytes of flash once linked in,
// and this firmware is close to filling the part, so we poke the port directly.
//
// A Pro Micro has NO pin-13 LED -- only RX (PB0) and TX (PD5), both active LOW.
// A Leonardo/Micro has the usual LED on pin 13 (PC7), active HIGH. Set this to
// match your board or the status blinks will be invisible.
#ifndef BOARD_PRO_MICRO
#define BOARD_PRO_MICRO 1
#endif

#if defined(__AVR_ATmega32U4__) && BOARD_PRO_MICRO
  // RX LED on PB0, active low.
  #define LED_INIT() (DDRB  |=  _BV(0))
  #define LED_ON()   (PORTB &= ~_BV(0))
  #define LED_OFF()  (PORTB |=  _BV(0))
#elif defined(__AVR_ATmega32U4__)
  // Leonardo / Micro: LED_BUILTIN is PC7, active high.
  #define LED_INIT() (DDRC  |=  _BV(7))
  #define LED_ON()   (PORTC |=  _BV(7))
  #define LED_OFF()  (PORTC &= ~_BV(7))
#else
  #define LED_INIT() pinMode(LED_BUILTIN, OUTPUT)
  #define LED_ON()   digitalWrite(LED_BUILTIN, HIGH)
  #define LED_OFF()  digitalWrite(LED_BUILTIN, LOW)
#endif
