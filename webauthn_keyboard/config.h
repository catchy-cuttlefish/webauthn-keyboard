// Board wiring and timing constants.
#pragma once

#include <Arduino.h>

// --- type-out button ---------------------------------------------------------
// Momentary button from pin 7 to GND. A short press types the stored text; a
// long press reboots into the bootloader.
//
// Pin 7 is PE6 on every ATmega32u4 board, and is a plain digital pin: no I2C
// (2/3), SPI (14-16) or UART (0/1) alternate function to clash with. It is
// driven through the registers because Arduino's pinMode()/digitalRead() drag
// in the pin-mapping tables.
#define BTN_INIT()    do { DDRE &= ~_BV(6); PORTE |= _BV(6); } while (0)
#define BTN_PRESSED() (!(PINE & _BV(6)))

#define TYPE_DEBOUNCE_MS  40
// Per-keystroke gap. The keyboard endpoint is polled every 10 ms, so anything
// below that risks reports being coalesced and characters being dropped.
#define TYPE_KEY_DELAY_MS 12
// Hold the button this long to reboot into the bootloader instead of typing.
#define TYPE_BOOTLOADER_HOLD_MS 3000UL

// --- status LED --------------------------------------------------------------
// Pro Micro: the RX LED on PB0, active low. (A Leonardo/Micro would use PC7
// active high instead -- this board has no pin-13 LED.)
#define LED_INIT() (DDRB  |=  _BV(0))
#define LED_ON()   (PORTB &= ~_BV(0))
#define LED_OFF()  (PORTB |=  _BV(0))
