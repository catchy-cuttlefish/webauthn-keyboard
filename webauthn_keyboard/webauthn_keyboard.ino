/*
 * A USB keyboard that a web page can write to.
 *
 * The board enumerates as a FIDO2 security key plus a boot keyboard. A page
 * calls navigator.credentials.create() with the text in `user.id` -- the one
 * field a client passes to the authenticator verbatim, neither hashed like
 * `challenge` nor encrypted like `largeBlob`. The text lands in RAM, and
 * pressing the button on pin 7 types it into whatever has focus.
 *
 * The text and the credential are deliberately volatile: unplugging the board
 * erases both, so an unpowered chip yields nothing to a programmer. The cost is
 * that a browser must write the text again on every plug-in.
 *
 * `user.id` is capped at 64 bytes by the WebAuthn spec, and byte 0 is a control
 * byte (0 = replace, 1 = append), so one registration carries 63 bytes and
 * longer strings take several. Capacity is 512 bytes.
 *
 * This performs no cryptography. Every credential reports the same hardcoded
 * public key and assertions carry a canned byte string that is not a signature.
 * Browsers do not verify assertions -- relying parties do -- so nothing here
 * ever checks them, and skipping the two P-256 scalar multiplies takes
 * registration from ~4.7 s to ~0.2 s and frees ~9 KB of flash.
 *
 * The consequences, plainly: this is not a security key and must not be
 * registered with a real relying party. Anyone can impersonate it. There is no
 * user-presence gate on CTAP operations, so any process that can open the HID
 * device can drive them. The typed text is held in the clear in RAM, which is
 * unavoidable for a device that types a secret on demand.
 */

#include "config.h"
#include "FidoHID.h"
#include "ctap.h"
#include "ctaphid.h"
#include "storage.h"
#include "typeout.h"

void setup()
{
  LED_INIT();
  LED_OFF();

  // A0/A1 are left floating on purpose: their ADC noise seeds the master
  // secret the first time the board boots.

  ctap_init();     // formats EEPROM on first boot
  ctaphid_init();
  typeout_init();  // configures the button pin

  // Three blinks: firmware is up and the USB interfaces are registered.
  for (uint8_t i = 0; i < 3; i++) {
    LED_ON();  delay(80);
    LED_OFF(); delay(80);
  }
}

void loop()
{
  ctaphid_poll();
  typeout_poll();
}
