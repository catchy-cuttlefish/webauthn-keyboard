/*
 * webauthn_largeblob -- a FIDO2/CTAP2 authenticator for the Arduino Leonardo
 * whose reason for existing is the `largeBlob` extension: a browser can stash
 * ~430 bytes of arbitrary (e.g. ASCII) data on the board and read it back.
 *
 * How the data actually gets there
 * -------------------------------
 * The authenticator never sees the plaintext. WebAuthn's largeBlob extension
 * puts the *client* (the browser) in charge of encryption:
 *
 *   1. Registration asks for `largeBlobKey`. We derive a 32-byte key from the
 *      credential and hand it to the browser.
 *   2. The browser deflates the caller's bytes, seals them with AES-256-GCM
 *      under that key, and wraps the result in a CBOR "large-blob array".
 *   3. That array is pushed to us with authenticatorLargeBlobs (0x0C) and
 *      lands verbatim in EEPROM. We only validate the trailing 16-byte
 *      SHA-256 checksum.
 *
 * So this firmware needs SHA-256 and P-256 -- but no AES at all.
 *
 * Deliberate deviations from CTAP2.1
 * ----------------------------------
 *   - largeBlob array is 512 bytes, not the mandated >= 1024 (the entire
 *     EEPROM is 1 KB).
 *   - No clientPin, no user verification, no pinUvAuthToken.
 *   - Exactly one discoverable-credential slot; registering a second rk
 *     credential evicts the first.
 *   - "none" attestation only, and excludeList is ignored.
 *   - Non-discoverable credentials are stateless: the private key is
 *     HMAC-SHA256(masterSecret, ...) over the credential ID, so an unlimited
 *     number of them cost zero storage.
 *
 * This is a learning/bench tool. The master secret sits in EEPROM in the
 * clear, entropy comes from ADC noise, and with REQUIRE_BUTTON=0 there is no
 * user consent at all. Do not protect anything you care about with it.
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

#if CTAP_DEBUG
  Serial.begin(115200);
#endif

  ctap_init();     // formats EEPROM on first boot
  ctaphid_init();
#if ENABLE_TYPEOUT
  typeout_init();  // configures the button pin
#endif

  // Three blinks: firmware is up and the USB interface is registered.
  for (uint8_t i = 0; i < 3; i++) {
    LED_ON(); delay(80);
    LED_OFF();  delay(80);
  }
}

void loop()
{
  ctaphid_poll();
#if ENABLE_TYPEOUT
  typeout_poll();
#endif
}
