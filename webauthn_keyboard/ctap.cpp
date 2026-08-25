#include "ctap.h"
#include "cbor.h"
#include "sha256.h"
#include "storage.h"
#include "config.h"

#include <Arduino.h>
#include <string.h>

static const uint8_t AAGUID[16] PROGMEM = {
  0x6c, 0x4e, 0x6f, 0x2d, 0x4c, 0x42, 0x21, 0x00,
  0x41, 0x72, 0x64, 0x75, 0x69, 0x6e, 0x6f, 0x31
};

// This device performs no cryptography. It is a keyboard that a web page can
// address over WebAuthn, so the credential key pair and the assertion
// signature are fixed constants:
//
//   * FAKE_PUBKEY is a genuine secp256r1 point (Chrome parses the COSE key and
//     rejects an off-curve one), but no private key is derived for it and every
//     credential reports the same one.
//   * FAKE_SIG is a structurally valid ASN.1 DER ECDSA signature that is not a
//     signature over anything. Relying parties verify assertions, browsers do
//     not, so nothing in this setup ever checks it.
//
// Regenerate both with the snippet in the README. Neither value is secret.
static const uint8_t FAKE_PUBKEY[64] PROGMEM = {
  0xC9, 0xFA, 0xB8, 0x1C, 0x91, 0x88, 0x6B, 0xB0, 0x89, 0xB6, 0xA2, 0xF3,
  0x3E, 0x08, 0xAA, 0xBE, 0x4D, 0xC8, 0x4F, 0x36, 0x91, 0x55, 0x67, 0xD3,
  0xC3, 0xAB, 0x3A, 0xC2, 0x08, 0x10, 0x65, 0xDC, 0x1A, 0x00, 0x92, 0x8F,
  0xF6, 0x69, 0xD9, 0x61, 0x0E, 0x13, 0xA2, 0x1E, 0xC2, 0x5F, 0xA1, 0xDD,
  0x34, 0xB7, 0xEB, 0x78, 0xAE, 0xB8, 0x4C, 0x0E, 0xD4, 0x25, 0x82, 0xC8,
  0x36, 0x16, 0x61, 0x3C,
};
static const uint8_t FAKE_SIG[] PROGMEM = {
  0x30, 0x45, 0x02, 0x21, 0x00, 0xA2, 0xA8, 0xD0, 0xD0, 0x5C, 0xC9, 0xCA,
  0xB1, 0x51, 0x0E, 0xB4, 0xC8, 0x52, 0x72, 0xC1, 0xDD, 0xD9, 0xB1, 0x63,
  0x91, 0xB0, 0xA0, 0xC1, 0x32, 0x74, 0x91, 0x19, 0x65, 0xEE, 0x6B, 0x9B,
  0xD3, 0x02, 0x20, 0x0D, 0x48, 0x23, 0xB5, 0x88, 0x8F, 0x24, 0x3A, 0x21,
  0x54, 0xC7, 0x50, 0x38, 0xCE, 0x2F, 0x12, 0xC6, 0xD9, 0x7B, 0x90, 0xC3,
  0x5C, 0xA6, 0x7C, 0x64, 0xB9, 0x3F, 0x11, 0x20, 0x23, 0xAB, 0x8D,
};

#define CRED_ID_LEN   (CRED_NONCE_LEN + 32)   // nonce || HMAC tag = 48
#define COSE_KEY_LEN  77
#define AUTHDATA_MC_LEN (32 + 1 + 4 + 16 + 2 + CRED_ID_LEN + COSE_KEY_LEN)  // 180
#define AUTHDATA_GA_LEN (32 + 1 + 4)                                        // 37

#define FLAG_UP 0x01
#define FLAG_UV 0x04
#define FLAG_AT 0x40

// Key-derivation domain separators.
#define KD_CRED  'c'
#define KD_NONCE 'n'

// --------------------------------------------------------------- helpers ---

static void kdf(uint8_t tag, const uint8_t rpIdHash[32],
                const uint8_t nonce[CRED_NONCE_LEN], uint8_t iter, uint8_t out[32])
{
  uint8_t master[32];
  hmac_sha256_ctx h;

  store_master(master);
  hmac_sha256_init(&h, master, 32);
  memset(master, 0, sizeof(master));

  hmac_sha256_update(&h, &tag, 1);
  hmac_sha256_update(&h, rpIdHash, 32);
  hmac_sha256_update(&h, nonce, CRED_NONCE_LEN);
  hmac_sha256_update(&h, &iter, 1);
  hmac_sha256_final(&h, out);
}


static void make_cred_id(const uint8_t rpIdHash[32],
                         const uint8_t nonce[CRED_NONCE_LEN], uint8_t out[CRED_ID_LEN])
{
  memcpy(out, nonce, CRED_NONCE_LEN);
  kdf(KD_CRED, rpIdHash, nonce, 0, out + CRED_NONCE_LEN);
}

static bool check_cred_id(const uint8_t rpIdHash[32],
                          const uint8_t *credId, uint32_t credIdLen)
{
  if (credIdLen != CRED_ID_LEN) return false;
  uint8_t tag[32], diff = 0;
  kdf(KD_CRED, rpIdHash, credId, 0, tag);
  for (uint8_t i = 0; i < 32; i++) diff |= tag[i] ^ credId[CRED_NONCE_LEN + i];
  return diff == 0;
}

static void fresh_nonce(uint32_t counter, const uint8_t rpIdHash[32],
                        uint8_t nonce[CRED_NONCE_LEN])
{
  uint8_t master[32], full[32];
  hmac_sha256_ctx h;
  uint8_t c[4] = { (uint8_t)counter, (uint8_t)(counter >> 8),
                   (uint8_t)(counter >> 16), (uint8_t)(counter >> 24) };
  uint8_t tag = KD_NONCE;

  store_master(master);
  hmac_sha256_init(&h, master, 32);
  memset(master, 0, sizeof(master));
  hmac_sha256_update(&h, &tag, 1);
  hmac_sha256_update(&h, rpIdHash, 32);
  hmac_sha256_update(&h, c, 4);
  hmac_sha256_final(&h, full);
  memcpy(nonce, full, CRED_NONCE_LEN);
}

// ---------------------------------------------------------- user presence ---

static void blink_activity(void)
{
  // There is no user-presence gate on CTAP operations: any process that can
  // open the HID device gets them. The LED is purely an activity indicator.
  LED_ON();
  delay(30);
  LED_OFF();
}

// ------------------------------------------------------------- authData ----

static void put_authdata_header(CborOut *o, const uint8_t rpIdHash[32],
                                uint8_t flags, uint32_t counter)
{
  uint8_t hdr[37];
  memcpy(hdr, rpIdHash, 32);
  hdr[32] = flags;
  hdr[33] = (uint8_t)(counter >> 24);
  hdr[34] = (uint8_t)(counter >> 16);
  hdr[35] = (uint8_t)(counter >> 8);
  hdr[36] = (uint8_t)counter;
  cbor_raw(o, hdr, 37);
}

// --------------------------------------------------------- authenticator ---

static uint16_t do_get_info(uint8_t *resp)
{
  CborOut o;
  uint8_t aaguid[16];

  memcpy_P(aaguid, AAGUID, 16);
  cbor_out_init(&o, resp + 1, CTAP_MAX_MSG - 1);

  cbor_map(&o, 4);

  cbor_uint(&o, 0x01);                       // versions
  cbor_array(&o, 1);
  cbor_tstr_P(&o, PSTR("FIDO_2_1"));         // not FIDO_2_0: we implement none
                                             // of the PIN machinery a 2.0
                                             // client would expect.


  cbor_uint(&o, 0x03);                       // aaguid
  cbor_bstr(&o, aaguid, 16);

  cbor_uint(&o, 0x04);                       // options
  cbor_map(&o, 2);
  cbor_tstr_P(&o, PSTR("rk")); cbor_bool(&o, true);
  cbor_tstr_P(&o, PSTR("up")); cbor_bool(&o, true);
  // No "clientPin"/"uv" keys at all: this authenticator has no user
  // verification of any kind.

  cbor_uint(&o, 0x05);                       // maxMsgSize
  cbor_uint(&o, CTAP_MAX_MSG);


  if (o.err) { resp[0] = CTAP1_ERR_OTHER; return 1; }
  resp[0] = CTAP2_OK;
  return (uint16_t)(1 + o.len);
}

static uint16_t do_make_credential(CborIn *in, uint8_t *resp)
{
  const uint8_t *clientDataHash = NULL;
  const char *rpId = NULL;   uint32_t rpIdLen = 0;
  const uint8_t *userId = NULL; uint32_t userIdLen = 0;
  bool es256 = false, rk = false;
  uint32_t nkeys;

  if (!cbor_enter_map(in, &nkeys)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;

  while (nkeys--) {
    uint32_t key;
    if (!cbor_get_uint(in, &key)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
    switch (key) {
      case 0x01: {
        uint32_t n;
        if (!cbor_get_bytes(in, &clientDataHash, &n) || n != 32)
          return (resp[0] = CTAP1_ERR_INVALID_PARAMETER), 1;
        break;
      }
      case 0x02: {                                   // rp
        uint32_t m;
        if (!cbor_enter_map(in, &m)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        while (m--) {
          if (cbor_text_is(in, "id")) {
            if (!cbor_get_text(in, &rpId, &rpIdLen))
              return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          } else {
            if (!cbor_skip(in) || !cbor_skip(in))
              return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          }
        }
        break;
      }
      case 0x03: {                                   // user
        uint32_t m;
        if (!cbor_enter_map(in, &m)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        while (m--) {
          if (cbor_text_is(in, "id")) {
            if (!cbor_get_bytes(in, &userId, &userIdLen))
              return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          } else {
            if (!cbor_skip(in) || !cbor_skip(in))
              return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          }
        }
        break;
      }
      case 0x04: {                                   // pubKeyCredParams
        uint32_t n;
        if (!cbor_enter_array(in, &n)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        while (n--) {
          uint32_t m;
          if (!cbor_enter_map(in, &m)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          while (m--) {
            if (cbor_text_is(in, "alg")) {
              int32_t alg;
              if (!cbor_get_int(in, &alg)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
              if (alg == -7) es256 = true;            // ES256, the only one we do
            } else {
              if (!cbor_skip(in) || !cbor_skip(in))
                return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
            }
          }
        }
        break;
      }
      case 0x06: {                                   // extensions
        uint32_t m;
        if (!cbor_enter_map(in, &m)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        while (m--) {
          // No authenticator extensions are supported.
          if (!cbor_skip(in) || !cbor_skip(in))
            return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        }
        break;
      }
      case 0x07: {                                   // options
        uint32_t m;
        if (!cbor_enter_map(in, &m)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        while (m--) {
          if (cbor_text_is(in, "rk")) {
            if (!cbor_get_bool(in, &rk)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          } else if (cbor_text_is(in, "uv")) {
            bool uv;
            if (!cbor_get_bool(in, &uv)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
            if (uv) return (resp[0] = CTAP2_ERR_UNSUPPORTED_OPTION), 1;
          } else {
            if (!cbor_skip(in) || !cbor_skip(in))
              return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          }
        }
        break;
      }
      case 0x08:                                     // pinUvAuthParam
        return (resp[0] = CTAP2_ERR_PIN_AUTH_INVALID), 1;
      case 0x05:                                     // excludeList: ignored
      default:
        if (!cbor_skip(in)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        break;
    }
  }

  if (!clientDataHash || !rpId) return (resp[0] = CTAP2_ERR_MISSING_PARAMETER), 1;
  if (!es256)                   return (resp[0] = CTAP2_ERR_UNSUPPORTED_ALGORITHM), 1;
  if (userIdLen > MAX_USER_ID_LEN) return (resp[0] = CTAP1_ERR_INVALID_LENGTH), 1;
  blink_activity();

  uint8_t rpIdHash[32];
  sha256((const uint8_t *)rpId, rpIdLen, rpIdHash);

  uint32_t counter = store_next_counter();

  uint8_t nonce[CRED_NONCE_LEN];
  fresh_nonce(counter, rpIdHash, nonce);

  uint8_t pub[64];
  memcpy_P(pub, FAKE_PUBKEY, sizeof(pub));

  uint8_t credId[CRED_ID_LEN];
  make_cred_id(rpIdHash, nonce, credId);

  // We keep exactly one discoverable-credential slot. Overwriting it is the
  // documented behaviour here; a second rk registration evicts the first.
  if (rk) store_rk_put(rpIdHash, nonce, userId, (uint8_t)userIdLen);

  // user.id is the one field a web page can put arbitrary bytes into that
  // reaches the authenticator untouched -- the client neither hashes nor
  // encrypts it. That makes it the write channel for the type-out text, so a
  // browser alone can set what the button types.
  if (rk) store_text_chunk(userId, (uint16_t)userIdLen);

  uint8_t aaguid[16];
  memcpy_P(aaguid, AAGUID, 16);

  CborOut o;
  cbor_out_init(&o, resp + 1, CTAP_MAX_MSG - 1);

  cbor_map(&o, 3);

  cbor_uint(&o, 0x01);
  cbor_tstr_P(&o, PSTR("none"));                    // "none" attestation: no
                                                    // batch cert, no extra sig.
  cbor_uint(&o, 0x02);
  cbor_head_out(&o, CBOR_BSTR, AUTHDATA_MC_LEN);
  put_authdata_header(&o, rpIdHash, FLAG_UP | FLAG_AT, counter);
  cbor_raw(&o, aaguid, 16);
  {
    uint8_t l[2] = { (uint8_t)(CRED_ID_LEN >> 8), (uint8_t)CRED_ID_LEN };
    cbor_raw(&o, l, 2);
  }
  cbor_raw(&o, credId, CRED_ID_LEN);
  {
    // COSE_Key: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
    static const uint8_t coseHdr[] PROGMEM = {
      0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20
    };
    uint8_t h[sizeof(coseHdr)];
    memcpy_P(h, coseHdr, sizeof(coseHdr));
    cbor_raw(&o, h, sizeof(h));
    cbor_raw(&o, pub, 32);
    uint8_t y[3] = { 0x22, 0x58, 0x20 };
    cbor_raw(&o, y, 3);
    cbor_raw(&o, pub + 32, 32);
  }

  cbor_uint(&o, 0x03);
  cbor_map(&o, 0);                                  // empty attStmt


  if (o.err) return (resp[0] = CTAP1_ERR_OTHER), 1;
  resp[0] = CTAP2_OK;
  return (uint16_t)(1 + o.len);
}

// Serializes the assertion response. Kept in its own frame (noinline) because
// its ~110 bytes of buffers -- credential ID and user handle -- need not be
// live while the request is still being parsed.
static __attribute__((noinline))
uint16_t ga_emit(uint8_t *resp, const uint8_t rpIdHash[32],
                 const uint8_t nonce[CRED_NONCE_LEN],
                 const uint8_t *authData, const uint8_t *der, uint8_t derLen,
                 bool fromRk)
{
  uint8_t credId[CRED_ID_LEN];
  CborOut o;

  make_cred_id(rpIdHash, nonce, credId);
  cbor_out_init(&o, resp + 1, CTAP_MAX_MSG - 1);

  cbor_map(&o, fromRk ? 4 : 3);

  cbor_uint(&o, 0x01);                       // credential descriptor
  cbor_map(&o, 2);
  cbor_tstr_P(&o, PSTR("id"));   cbor_bstr(&o, credId, CRED_ID_LEN);
  cbor_tstr_P(&o, PSTR("type")); cbor_tstr_P(&o, PSTR("public-key"));

  cbor_uint(&o, 0x02);                       // authData
  cbor_bstr(&o, authData, AUTHDATA_GA_LEN);

  cbor_uint(&o, 0x03);                       // signature
  cbor_bstr(&o, der, derLen);

  if (fromRk) {
    uint8_t userId[MAX_USER_ID_LEN];
    uint8_t userIdLen = store_rk_userid(userId);
    cbor_uint(&o, 0x04);                     // user handle
    cbor_map(&o, 1);
    cbor_tstr_P(&o, PSTR("id"));
    cbor_bstr(&o, userId, userIdLen);
  }


  if (o.err) return (resp[0] = CTAP1_ERR_OTHER), 1;
  resp[0] = CTAP2_OK;
  return (uint16_t)(1 + o.len);
}

static uint16_t do_get_assertion(CborIn *in, uint8_t *resp)
{
  const uint8_t *clientDataHash = NULL;
  const char *rpId = NULL; uint32_t rpIdLen = 0;
  bool up = true;
  bool haveCred = false, fromRk = false;
  uint8_t nonce[CRED_NONCE_LEN];
  uint8_t rpIdHash[32];
  uint32_t nkeys;

  if (!cbor_enter_map(in, &nkeys)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;

  // allowList entries are verified as they are parsed rather than collected
  // into a fixed-size array. That removes both the arbitrary length cap and
  // ~24 bytes of stack. It relies on CTAP2's canonical map ordering putting
  // rpId (key 1) ahead of allowList (key 3), which is checked below.
  bool haveRpIdHash = false;
  bool haveAllowList = false;

  while (nkeys--) {
    uint32_t key;
    if (!cbor_get_uint(in, &key)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
    switch (key) {
      case 0x01:
        if (!cbor_get_text(in, &rpId, &rpIdLen))
          return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        sha256((const uint8_t *)rpId, rpIdLen, rpIdHash);
        haveRpIdHash = true;
        break;
      case 0x02: {
        uint32_t n;
        if (!cbor_get_bytes(in, &clientDataHash, &n) || n != 32)
          return (resp[0] = CTAP1_ERR_INVALID_PARAMETER), 1;
        break;
      }
      case 0x03: {                                   // allowList
        uint32_t n;
        if (!cbor_enter_array(in, &n)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        // Non-canonical ordering would leave rpIdHash unknown here.
        if (!haveRpIdHash) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        haveAllowList = true;
        while (n--) {
          uint32_t m;
          if (!cbor_enter_map(in, &m)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          while (m--) {
            if (cbor_text_is(in, "id")) {
              const uint8_t *d; uint32_t dl;
              if (!cbor_get_bytes(in, &d, &dl))
                return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
              if (!haveCred && check_cred_id(rpIdHash, d, dl)) {
                memcpy(nonce, d, CRED_NONCE_LEN);
                haveCred = true;
              }
            } else {
              if (!cbor_skip(in) || !cbor_skip(in))
                return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
            }
          }
        }
        break;
      }
      case 0x04: {                                   // extensions
        uint32_t m;
        if (!cbor_enter_map(in, &m)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        while (m--) {
          // No authenticator extensions are supported.
          if (!cbor_skip(in) || !cbor_skip(in))
            return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        }
        break;
      }
      case 0x05: {                                   // options
        uint32_t m;
        if (!cbor_enter_map(in, &m)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        while (m--) {
          if (cbor_text_is(in, "up")) {
            if (!cbor_get_bool(in, &up)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          } else if (cbor_text_is(in, "uv")) {
            bool uv;
            if (!cbor_get_bool(in, &uv)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
            if (uv) return (resp[0] = CTAP2_ERR_UNSUPPORTED_OPTION), 1;
          } else {
            if (!cbor_skip(in) || !cbor_skip(in))
              return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
          }
        }
        break;
      }
      case 0x06:                                     // pinUvAuthParam
        return (resp[0] = CTAP2_ERR_PIN_AUTH_INVALID), 1;
      default:
        if (!cbor_skip(in)) return (resp[0] = CTAP2_ERR_INVALID_CBOR), 1;
        break;
    }
  }

  if (!clientDataHash || !haveRpIdHash) return (resp[0] = CTAP2_ERR_MISSING_PARAMETER), 1;

  // No allowList => the platform wants a discoverable credential.
  if (!haveCred && !haveAllowList && store_rk_match(rpIdHash)) {
    store_rk_nonce(nonce);
    haveCred = true;
    fromRk = true;
  }
  if (!haveCred) return (resp[0] = CTAP2_ERR_NO_CREDENTIALS), 1;

  if (up) blink_activity();

  uint32_t counter = store_next_counter();

  // Sign over authenticatorData || clientDataHash.
  uint8_t authData[AUTHDATA_GA_LEN];
  memcpy(authData, rpIdHash, 32);
  authData[32] = up ? FLAG_UP : 0x00;
  authData[33] = (uint8_t)(counter >> 24);
  authData[34] = (uint8_t)(counter >> 16);
  authData[35] = (uint8_t)(counter >> 8);
  authData[36] = (uint8_t)counter;

  // Nothing is signed, so clientDataHash is only checked for presence and the
  // canned signature is copied out as-is.
  uint8_t der[sizeof(FAKE_SIG)];
  uint8_t derLen = (uint8_t)sizeof(FAKE_SIG);
  memcpy_P(der, FAKE_SIG, derLen);

  // From here on `resp` may be overwriting the request buffer, but everything
  // still needed lives in locals.
  return ga_emit(resp, rpIdHash, nonce, authData, der, derLen, fromRk);
}

// -----------------------------------------------------------------------------

void ctap_init(void)
{
  store_init();
}

uint16_t ctap_handle(const uint8_t *req, uint16_t reqLen, uint8_t *resp)
{
  if (reqLen < 1) { resp[0] = CTAP1_ERR_INVALID_LENGTH; return 1; }

  uint8_t cmd = req[0];
  CborIn in;
  cbor_in_init(&in, req + 1, reqLen - 1);

  switch (cmd) {
    case CTAP_GET_INFO:
      return do_get_info(resp);
    case CTAP_MAKE_CREDENTIAL:
      return do_make_credential(&in, resp);
    case CTAP_GET_ASSERTION:
      return do_get_assertion(&in, resp);
    case CTAP_RESET:
      blink_activity();
      store_reset();
      resp[0] = CTAP2_OK;
      return 1;
    case CTAP_GET_NEXT_ASSERT:
      resp[0] = CTAP2_ERR_NOT_ALLOWED;
      return 1;
    case CTAP_CLIENT_PIN:
      resp[0] = CTAP2_ERR_UNSUPPORTED_OPTION;
      return 1;
    default:
      resp[0] = CTAP1_ERR_INVALID_COMMAND;
      return 1;
  }
}
