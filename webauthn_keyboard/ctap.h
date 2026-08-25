#pragma once
#include <stdint.h>

// One buffer serves as both the request and the response. They are never live
// at the same time: every command fully parses its request into locals before
// a single byte of response is emitted. This halves the largest RAM consumer
// in the firmware, which matters a lot on a 2.5 KB part.
//
// Advertised to the platform as maxMsgSize.
#define CTAP_MAX_MSG   384

// --- CTAP2 commands ---
#define CTAP_MAKE_CREDENTIAL  0x01
#define CTAP_GET_ASSERTION    0x02
#define CTAP_GET_INFO         0x04
#define CTAP_CLIENT_PIN       0x06
#define CTAP_RESET            0x07
#define CTAP_GET_NEXT_ASSERT  0x08

// --- status codes ---
#define CTAP2_OK                          0x00
#define CTAP1_ERR_INVALID_COMMAND         0x01
#define CTAP1_ERR_INVALID_PARAMETER       0x02
#define CTAP1_ERR_INVALID_LENGTH          0x03
#define CTAP1_ERR_OTHER                   0x7F
#define CTAP2_ERR_INVALID_CBOR            0x12
#define CTAP2_ERR_MISSING_PARAMETER       0x14
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM   0x26
#define CTAP2_ERR_NOT_ALLOWED             0x30
#define CTAP2_ERR_PIN_AUTH_INVALID        0x33
#define CTAP2_ERR_UNSUPPORTED_OPTION      0x2B
#define CTAP2_ERR_NO_CREDENTIALS          0x2E

void ctap_init(void);

// `req` is the raw CBOR message: req[0] is the command byte, the rest is the
// command's CBOR parameter map. Writes status + CBOR into `resp` and returns
// the total length (always >= 1).
//
// `resp` MAY alias `req` (and normally does -- see CTAP_MAX_MSG).
uint16_t ctap_handle(const uint8_t *req, uint16_t reqLen, uint8_t *resp);

