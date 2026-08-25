#include "ctaphid.h"
#include "ctap.h"
#include "config.h"
#include "FidoHID.h"
#include "storage.h"
#include "typeout.h"

#include <Arduino.h>
#include <avr/wdt.h>
#include <string.h>

#define CID_BROADCAST 0xFFFFFFFFUL
#define INIT_PAYLOAD  (FIDO_HID_PACKET_SIZE - 7)   // 57
#define CONT_PAYLOAD  (FIDO_HID_PACKET_SIZE - 5)   // 59

#define CAPABILITY_CBOR 0x04
#define CAPABILITY_NMSG 0x08

// Per spec the host must deliver the next frame of a message within 500 ms.
#define FRAME_TIMEOUT_MS 500UL

// Single buffer for both directions. ctap_handle() is documented to tolerate
// resp aliasing req; PING simply echoes it in place.
static uint8_t  ioBuf[CTAP_MAX_MSG];
static uint8_t  pkt[FIDO_HID_PACKET_SIZE];

static uint32_t activeCid   = 0;      // 0 == idle
static uint8_t  activeCmd   = 0;
static uint16_t expectedLen = 0;
static uint16_t gotLen      = 0;
static uint8_t  nextSeq     = 0;
static bool     overflow    = false;  // message longer than ioBuf
static uint32_t lastFrameMs = 0;
static uint32_t nextCid     = 1;

static inline uint32_t rd32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static inline void wr32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static void reset_transaction(void)
{
  activeCid = 0;
  activeCmd = 0;
  expectedLen = gotLen = 0;
  nextSeq = 0;
  overflow = false;
}

static void send_message(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len)
{
  uint16_t off = 0;
  uint8_t  seq = 0;

  memset(pkt, 0, sizeof(pkt));
  wr32(pkt, cid);
  pkt[4] = cmd | 0x80;
  pkt[5] = (uint8_t)(len >> 8);
  pkt[6] = (uint8_t)len;
  uint16_t n = len < INIT_PAYLOAD ? len : INIT_PAYLOAD;
  memcpy(pkt + 7, data, n);
  FidoHID.send(pkt);
  off += n;

  while (off < len) {
    memset(pkt, 0, sizeof(pkt));
    wr32(pkt, cid);
    pkt[4] = seq++;
    n = (uint16_t)((len - off) < CONT_PAYLOAD ? (len - off) : CONT_PAYLOAD);
    memcpy(pkt + 5, data + off, n);
    FidoHID.send(pkt);
    off += n;
  }
}

static void send_error(uint32_t cid, uint8_t code)
{
  send_message(cid, CTAPHID_ERROR, &code, 1);
}

void ctaphid_keepalive(void)
{
  if (!activeCid) return;
  uint8_t status = 0x01;              // 0x01 = PROCESSING
  send_message(activeCid, CTAPHID_KEEPALIVE, &status, 1);
}

static void handle_init(uint32_t cid, const uint8_t *payload, uint16_t len)
{
  if (len != 8) { send_error(cid, ERR_INVALID_LEN); return; }

  uint32_t newCid;
  if (cid == CID_BROADCAST) {
    newCid = nextCid++;
    if (nextCid == CID_BROADCAST || nextCid == 0) nextCid = 1;
  } else {
    newCid = cid;                     // resync of an existing channel
    if (cid == activeCid) reset_transaction();
  }

  uint8_t r[17];
  memcpy(r, payload, 8);              // echo nonce
  wr32(r + 8, newCid);
  r[12] = 2;                          // CTAPHID protocol version
  r[13] = 1;                          // device major
  r[14] = 0;                          // device minor
  r[15] = 0;                          // device build
  r[16] = CAPABILITY_CBOR | CAPABILITY_NMSG;
  send_message(cid, CTAPHID_INIT, r, sizeof(r));
}

static void dispatch(void)
{
  uint32_t cid = activeCid;
  uint8_t  cmd = activeCmd;
  uint16_t len = gotLen;

  if (overflow) {
    reset_transaction();
    send_error(cid, ERR_INVALID_LEN);
    return;
  }

  switch (cmd) {
    case CTAPHID_PING:
      send_message(cid, CTAPHID_PING, ioBuf, len);
      break;

    case CTAPHID_CBOR: {
      if (len < 1) { send_error(cid, ERR_INVALID_LEN); break; }
      uint16_t rlen = ctap_handle(ioBuf, len, ioBuf);
      send_message(cid, CTAPHID_CBOR, ioBuf, rlen);
      break;
    }

    case CTAPHID_CANCEL:
      // CANCEL has no response of its own, and commands are processed
      // synchronously, so by the time one is dequeued the command it refers to
      // has already answered. Nothing to do.
      break;

    case CTAPHID_SETTEXT:
      if (len > TYPEOUT_MAX) { send_error(cid, ERR_INVALID_LEN); break; }
      store_text_set(ioBuf, len);
      { uint8_t okb = 0; send_message(cid, CTAPHID_SETTEXT, &okb, 1); }
      break;

    case CTAPHID_TEXTINFO: {
      uint16_t n = store_text_len();
      uint8_t r[4] = { (uint8_t)(TYPEOUT_MAX >> 8), (uint8_t)TYPEOUT_MAX,
                       (uint8_t)(n >> 8), (uint8_t)n };
      send_message(cid, CTAPHID_TEXTINFO, r, sizeof(r));
      break;
    }

    case CTAPHID_BOOTLOADER:
      // Same handshake the Arduino core uses for the 1200-baud touch: leave a
      // magic value where Caterina looks for it, then let the watchdog reset us.
      { uint8_t okb = 0; send_message(cid, CTAPHID_BOOTLOADER, &okb, 1); }
      delay(50);                       // let the reply reach the host first
      *(volatile uint16_t *)0x0800 = 0x7777;
      wdt_enable(WDTO_120MS);
      for (;;) { }


    case CTAPHID_MSG:
      // CAPABILITY_NMSG is advertised: no CTAP1/U2F support.
      send_error(cid, ERR_INVALID_CMD);
      break;

    default:
      send_error(cid, ERR_INVALID_CMD);
      break;
  }
  reset_transaction();
}

static void handle_packet(void)
{
  uint32_t cid = rd32(pkt);

  // Channel 0 is reserved and is not a valid destination for a reply either,
  // so the frame is dropped rather than answered.
  if (cid == 0) return;

  bool isInit = (pkt[4] & 0x80) != 0;

  if (isInit) {
    uint8_t  cmd = pkt[4] & 0x7F;
    uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];

    if (cmd == CTAPHID_INIT) {
      handle_init(cid, pkt + 7, bcnt);
      return;
    }
    if (cid == CID_BROADCAST) { send_error(cid, ERR_INVALID_CHANNEL); return; }

    // A CANCEL for the in-flight channel is handled inline; anything else from
    // a different channel while a transaction is open gets BUSY.
    if (activeCid && cid != activeCid) { send_error(cid, ERR_CHANNEL_BUSY); return; }
    if (activeCid == cid && gotLen < expectedLen) {
      // Host restarted a message mid-stream; treat as a fresh transaction.
      reset_transaction();
    }

    activeCid   = cid;
    activeCmd   = cmd;
    expectedLen = bcnt;
    gotLen      = 0;
    nextSeq     = 0;
    overflow    = (bcnt > CTAP_MAX_MSG);
    lastFrameMs = millis();

    uint16_t n = bcnt < INIT_PAYLOAD ? bcnt : INIT_PAYLOAD;
    if (!overflow) memcpy(ioBuf, pkt + 7, n);
    gotLen = n;

    if (gotLen >= expectedLen) dispatch();
    return;
  }

  // ---- continuation ----
  if (cid != activeCid || activeCid == 0) { send_error(cid, ERR_INVALID_CHANNEL); return; }
  uint8_t seq = pkt[4];
  if (seq != nextSeq || seq > 0x7F) {
    reset_transaction();
    send_error(cid, ERR_INVALID_SEQ);
    return;
  }
  nextSeq++;
  lastFrameMs = millis();

  uint16_t remain = expectedLen - gotLen;
  uint16_t n = remain < CONT_PAYLOAD ? remain : CONT_PAYLOAD;
  if (!overflow) memcpy(ioBuf + gotLen, pkt + 5, n);
  gotLen += n;

  if (gotLen >= expectedLen) dispatch();
}

void ctaphid_init(void)
{
  reset_transaction();
}

void ctaphid_poll(void)
{
  if (FidoHID.recv(pkt)) {
    handle_packet();
    return;
  }
  if (activeCid && gotLen < expectedLen &&
      (millis() - lastFrameMs) > FRAME_TIMEOUT_MS) {
    uint32_t cid = activeCid;
    reset_transaction();
    send_error(cid, ERR_MSG_TIMEOUT);
  }
}
