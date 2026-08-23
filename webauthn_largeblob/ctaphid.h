// CTAPHID framing (FIDO CTAP 2.1, §11.2) over the 64-byte HID reports.
//
//   init frame: CID[4] | CMD|0x80 [1] | BCNTH | BCNTL | payload[57]
//   cont frame: CID[4] | SEQ  [1]                     | payload[59]
#pragma once
#include <stdint.h>

#define CTAPHID_PING      0x01
#define CTAPHID_MSG       0x03
#define CTAPHID_INIT      0x06
#define CTAPHID_CBOR      0x10
#define CTAPHID_CANCEL    0x11
#define CTAPHID_KEEPALIVE 0x3B
#define CTAPHID_ERROR     0x3F

// Vendor-specific range is 0x40-0x7F. Used by tools/provision.py to load the
// string that the button types out. This is NOT reachable from a web page --
// browsers expose only the WebAuthn API, never raw CTAPHID -- which is exactly
// why provisioning is a host-side step.
#define CTAPHID_SETTEXT   0x40   // payload: the plaintext, 0..TYPEOUT_MAX bytes
// Reboots into the Caterina bootloader. With CDC disabled there is no
// 1200-baud touch and a Pro Micro has no reset button, so this is the only
// remaining way to reprogram the board -- see tools/reboot_bootloader.py.
// Returns capacity and stored length, both uint16 BE. Deliberately does NOT
// return the text: the device types the secret on a button press, but nothing
// should be able to read it back over USB.
#define CTAPHID_TEXTINFO  0x41
#define CTAPHID_BOOTLOADER 0x42
#define CTAPHID_TYPENOW    0x43   // test hook; compiled out unless ALLOW_REMOTE_TYPE

#define ERR_INVALID_CMD   0x01
#define ERR_INVALID_PAR   0x02
#define ERR_INVALID_LEN   0x03
#define ERR_INVALID_SEQ   0x04
#define ERR_MSG_TIMEOUT   0x05
#define ERR_CHANNEL_BUSY  0x06
#define ERR_INVALID_CHANNEL 0x0B
#define ERR_OTHER         0x7F

void ctaphid_init(void);
// Pumps the USB OUT endpoint; call from loop().
void ctaphid_poll(void);
// Emits a KEEPALIVE(PROCESSING) frame for the active channel.
void ctaphid_keepalive(void);
